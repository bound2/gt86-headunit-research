/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_h264.h"
#include "codec_api.h"
#include <cstdlib>
#include <cstring>
#include <new>
#include <array>

struct SourceSet {
    projection_h264_source source{};
    uint32_t width=0,height=0;
    bool valid=false;
};
struct PictureSource { SourceSet set{}; uint64_t token=0,timestamp=0; };

struct projection_h264 {
    ISVCDecoder *codec = nullptr;
    uint64_t generation = 0;
    uint32_t max_width = 0, max_height = 0;
    size_t waiting_bytes = 0;
    unsigned waiting_nals = 0;
    uint64_t au_timestamp = 0;
    std::array<SourceSet,32> sources{};
    struct Pps { uint32_t sps=0; bool valid=false; };
    std::array<Pps,256> pps{};
    std::array<PictureSource,32> pictures{};
    uint64_t next_token=1,au_token=0;
    uint32_t au_pps=0;
    bool sps = false, draining = false, ended = false, pending = false, has_vcl = false;
};
struct projection_h264_frame { projection_h264_view view; uint8_t *pixels; };

namespace {
// Bounded SPS/VUI inspection; the decoder still validates coded picture syntax.
// All loops, shifts, signed Golomb values and RBSP storage are bounded here.
struct Bits {
    const uint8_t *data;
    size_t size, bit = 0;
    bool ok = true;
    uint32_t read(unsigned count) {
        if (!ok || count > 32 || count > size * 8 - bit) { ok = false; return 0; }
        uint32_t value = 0;
        for (unsigned i = 0; i < count; ++i, ++bit)
            value = (value << 1) | ((data[bit / 8] >> (7 - bit % 8)) & 1);
        return value;
    }
    uint32_t ue() {
        unsigned zeros = 0;
        while (ok && read(1) == 0) {
            if (++zeros > 30) { ok = false; return 0; }
        }
        return ok ? ((1u << zeros) - 1u) + read(zeros) : 0;
    }
    int32_t se() {
        uint32_t v = ue();
        return (v & 1) ? static_cast<int32_t>((v + 1) / 2) : -static_cast<int32_t>(v / 2);
    }
};

void hrd(Bits &b) {
    uint32_t count=b.ue();
    if(count>31) { b.ok=false; return; }
    b.read(4); b.read(4);
    for(uint32_t i=0;i<=count&&b.ok;++i) { b.ue(); b.ue(); b.read(1); }
    b.read(5); b.read(5); b.read(5); b.read(5);
}
void vui(Bits &b,projection_h264_source &s) {
    static const uint16_t ratios[17][2]={{0,0},{1,1},{12,11},{10,11},{16,11},{40,33},
        {24,11},{20,11},{32,11},{80,33},{18,11},{15,11},{64,33},{160,99},{4,3},{3,2},{2,1}};
    s.aspect_present=uint8_t(b.read(1));
    if(s.aspect_present) {
        s.aspect_idc=uint8_t(b.read(8));
        if(s.aspect_idc<17) { s.sar_width=ratios[s.aspect_idc][0]; s.sar_height=ratios[s.aspect_idc][1]; }
        else if(s.aspect_idc==255) {
            s.sar_width=b.read(16); s.sar_height=b.read(16);
            if(!s.sar_width||!s.sar_height) s.sar_width=s.sar_height=0;
        } else { b.ok=false; return; }
    }
    if(b.read(1)) b.read(1); // overscan (no crop is performed here)
    s.signal_present=uint8_t(b.read(1));
    if(s.signal_present) {
        s.video_format=uint8_t(b.read(3)); s.full_range=uint8_t(b.read(1)); s.colour_present=uint8_t(b.read(1));
        if(s.video_format>5) { b.ok=false; return; }
        if(s.colour_present) { s.primaries=uint8_t(b.read(8)); s.transfer=uint8_t(b.read(8)); s.matrix=uint8_t(b.read(8)); }
    }
    s.chroma_present=uint8_t(b.read(1));
    if(s.chroma_present) {
        uint32_t top=b.ue(),bottom=b.ue();
        if(top>5||bottom>5) { b.ok=false; return; }
        s.chroma_top=uint8_t(top); s.chroma_bottom=uint8_t(bottom);
    }
    s.timing_present=uint8_t(b.read(1));
    if(s.timing_present) {
        s.num_units_in_tick=b.read(32); s.time_scale=b.read(32); s.fixed_frame_rate=uint8_t(b.read(1));
        if(!s.num_units_in_tick||!s.time_scale) { b.ok=false; return; }
    }
    bool nal=b.read(1)!=0; if(nal) hrd(b);
    bool vcl=b.read(1)!=0; if(vcl) hrd(b);
    if(nal||vcl) b.read(1);
    b.read(1); // pic_struct_present_flag; no SEI presentation-time claim
    if(b.read(1)) {
        b.read(1);
        for(unsigned i=0;i<4;++i) if(b.ue()>16) b.ok=false;
        uint32_t reorder=b.ue(),buffer=b.ue();
        if(buffer>16||reorder>buffer) b.ok=false;
    }
}
int sps_dimensions(const uint8_t *data, size_t size, projection_h264 *owner) {
    uint8_t rbsp[4096];
    if (size > sizeof(rbsp)) return PROJECTION_H264_LIMIT;
    size_t used = 0;
    unsigned zeros = 0;
    for (size_t i = 0; i < size; ++i) {
        if (zeros == 2 && data[i] == 3) { zeros = 0; continue; }
        rbsp[used++] = data[i];
        zeros = data[i] == 0 ? zeros + 1 : 0;
    }
    Bits b{rbsp, used};
    uint32_t profile = b.read(8);
    if (profile != 66 && profile != 77 && profile != 100) return PROJECTION_H264_BITSTREAM;
    if (b.read(8) & 3u) return PROJECTION_H264_BITSTREAM; // reserved_zero_2bits
    b.read(8); // level; full level syntax/feature validation belongs to codec
    uint32_t id=b.ue();
    if (id > 31) return PROJECTION_H264_BITSTREAM;
    if (profile == 100) {
        if (b.ue() != 1 || b.ue() != 0 || b.ue() != 0) return PROJECTION_H264_BITSTREAM;
        b.read(1); // qpprime_y_zero_transform_bypass_flag
        if (b.read(1)) {
            for (unsigned list = 0; list < 8; ++list) {
                if (!b.read(1)) continue;
                int last = 8, next = 8;
                for (unsigned j = 0; j < (list < 6 ? 16u : 64u); ++j) {
                    if (next) {
                        int delta = b.se();
                        if (delta < -128 || delta > 127) return PROJECTION_H264_BITSTREAM;
                        next = (last + delta + 256) % 256;
                    }
                    last = next ? next : last;
                }
            }
        }
    }
    if (b.ue() > 12) return PROJECTION_H264_BITSTREAM;
    uint32_t poc = b.ue();
    if (poc == 0) {
        if (b.ue() > 12) return PROJECTION_H264_BITSTREAM;
    } else if (poc == 1) {
        b.read(1); b.se(); b.se();
        uint32_t cycle = b.ue();
        if (cycle > 255) return PROJECTION_H264_BITSTREAM;
        for (uint32_t i = 0; i < cycle; ++i) b.se();
    } else if (poc != 2) return PROJECTION_H264_BITSTREAM;
    if (b.ue() > 16) return PROJECTION_H264_LIMIT;
    b.read(1); // gaps_in_frame_num_value_allowed_flag
    uint32_t w = b.ue(), h = b.ue();
    if (!b.ok) return PROJECTION_H264_BITSTREAM;
    // Bound the CODED allocation, not just the smaller cropped display rectangle.
    if (w >= owner->max_width / 16 || h >= owner->max_height / 16) return PROJECTION_H264_LIMIT;
    if (b.read(1) != 1) return PROJECTION_H264_BITSTREAM; // no fields/MBAFF
    b.read(1); // direct_8x8_inference_flag
    SourceSet set{}; set.width=(w+1)*16; set.height=(h+1)*16;
    if (b.read(1)) {
        uint64_t left = b.ue(), right = b.ue(), top = b.ue(), bottom = b.ue();
        if ((left + right) * 2 >= (w + 1) * 16 || (top + bottom) * 2 >= (h + 1) * 16)
            return PROJECTION_H264_BITSTREAM;
        set.width-=uint32_t((left+right)*2); set.height-=uint32_t((top+bottom)*2);
    }
    set.source.video_format=5; set.source.primaries=set.source.transfer=set.source.matrix=2;
    set.source.vui_present=uint8_t(b.read(1));
    if(set.source.vui_present) vui(b,set.source);
    if(b.read(1)!=1) b.ok=false; // rbsp_stop_one_bit and alignment, no ignored tail
    while(b.ok&&b.bit%8) if(b.read(1)) b.ok=false;
    if(!b.ok||b.bit!=used*8) return PROJECTION_H264_BITSTREAM;
    set.valid=true; owner->sources[id]=set;
    return PROJECTION_H264_MORE;
}

int inspect_nal(const uint8_t *data, size_t size, projection_h264 *owner, uint64_t timestamp,
                bool &sps, bool &vcl) {
    if (size > PROJECTION_H264_MAX_NAL) return PROJECTION_H264_LIMIT;
    size_t prefix = 0;
    if (size >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 1) prefix = 3;
    else if (size >= 5 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) prefix = 4;
    else return PROJECTION_H264_BITSTREAM;
    uint8_t header = data[prefix], type = header & 31;
    if ((header & 0x80) || !(type == 1 || type == 5 || (type >= 6 && type <= 9) || type == 12))
        return PROJECTION_H264_BITSTREAM;
    if ((type == 5 || type == 7 || type == 8) && !(header & 0x60)) return PROJECTION_H264_BITSTREAM;
    // Annex-B trailing_zero_8bits/cabac_zero_word are not another NAL.
    size_t end = size;
    while (end > prefix + 1 && data[end - 1] == 0) --end;
    if (end <= prefix + 1) return PROJECTION_H264_BITSTREAM;
    unsigned zeros = 0;
    for (size_t i = prefix + 1; i < end; ++i) {
        if (zeros == 2) {
            if (data[i] < 3) return PROJECTION_H264_BITSTREAM; // embedded NAL/unescaped RBSP
            if (data[i] == 3) {
                if (i + 1 == end || data[i + 1] > 3) return PROJECTION_H264_BITSTREAM;
                zeros = 0;
                continue;
            }
        }
        zeros = data[i] == 0 ? zeros + 1 : 0;
    }
    if (owner->has_vcl && type >= 6 && type <= 9) return PROJECTION_H264_BITSTREAM;
    if (type == 7) {
        int result = sps_dimensions(data + prefix + 1, end - prefix - 1, owner);
        if (result != PROJECTION_H264_MORE) return result;
        sps = true;
    } else if ((type == 1 || type == 5 || type == 8) && !owner->sps) return PROJECTION_H264_BITSTREAM;
    if (type == 1 || type == 5 || type == 8) {
        // First three Exp-Golomb fields fit within this bounded prefix.
        uint8_t prefix_bits[32]; size_t used = 0; zeros = 0;
        for (size_t i = prefix + 1; i < end && used < sizeof(prefix_bits); ++i) {
            if (zeros == 2 && data[i] == 3) { zeros = 0; continue; }
            prefix_bits[used++] = data[i]; zeros = data[i] == 0 ? zeros + 1 : 0;
        }
        Bits b{prefix_bits, used};
        if(type==8) {
            uint32_t pps=b.ue(),sps_id=b.ue();
            if(!b.ok||pps>255||sps_id>31||!owner->sources[sps_id].valid) return PROJECTION_H264_BITSTREAM;
            owner->pps[pps]={sps_id,true}; return PROJECTION_H264_MORE;
        }
        uint32_t first_mb = b.ue(), slice = b.ue(),pps=b.ue();
        if (!b.ok || slice > 9 || (slice % 5 != 0 && slice % 5 != 2) ||
            (type == 5 && slice % 5 != 2)||pps>255||!owner->pps[pps].valid) return PROJECTION_H264_BITSTREAM;
        if (first_mb >= (owner->max_width / 16) * (owner->max_height / 16)) return PROJECTION_H264_LIMIT;
        if ((!owner->has_vcl && first_mb != 0) ||
            (owner->has_vcl && (!first_mb || timestamp != owner->au_timestamp||pps!=owner->au_pps))) return PROJECTION_H264_BITSTREAM;
        if(!owner->has_vcl) {
            if(!owner->next_token) return PROJECTION_H264_LIMIT;
            PictureSource *picture=nullptr;
            for(auto &p:owner->pictures) if(!p.token) { picture=&p; break; }
            if(!picture) return PROJECTION_H264_LIMIT;
            owner->au_token=owner->next_token++; owner->au_pps=pps;
            *picture={owner->sources[owner->pps[pps].sps],owner->au_token,timestamp};
        }
        vcl = true;
    }
    return PROJECTION_H264_MORE;
}

void release_codec(projection_h264 *owner) noexcept {
    if (owner->codec) {
        // OpenH264 destruction releases all contexts (including partial init).
        WelsDestroyDecoder(owner->codec);
        owner->codec = nullptr;
    }
}
int fail(projection_h264 *owner, int result) { release_codec(owner); return result; }
int check(projection_h264 *owner, uint64_t generation, projection_h264_frame **out) {
    if (out) *out = nullptr;
    if (!owner || !out) return PROJECTION_H264_ARGUMENT;
    if (generation != owner->generation) return PROJECTION_H264_STALE;
    if (!owner->codec) return PROJECTION_H264_STATE;
    return PROJECTION_H264_MORE;
}
int copy_frame(projection_h264 *owner, DECODING_STATE status, uint8_t *planes[3],
               const SBufferInfo &info, projection_h264_frame **out) {
    if (status != dsErrorFree && status != dsFramePending)
        return fail(owner, (status & dsOutOfMemory) ? PROJECTION_H264_MEMORY : PROJECTION_H264_BITSTREAM);
    if (info.iBufferStatus == 0) return PROJECTION_H264_MORE;
    PictureSource *source=nullptr;
    for(auto &p:owner->pictures) if(p.token&&p.token==info.uiOutYuvTimeStamp) { source=&p; break; }
    if(!source) return fail(owner,PROJECTION_H264_BACKEND);
    const auto &s = info.UsrData.sSystemBuffer;
    if (info.iBufferStatus != 1 || !planes[0] || !planes[1] || !planes[2] ||
        s.iWidth <= 0 || s.iHeight <= 0 || s.iWidth % 2 || s.iHeight % 2 ||
        s.iWidth > static_cast<int>(owner->max_width) || s.iHeight > static_cast<int>(owner->max_height) ||
        s.iFormat != videoFormatI420 || s.iStride[0] < s.iWidth || s.iStride[1] < s.iWidth / 2 ||
        s.iStride[0] > 16384 || s.iStride[1] > 8192||
        uint32_t(s.iWidth)!=source->set.width||uint32_t(s.iHeight)!=source->set.height) return fail(owner, PROJECTION_H264_BACKEND);
    size_t y_size = static_cast<size_t>(s.iWidth) * s.iHeight, total = y_size + y_size / 2;
    auto *frame = static_cast<projection_h264_frame *>(std::calloc(1, sizeof(projection_h264_frame)));
    if (!frame) return fail(owner, PROJECTION_H264_MEMORY);
    frame->pixels = static_cast<uint8_t *>(std::malloc(total));
    if (!frame->pixels) { std::free(frame); return fail(owner, PROJECTION_H264_MEMORY); }
    auto &v = frame->view;
    v.width = static_cast<uint32_t>(s.iWidth); v.height = static_cast<uint32_t>(s.iHeight);
    v.generation = owner->generation; v.timestamp = source->timestamp; v.bytes = total;
    v.source=source->set.source; *source=PictureSource{};
    v.plane[0] = frame->pixels; v.plane[1] = frame->pixels + y_size; v.plane[2] = frame->pixels + y_size + y_size / 4;
    size_t offset = 0;
    for (unsigned p = 0; p < 3; ++p) {
        size_t width = p ? v.width / 2 : v.width, height = p ? v.height / 2 : v.height;
        v.stride[p] = static_cast<uint32_t>(width);
        for (size_t row = 0; row < height; ++row) {
            std::memcpy(frame->pixels + offset, planes[p] + row * s.iStride[p ? 1 : 0], width);
            offset += width;
        }
    }
    *out = frame;
    return PROJECTION_H264_FRAME;
}
int finish_au(projection_h264 *owner, projection_h264_frame **out) {
    owner->pending = false;
    owner->has_vcl = false;
    owner->waiting_bytes = 0; owner->waiting_nals = 0;
    uint8_t *planes[3] = {};
    SBufferInfo info{};
    auto result = owner->codec->DecodeFrame2(nullptr, 0, planes, &info);
    return copy_frame(owner, result, planes, info, out);
}
}

extern "C" int projection_h264_create(uint64_t generation, uint32_t max_width,
                                      uint32_t max_height, projection_h264 **out) {
    if (out) *out = nullptr;
    if (!out || !generation || max_width < 16 || max_height < 16 ||
        max_width > PROJECTION_H264_MAX_WIDTH || max_height > PROJECTION_H264_MAX_HEIGHT ||
        max_width % 16 || max_height % 16) return PROJECTION_H264_ARGUMENT;
    auto *owner = new (std::nothrow) projection_h264;
    if (!owner) return PROJECTION_H264_MEMORY;
    int result = PROJECTION_H264_BACKEND;
    try {
        if (WelsCreateDecoder(&owner->codec) == 0 && owner->codec) {
            int threads = 0, trace = 0;
            SDecodingParam param{};
            param.uiTargetDqLayer = 255;
            param.eEcActiveIdc = ERROR_CON_DISABLE;
            param.sVideoProperty.size = sizeof(param.sVideoProperty);
            param.sVideoProperty.eVideoBsType = VIDEO_BITSTREAM_AVC;
            if (owner->codec->SetOption(DECODER_OPTION_NUM_OF_THREADS, &threads) == 0 &&
                owner->codec->SetOption(DECODER_OPTION_TRACE_LEVEL, &trace) == 0 &&
                owner->codec->Initialize(&param) == 0) {
                owner->generation = generation; owner->max_width = max_width; owner->max_height = max_height;
                *out = owner;
                return PROJECTION_H264_MORE;
            }
        }
    } catch (const std::bad_alloc &) { result = PROJECTION_H264_MEMORY; }
      catch (...) { result = PROJECTION_H264_BACKEND; }
    release_codec(owner); delete owner;
    return result;
}
extern "C" int projection_h264_push(projection_h264 *owner, uint64_t generation, const uint8_t *data,
                                    size_t size, uint64_t timestamp, projection_h264_frame **out) {
    int result = check(owner, generation, out);
    if (result != PROJECTION_H264_MORE) return result;
    if (!data || !size) return PROJECTION_H264_ARGUMENT;
    if (owner->draining) return PROJECTION_H264_STATE;
    bool sps = false, vcl = false;
    result = inspect_nal(data, size, owner, timestamp, sps, vcl);
    if (result != PROJECTION_H264_MORE) return fail(owner, result);
    if (owner->waiting_nals >= 256 || size > PROJECTION_H264_MAX_NAL - owner->waiting_bytes)
        return fail(owner, PROJECTION_H264_LIMIT);
    owner->sps = owner->sps || sps;
    if (vcl) { owner->has_vcl = true; owner->au_timestamp = timestamp; }
    owner->waiting_bytes += size; ++owner->waiting_nals; owner->pending = true;
    try {
        uint8_t *planes[3] = {};
        SBufferInfo info{};
        info.uiInBsTimeStamp = vcl?owner->au_token:0;
        auto status = owner->codec->DecodeFrame2(data, static_cast<int>(size), planes, &info);
        return copy_frame(owner, status, planes, info, out);
    } catch (const std::bad_alloc &) { return fail(owner, PROJECTION_H264_MEMORY); }
      catch (...) { return fail(owner, PROJECTION_H264_BACKEND); }
}
extern "C" int projection_h264_end_access_unit(projection_h264 *owner, uint64_t generation,
                                               projection_h264_frame **out) {
    int result = check(owner, generation, out);
    if (result != PROJECTION_H264_MORE) return result;
    if (owner->draining) return PROJECTION_H264_STATE;
    if (!owner->pending) return PROJECTION_H264_MORE;
    try { return finish_au(owner, out); }
    catch (const std::bad_alloc &) { return fail(owner, PROJECTION_H264_MEMORY); }
    catch (...) { return fail(owner, PROJECTION_H264_BACKEND); }
}
extern "C" int projection_h264_drain(projection_h264 *owner, uint64_t generation,
                                     projection_h264_frame **out) {
    int result = check(owner, generation, out);
    if (result != PROJECTION_H264_MORE) return result;
    if (owner->ended) return PROJECTION_H264_END;
    try {
        if (!owner->draining) {
            owner->draining = true;
            int end = 1;
            if (owner->codec->SetOption(DECODER_OPTION_END_OF_STREAM, &end) != 0)
                return fail(owner, PROJECTION_H264_BACKEND);
            if (owner->pending) return finish_au(owner, out);
        }
        int remaining = 0;
        if (owner->codec->GetOption(DECODER_OPTION_NUM_OF_FRAMES_REMAINING_IN_BUFFER, &remaining) != 0 ||
            remaining < 0 || remaining > 16) return fail(owner, PROJECTION_H264_BACKEND);
        if (!remaining) {
            for(const auto &p:owner->pictures) if(p.token) return fail(owner,PROJECTION_H264_BACKEND);
            owner->ended = true; return PROJECTION_H264_END;
        }
        uint8_t *planes[3] = {};
        SBufferInfo info{};
        auto status = owner->codec->FlushFrame(planes, &info);
        result = copy_frame(owner, status, planes, info, out);
        if (result == PROJECTION_H264_MORE) return fail(owner, PROJECTION_H264_BACKEND);
        return result;
    } catch (const std::bad_alloc &) { return fail(owner, PROJECTION_H264_MEMORY); }
      catch (...) { return fail(owner, PROJECTION_H264_BACKEND); }
}
extern "C" int projection_h264_frame_view(const projection_h264_frame *frame, projection_h264_view *out) {
    if (out) std::memset(out, 0, sizeof(*out));
    if (!frame || !out) return PROJECTION_H264_ARGUMENT;
    *out = frame->view;
    return PROJECTION_H264_FRAME;
}
extern "C" void projection_h264_frame_destroy(projection_h264_frame *frame) {
    if (frame) { std::free(frame->pixels); std::free(frame); }
}
extern "C" void projection_h264_destroy(projection_h264 *owner) {
    if (owner) { release_codec(owner); delete owner; }
}
