/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_video.h"
#include "monocypher.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <new>
#include <vector>

namespace {
constexpr size_t max_plain = PROJECTION_H264_MAX_NAL;
struct Nal { const uint8_t *data = nullptr; size_t size = 0; };
struct Avcc {
    const uint8_t *data = nullptr; size_t size = 0, count = 0;
    std::array<Nal, 64> sets{};
    uint8_t profile = 0, length_size = 0;
};
struct Queued {
    projection_h264_frame *frame = nullptr;
    projection_video_metadata meta{};
    uint64_t queued_ms = 0;
};
struct Pending { projection_video_metadata meta{}; bool used = false; };
uint32_t be32(const uint8_t *p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3];
}
uint32_t le32(const uint8_t *p) {
    return uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0];
}
bool box(const uint8_t *p, size_t n, size_t &size, size_t &header) {
    if (n < 8) return false;
    uint64_t declared = be32(p); header = 8;
    if (declared == 1) {
        if (n < 16) return false;
        declared = uint64_t(be32(p + 8)) << 32 | be32(p + 12); header = 16;
    }
    if (declared < header || declared > n) return false;
    size = static_cast<size_t>(declared); return true;
}
bool tag(const uint8_t *p, const char *name) { return std::memcmp(p + 4, name, 4) == 0; }
int config_record(const uint8_t *&p, size_t &n) {
    if (!n) return PROJECTION_VIDEO_MORE; // Explicit empty configuration/keepalive.
    if (p[0] == 1) return PROJECTION_VIDEO_MORE;
    // The pinned native receiver tests a four-reserved-zero + avcC wrapper.
    // Its extent is the enclosing screen record, NOT a general MP4 size-to-EOF
    // rule. Only this exact top-level AVC prefix is admitted; no marker search.
    if(n>=8&&be32(p)==0&&tag(p,"avcC")) { p+=8; n-=8; return PROJECTION_VIDEO_MORE; }
    size_t length = 0, header = 0;
    if (!box(p, n, length, header) || length != n) return PROJECTION_VIDEO_FORMAT;
    if (tag(p, "avcC")) { p += header; n -= header; return PROJECTION_VIDEO_MORE; }
    if (!tag(p, "avc1") || n < header + 78) return PROJECTION_VIDEO_FORMAT;
    // VisualSampleEntry: 78 fixed bytes after the box header; children follow.
    size_t offset = header + 78, found_size = 0, children = 0;
    const uint8_t *found = nullptr;
    while (offset < n) {
        if (n - offset == 4 && be32(p + offset) == 0) { offset += 4; break; }
        if (++children > 32 || !box(p + offset, n - offset, length, header)) return PROJECTION_VIDEO_FORMAT;
        if (tag(p + offset, "hvcC")) return PROJECTION_VIDEO_FORMAT;
        if (tag(p + offset, "avcC")) {
            if (found) return PROJECTION_VIDEO_FORMAT;
            found = p + offset + header; found_size = length - header;
        }
        offset += length;
    }
    if (!found || offset != n) return PROJECTION_VIDEO_FORMAT;
    p = found; n = found_size; return PROJECTION_VIDEO_MORE;
}
int parse_avcc(const uint8_t *p, size_t n, Avcc &out) {
    if (n < 7 || p[0] != 1 || (p[1] != 66 && p[1] != 77 && p[1] != 100) ||
        (p[4] & 0xfc) != 0xfc || (p[5] & 0xe0) != 0xe0 || (p[4] & 3) == 2)
        return PROJECTION_VIDEO_FORMAT;
    out.data = p; out.size = n; out.profile = p[1]; out.length_size = (p[4] & 3) + 1;
    size_t offset = 6;
    for (unsigned group = 0; group < 2; ++group) {
        if (group && offset == n) return PROJECTION_VIDEO_FORMAT;
        unsigned count = group ? p[offset++] : p[5] & 31;
        if (!count || count > out.sets.size() - out.count) return PROJECTION_VIDEO_FORMAT;
        for (unsigned i = 0; i < count; ++i) {
            if (n - offset < 2) return PROJECTION_VIDEO_FORMAT;
            size_t length = size_t(p[offset]) * 256 + p[offset + 1]; offset += 2;
            if (length < 2 || length > n - offset || length > 4096 || (p[offset] & 0x80) ||
                !(p[offset] & 0x60) || (p[offset] & 31) != (group ? 8 : 7)) return PROJECTION_VIDEO_FORMAT;
            if (!group && !i && (length < 4 || std::memcmp(p + offset + 1, p + 1, 3))) return PROJECTION_VIDEO_FORMAT;
            out.sets[out.count++] = Nal{p + offset, length}; offset += length;
        }
    }
    // High-profile extension may be omitted by older writers. If present, only
    // 4:2:0 / 8-bit / zero SPS extensions is supported, with exact reserved bits.
    if (offset != n && (out.profile != 100 || n - offset != 4 || p[offset] != 0xfd ||
        p[offset + 1] != 0xf8 || p[offset + 2] != 0xf8 || p[offset + 3] != 0)) return PROJECTION_VIDEO_FORMAT;
    return PROJECTION_VIDEO_MORE;
}
}

struct projection_video {
    projection_video_config config{};
    uint8_t key[32]{};
    uint64_t generation = 0, now = 0, counter = 0, epoch = 0, rx_at = 0;
    bool exhausted = false, started = false, dead = false, finishing = false, ended = false, need_idr = true;
    size_t rx_used = 0, rx_expected = 0, count = 0;
    std::vector<uint8_t> wire, plain, scratch, parameters;
    Avcc avcc{};
    projection_h264 *decoder = nullptr;
    std::array<Queued, 8> queue{};
    std::array<Pending, 32> pending{};
};

namespace {
void clear_frames(projection_video *v) {
    for (auto &q : v->queue) { projection_h264_frame_destroy(q.frame); q = Queued{}; }
    v->count = 0; v->pending = {};
}
void wipe_bytes(std::vector<uint8_t> &v) { if (!v.empty()) crypto_wipe(v.data(), v.size()); }
void close(projection_video *v) {
    clear_frames(v); projection_h264_destroy(v->decoder); v->decoder = nullptr;
    crypto_wipe(v->key, sizeof(v->key)); wipe_bytes(v->wire); wipe_bytes(v->plain);
    wipe_bytes(v->scratch); wipe_bytes(v->parameters); v->avcc = {};
    v->rx_used = v->rx_expected = 0; v->dead = true;
}
int stop(projection_video *v, int result) { close(v); return result; }
int owner(const projection_video *v, uint64_t generation) {
    if (!v || !generation) return PROJECTION_VIDEO_ARGUMENT;
    if (v->generation != generation) return PROJECTION_VIDEO_STALE;
    return v->dead ? PROJECTION_VIDEO_STATE : PROJECTION_VIDEO_MORE;
}
int backend_result(int result) {
    if (result == PROJECTION_H264_MEMORY) return PROJECTION_VIDEO_MEMORY;
    if (result == PROJECTION_H264_LIMIT) return PROJECTION_VIDEO_LIMIT;
    return PROJECTION_VIDEO_FORMAT;
}
int collect(projection_video *v, projection_h264_frame *frame) {
    if (!frame) return PROJECTION_VIDEO_MORE;
    projection_h264_view view{};
    if (projection_h264_frame_view(frame, &view) != PROJECTION_H264_FRAME || v->count >= v->config.queue_frames) {
        projection_h264_frame_destroy(frame); return PROJECTION_VIDEO_LIMIT;
    }
    for (auto &p : v->pending) {
        if (!p.used || p.meta.counter != view.timestamp) continue;
        if (view.generation != v->generation || p.meta.configuration_epoch != v->epoch) break;
        v->queue[v->count++] = Queued{frame, p.meta, v->now}; p = Pending{};
        return PROJECTION_VIDEO_MORE;
    }
    projection_h264_frame_destroy(frame); return PROJECTION_VIDEO_FORMAT;
}
int configure(projection_video *v, const uint8_t *data, size_t n) {
    if (!v->config.allow_clear_config) return PROJECTION_VIDEO_LIMIT;
    int result = config_record(data, n); if (result < 0) return result;
    // Empty/identical clear configuration cannot reset live decoder history,
    // nonce, queued frames, epoch, IDR requirement or existing deadlines.
    if(!n || (v->decoder&&n==v->parameters.size()&&!std::memcmp(data,v->parameters.data(),n)))
        return PROJECTION_VIDEO_IGNORED;
    if(v->epoch>=64) return PROJECTION_VIDEO_LIMIT;
    Avcc parsed{}; result = parse_avcc(data, n, parsed); if (result < 0) return result;
    projection_h264 *raw = nullptr;
    result = projection_h264_create(v->generation, v->config.max_width, v->config.max_height, &raw);
    if (result < 0) return backend_result(result);
    std::unique_ptr<projection_h264, decltype(&projection_h264_destroy)> candidate(raw, projection_h264_destroy);
    for (size_t i = 0; i < parsed.count; ++i) {
        std::memset(v->scratch.data(), 0, 3); v->scratch[3] = 1;
        std::memcpy(v->scratch.data() + 4, parsed.sets[i].data, parsed.sets[i].size);
        projection_h264_frame *frame = nullptr;
        result = projection_h264_push(raw, v->generation, v->scratch.data(), parsed.sets[i].size + 4, 0, &frame);
        projection_h264_frame_destroy(frame);
        if (result != PROJECTION_H264_MORE) return backend_result(result);
    }
    projection_h264_frame *frame = nullptr;
    result = projection_h264_end_access_unit(raw, v->generation, &frame);
    projection_h264_frame_destroy(frame);
    if (result != PROJECTION_H264_MORE) return backend_result(result);
    wipe_bytes(v->parameters); v->parameters.assign(data, data + n); v->avcc = {};
    result = parse_avcc(v->parameters.data(), v->parameters.size(), v->avcc);
    if (result < 0) return result;
    clear_frames(v); projection_h264_destroy(v->decoder); v->decoder = candidate.release();
    ++v->epoch; v->need_idr = true; wipe_bytes(v->scratch);
    return PROJECTION_VIDEO_CONFIG;
}
int decode(projection_video *v, size_t size, const projection_video_metadata &meta) {
    if (!v->decoder) return PROJECTION_VIDEO_FORMAT;
    std::array<Nal, 256> nals{};
    size_t offset = 0, count = 0, annex_size = 0; bool vcl = false, idr = false;
    // Preflight the ENTIRE length table before passing even the first NAL to
    // the stateful decoder; malformed tails cannot expose a partial AU.
    while (offset < size) {
        if (size - offset < v->avcc.length_size || count == nals.size()) return PROJECTION_VIDEO_FORMAT;
        size_t length = 0;
        for (unsigned i = 0; i < v->avcc.length_size; ++i) length = (length << 8) | v->plain[offset++];
        if (length < 2 || length > size - offset || length > max_plain - 4 ||
            length + 4 > max_plain - annex_size) return PROJECTION_VIDEO_FORMAT;
        Nal nal{v->plain.data() + offset, length}; unsigned type = nal.data[0] & 31;
        if (type == 7 || type == 8) {
            bool match = false;
            for (size_t i = 0; i < v->avcc.count; ++i)
                if (length == v->avcc.sets[i].size && !std::memcmp(nal.data, v->avcc.sets[i].data, length)) match = true;
            if (!match) return PROJECTION_VIDEO_FORMAT; // changed sets require a new config record/epoch
        }
        if (type == 1 || type == 5) { if (!vcl) idr = type == 5; vcl = true; }
        nals[count++] = nal; offset += length; annex_size += length + 4;
    }
    if (vcl && v->need_idr && !idr) return PROJECTION_VIDEO_FORMAT;
    if (vcl) {
        auto p = std::find_if(v->pending.begin(), v->pending.end(), [](const Pending &p) { return !p.used; });
        if (p == v->pending.end()) return PROJECTION_VIDEO_LIMIT;
        *p = Pending{meta, true};
    }
    for (size_t i = 0; i < count; ++i) {
        std::memset(v->scratch.data(), 0, 3); v->scratch[3] = 1;
        std::memcpy(v->scratch.data() + 4, nals[i].data, nals[i].size);
        projection_h264_frame *frame = nullptr;
        int result = projection_h264_push(v->decoder, v->generation, v->scratch.data(), nals[i].size + 4, meta.counter, &frame);
        if (result < 0) return backend_result(result);
        result = collect(v, frame); if (result < 0) return result;
    }
    projection_h264_frame *frame = nullptr;
    int result = projection_h264_end_access_unit(v->decoder, v->generation, &frame);
    if (result < 0) return backend_result(result);
    result = collect(v, frame); if (result < 0) return result;
    if (vcl) v->need_idr = false;
    wipe_bytes(v->scratch); return PROJECTION_VIDEO_PACKET;
}
int handle(projection_video *v) {
    const size_t body_size = v->rx_expected - PROJECTION_VIDEO_HEADER;
    const uint8_t *body = v->wire.data() + PROJECTION_VIDEO_HEADER;
    if (v->wire[4] == 1) return configure(v, body, body_size);
    if (v->wire[4] != 0) return PROJECTION_VIDEO_IGNORED;
    if (v->exhausted) return PROJECTION_VIDEO_LIMIT;
    uint8_t nonce[12]{}; uint64_t counter = v->counter;
    for (unsigned i = 0; i < 8; ++i) { nonce[i + 4] = uint8_t(counter); counter >>= 8; }
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, v->key, nonce);
    int result = crypto_aead_read(&ctx, v->plain.data(), body + body_size - 16,
                                 v->wire.data(), PROJECTION_VIDEO_HEADER, body, body_size - 16);
    crypto_wipe(&ctx, sizeof(ctx)); crypto_wipe(nonce, sizeof(nonce));
    if (result) return PROJECTION_VIDEO_AUTH;
    projection_video_metadata meta{};
    meta.generation = v->generation; meta.configuration_epoch = v->epoch;
    meta.counter = v->counter; meta.received_ms = v->now; meta.frame_authenticated = 1;
    std::memcpy(meta.header, v->wire.data(), sizeof(meta.header));
    if (v->counter == UINT64_MAX) v->exhausted = true; else ++v->counter;
    result = decode(v, body_size - 16, meta); wipe_bytes(v->plain); return result;
}
}

extern "C" int projection_video_create(const projection_video_config *config, const uint8_t key[32],
                                         uint64_t generation, uint64_t now, projection_video **out) {
    if (out) *out = nullptr;
    if (!out || !config || !key || !generation || config->allow_clear_config != 1 ||
        config->queue_frames < 2 || config->queue_frames > 8 || !config->receive_ms || config->receive_ms > 60000 ||
        !config->hold_ms || config->hold_ms > 60000 || config->max_width < 16 || config->max_height < 16 ||
        config->max_width > PROJECTION_H264_MAX_WIDTH || config->max_height > PROJECTION_H264_MAX_HEIGHT ||
        config->max_width % 16 || config->max_height % 16) return PROJECTION_VIDEO_ARGUMENT;
    auto *v = new (std::nothrow) projection_video;
    if (!v) return PROJECTION_VIDEO_MEMORY;
    try {
        v->wire.resize(PROJECTION_VIDEO_HEADER + max_plain + 16); v->plain.resize(max_plain);
        v->scratch.resize(max_plain); v->parameters.reserve(PROJECTION_VIDEO_CONFIG_LIMIT);
        v->config = *config; v->generation = generation; v->now = now; std::memcpy(v->key, key, 32);
        *out = v; return PROJECTION_VIDEO_MORE;
    } catch (...) { close(v); delete v; return PROJECTION_VIDEO_MEMORY; }
}
extern "C" int projection_video_check(projection_video *v, uint64_t generation, uint64_t now) {
    int result = owner(v, generation); if (result < 0) return result;
    if (now < v->now) return PROJECTION_VIDEO_ARGUMENT;
    v->now = now;
    if ((v->rx_used && now - v->rx_at >= v->config.receive_ms) ||
        (v->count && now - v->queue[0].queued_ms >= v->config.hold_ms)) return stop(v, PROJECTION_VIDEO_DEADLINE);
    return PROJECTION_VIDEO_MORE;
}
extern "C" uint32_t projection_video_next_delay(const projection_video *v) {
    if (!v || v->dead) return UINT32_MAX;
    uint64_t delay = UINT32_MAX;
    if (v->rx_used) delay = v->config.receive_ms - std::min(uint64_t(v->config.receive_ms), v->now - v->rx_at);
    if (v->count) delay = std::min(delay, v->config.hold_ms - std::min(uint64_t(v->config.hold_ms), v->now - v->queue[0].queued_ms));
    return static_cast<uint32_t>(delay);
}
extern "C" int projection_video_feed(projection_video *v, uint64_t generation, const uint8_t *data,
                                       size_t size, size_t *consumed, uint64_t now) {
    if (consumed) *consumed = 0;
    if (!consumed || (!data && size)) return PROJECTION_VIDEO_ARGUMENT;
    int result = projection_video_check(v, generation, now); if (result < 0) return result;
    if (v->finishing) return PROJECTION_VIDEO_STATE;
    if (v->config.queue_frames - v->count < 2) return PROJECTION_VIDEO_BUSY;
    if (!size) return PROJECTION_VIDEO_MORE;
    if (!v->rx_used) v->rx_at = now;
    if (v->rx_used < PROJECTION_VIDEO_HEADER) {
        size_t take = std::min(size, PROJECTION_VIDEO_HEADER - v->rx_used);
        std::memcpy(v->wire.data() + v->rx_used, data, take); v->rx_used += take;
        data += take; size -= take; *consumed += take;
        if (v->rx_used < PROJECTION_VIDEO_HEADER) return PROJECTION_VIDEO_MORE;
        size_t body = le32(v->wire.data()); uint8_t opcode = v->wire[4];
        if (opcode == 0 && body < 16) return stop(v, PROJECTION_VIDEO_AUTH);
        if (body > (opcode == 0 ? max_plain + 16 : PROJECTION_VIDEO_CONFIG_LIMIT)) return stop(v, PROJECTION_VIDEO_LIMIT);
        v->rx_expected = PROJECTION_VIDEO_HEADER + body;
    }
    size_t take = std::min(size, v->rx_expected - v->rx_used);
    if (take) std::memcpy(v->wire.data() + v->rx_used, data, take);
    v->rx_used += take; *consumed += take;
    if (v->rx_used != v->rx_expected) return PROJECTION_VIDEO_MORE;
    try {
        result = handle(v);
        if (result < 0) return stop(v, result);
        crypto_wipe(v->wire.data(), v->rx_used); v->rx_used = v->rx_expected = 0;
        return result;
    } catch (const std::bad_alloc &) { return stop(v, PROJECTION_VIDEO_MEMORY); }
      catch (...) { return stop(v, PROJECTION_VIDEO_FORMAT); }
}
extern "C" int projection_video_start(projection_video *v, uint64_t generation, uint64_t now) {
    int result = projection_video_check(v, generation, now); if (result < 0) return result;
    v->started = true; return PROJECTION_VIDEO_MORE;
}
extern "C" int projection_video_get_configuration(const projection_video *v, uint64_t generation,
                                                    projection_video_configuration *out) {
    if (out) *out = {};
    if (!out) return PROJECTION_VIDEO_ARGUMENT;
    int result = owner(v, generation); if (result < 0) return result;
    if (!v->epoch) return PROJECTION_VIDEO_MORE;
    out->generation = v->generation; out->epoch = v->epoch;
    out->profile = v->avcc.profile; out->length_size = v->avcc.length_size;
    return PROJECTION_VIDEO_CONFIG;
}
extern "C" int projection_video_take(projection_video *v, uint64_t generation, projection_h264_frame **out,
                                       projection_video_metadata *meta, uint64_t now) {
    if (out) *out = nullptr; if (meta) *meta = {};
    if (!out || !meta) return PROJECTION_VIDEO_ARGUMENT;
    int result = projection_video_check(v, generation, now); if (result < 0) return result;
    if (!v->started) return PROJECTION_VIDEO_BUSY;
    if (!v->count) return v->ended ? PROJECTION_VIDEO_END : PROJECTION_VIDEO_MORE;
    *out = v->queue[0].frame; *meta = v->queue[0].meta;
    --v->count;
    for (size_t i = 0; i < v->count; ++i) v->queue[i] = v->queue[i + 1];
    v->queue[v->count] = Queued{}; return PROJECTION_VIDEO_FRAME;
}
extern "C" int projection_video_finish(projection_video *v, uint64_t generation, uint64_t now) {
    int result = projection_video_check(v, generation, now); if (result < 0) return result;
    if (v->rx_used) return stop(v, PROJECTION_VIDEO_WIRE);
    v->finishing = true; crypto_wipe(v->key, sizeof(v->key));
    if (v->ended) return PROJECTION_VIDEO_END;
    if (v->config.queue_frames - v->count < 2) return PROJECTION_VIDEO_BUSY;
    if (!v->decoder) { v->ended = true; return PROJECTION_VIDEO_END; }
    projection_h264_frame *frame = nullptr;
    result = projection_h264_drain(v->decoder, generation, &frame);
    if (result < 0) return stop(v, backend_result(result));
    if (result == PROJECTION_H264_END) {
        for (const auto &p : v->pending) if (p.used) return stop(v, PROJECTION_VIDEO_FORMAT);
        v->ended = true; return PROJECTION_VIDEO_END;
    }
    result = collect(v, frame);
    return result < 0 ? stop(v, result) : PROJECTION_VIDEO_MORE;
}
extern "C" void projection_video_destroy(projection_video *v) { if (v) { close(v); delete v; } }
