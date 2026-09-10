/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_pcm_output.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
namespace projection_pcm {
static constexpr uint64_t ms=1000000;
static bool marked(const uint8_t *p,size_t bit) noexcept { return (p[bit/8]&(1u<<(bit%8)))!=0; }
static void mark(uint8_t *p,size_t bit,bool value) noexcept {
    uint8_t mask=static_cast<uint8_t>(1u<<(bit%8));
    p[bit/8]=static_cast<uint8_t>(value?(p[bit/8]|mask):(p[bit/8]&~mask));
}
bool scale(uint64_t value,uint64_t frequency,uint32_t rate,uint64_t& out) noexcept {
    if(!frequency||!rate||frequency>UINT64_MAX/rate) return false;
    const uint64_t whole=value/frequency,part=(value%frequency)*rate/frequency;
    if(whole>(UINT64_MAX-part)/rate) return false;
    out=whole*rate+part; return true;
}
static bool same(const projection_audio_format& a,const projection_audio_format& b) noexcept {
    return a.bit==b.bit&&a.clock_rate==b.clock_rate&&a.input_rate==b.input_rate&&
        a.codec==b.codec&&a.channels==b.channels&&a.aac_config==b.aac_config;
}
bool Drift::update(uint64_t frame,uint64_t qpc,int64_t phase_ns,uint32_t rate,uint32_t limit) noexcept {
    int32_t previous=ppm;
    if(!rate||!limit||limit>1000||phase_ns>100000000||phase_ns< -100000000||
       (anchored&&(qpc<ns||frame<frames||qpc-ns>4000000000))) { clear(); return previous!=0; }
    if(!anchored) { frames=frame; ns=qpc; anchored=true; return false; }
    uint64_t elapsed=qpc-ns;
    if(elapsed<2000000000) return false;
    double ratio=double(frame-frames)*1000000000.0/(double(rate)*double(elapsed));
    double measured=(ratio/(1.0+double(ppm)/1000000.0)-1.0)*1000000.0;
    if(!std::isfinite(measured)||std::abs(measured)>5000.0) { clear(); return previous!=0; }
    estimate=estimated?0.75*estimate+0.25*measured:measured; estimated=true;
    double phase=std::clamp(double(phase_ns)/8000.0,-double(limit),double(limit)); // Eight-second phase horizon.
    double target=((1.0+phase/1000000.0)/(1.0+estimate/1000000.0)-1.0)*1000000.0;
    int32_t desired=static_cast<int32_t>(std::round(std::clamp(target,-double(limit),double(limit))));
    ppm=std::clamp(desired,previous-100,previous+100); // <=100 ppm per >=2-second observation window.
    frames=frame; ns=qpc; return ppm!=previous;
}
Output::Output(Bindings b,uint64_t gen,uint32_t buffer,uint32_t startup,uint32_t late_budget,uint32_t drift_limit) noexcept:
    bindings_(b),generation_(gen),buffer_ms_(buffer),startup_ms_(startup),late_ms_(late_budget),drift_ppm_(drift_limit) {}
Output::~Output() noexcept { shutdown(); }
bool Output::valid(uint64_t gen) const noexcept {
    return gen&&gen==generation_&&!failed_&&bindings_.thread&&bindings_.thread(bindings_.context);
}
void Output::clear(Slot& s) noexcept {
    delete s.device; s.device=nullptr;
    pair_crypto_wipe(s.bytes.data(),s.bytes.size());
    s=Slot{};
}
void Output::shutdown() noexcept { for(auto& s:slots_) clear(s); failed_=true; }
int Output::fail(int code) noexcept { shutdown(); return code; }
int Output::refresh() noexcept {
    uint64_t t=bindings_.clock(bindings_.context);
    if(t==UINT64_MAX||t<now_) return fail(IAP2_PROVIDER_FAILED);
    now_=t; return IAP2_OK;
}
Output::Slot *Output::find(uint64_t lease) noexcept {
    for(auto& s:slots_) if(lease&&s.lease==lease) return &s;
    return nullptr;
}
projection_audio_sink Output::sink() noexcept { return {this,open,start,submit,poll,playback,close,flush,PROJECTION_AUDIO_SINK_CONCEALMENT|PROJECTION_AUDIO_SINK_TIMED,nullptr}; }
int Output::open(void *ctx,uint64_t gen,const projection_session_resource *r,const projection_audio_format *f,uint64_t *lease) noexcept {
    auto& o=*static_cast<Output*>(ctx); projection_audio_format expected{};
    if(lease) *lease=0;
    if(!o.valid(gen)||!r||!f||!lease||!o.bindings_.open||!o.bindings_.clock||o.late_ms_>1000||o.drift_ppm_>1000) return IAP2_ARGUMENT;
    if(r->type<100||r->type>102||r->peer_data_port||r->audio_format!=f->bit||
       projection_audio_format_get(f->bit,&expected)!=IAP2_OK||!same(*f,expected)||f->codec!=PROJECTION_AUDIO_PCM16||
       r->frames_per_packet>PROJECTION_AUDIO_PAYLOAD/(2u*f->channels)) return IAP2_UNSUPPORTED;
    auto& s=o.slots_[r->type-100];
    if(s.device||o.serial_==UINT64_MAX) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    Device *device=nullptr;
    int result=o.bindings_.open(o.bindings_.context,*f,o.buffer_ms_,device);
    if(result!=IAP2_OK||!device) { delete device; return o.fail(result==IAP2_OK?IAP2_PROVIDER_FAILED:result); }
    s.device=device; // Owned before any subsequent failure, including sibling cleanup.
    if(!device->capacity||device->capacity>device_frames||!device->frequency||device->frequency>UINT64_MAX/48000||
       !device->period_ns||device->period_ns>100*ms)
        return o.fail(IAP2_UNSUPPORTED);
    const uint64_t guard=(device->period_ns*f->clock_rate+999999999)/1000000000;
    if(device->capacity<=4*guard) return o.fail(IAP2_UNSUPPORTED);
    if(o.drift_ppm_) {
        if(!device->rate_adjustable) return o.fail(IAP2_UNSUPPORTED);
        result=device->adjust(0); if(result!=IAP2_OK) return o.fail(result);
    }
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    s.format=*f; s.type=r->type; s.lease=++o.serial_; *lease=s.lease; return IAP2_OK;
}
int Output::start(void *ctx,uint64_t gen,uint64_t lease) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(!o.valid(gen)) return IAP2_INVALID;
    Slot *s=o.find(lease); if(!s||s->armed||s->flushing) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    s->armed=true; return IAP2_OK; // Device is never started without prefilled media.
}
int Output::submit(void *ctx,uint64_t gen,uint64_t lease,const projection_audio_format *f,const projection_audio_packet *p) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(!o.valid(gen)||!f||!p) return IAP2_INVALID;
    Slot *s=o.find(lease); if(!s||!s->armed||!same(*f,s->format)) return IAP2_INVALID;
    size_t frame=2u*f->channels;
    if((!p->data&&p->size)||p->size>PROJECTION_AUDIO_PAYLOAD||p->size%frame||p->frames!=p->size/frame||
       p->concealed>1||p->timed>1||(!p->timed&&p->presentation_ns)||p->presentation_ns==UINT64_MAX) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    if(!p->size) return IAP2_OK;
    if(p->size>queue_bytes-s->size) return IAP2_MORE;
    if(s->has_input&&p->sample_time!=s->next_sample) return o.fail(IAP2_UNSUPPORTED);
    if(!s->has_input) { s->timed=p->timed!=0; s->time_origin_ns=p->presentation_ns; s->input_frames=0; }
    else {
        if(s->timed!=(p->timed!=0)) return o.fail(IAP2_UNSUPPORTED);
        if(s->timed) {
            uint64_t elapsed=0,expected;
            if(!scale(s->input_frames,f->clock_rate,1000000000,elapsed)||s->time_origin_ns>UINT64_MAX-elapsed) return o.fail(IAP2_INVALID);
            expected=s->time_origin_ns+elapsed;
            if((p->presentation_ns>expected?p->presentation_ns-expected:expected-p->presentation_ns)>1) return o.fail(IAP2_UNSUPPORTED);
        }
    }
    if(s->input_frames>UINT64_MAX-p->frames) return o.fail(IAP2_INVALID);
    if(!s->size) s->queued_ns=o.now_;
    size_t tail=(s->head+s->size)%queue_bytes;
    for(size_t i=0;i<p->size;i+=2) {
        s->bytes[(tail+i)%queue_bytes]=p->data[i+1];
        s->bytes[(tail+i+1)%queue_bytes]=p->data[i];
        mark(s->concealed_queue.data(),((tail+i)%queue_bytes)/2,p->concealed!=0);
    }
    s->size+=p->size; s->input_frames+=p->frames; s->next_sample=p->sample_time+p->frames; s->has_input=true;
    return IAP2_OK;
}
int Output::observe(Slot& s,projection_playback_position& out,uint64_t& frames) noexcept {
    out={}; out.sample_rate=s.format.clock_rate; frames=0;
    if(!s.running) return IAP2_MORE;
    uint64_t position=0,qpc=0;
    int r=s.device->position(position,qpc);
    if(refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    if(r==IAP2_MORE) return IAP2_MORE;
    if(r!=IAP2_OK) return fail(r);
    if(qpc<s.started_ns||qpc>now_||(s.observed&&(position<s.last_position||qpc<s.last_qpc))||
       !scale(position,s.device->frequency,s.format.clock_rate,frames)) return fail(IAP2_PROVIDER_FAILED);
    s.observed=true; s.last_position=position; s.last_qpc=qpc;
    // Initial zero can precede physical propagation. End/underrun is not media.
    if(!position||frames>=s.written||s.written-frames>s.device->capacity||
       marked(s.concealed_device.data(),static_cast<size_t>(frames%s.device->capacity))) return IAP2_OK;
    out.raw_ns=qpc; out.sample_time=s.origin+static_cast<uint32_t>(frames); out.has_position=1;
    return IAP2_OK;
}
int Output::activate(Slot& s) noexcept {
    if(now_<s.start_due) return IAP2_MORE;
    if(s.timed&&late(now_,s.start_due)) {
        int r=reset_epoch(s); return r==IAP2_OK?IAP2_MORE:r;
    }
    s.started_ns=now_;
    int r=s.device->start(); if(r!=IAP2_OK) return fail(r);
    s.running=true; s.primed=false;
    if(refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    return IAP2_OK;
}
bool Output::late(uint64_t now,uint64_t due) const noexcept {
    return late_ms_&&now>due&&now-due>uint64_t(late_ms_)*ms;
}
int Output::scheduled(const Slot& s,uint64_t frames,uint64_t& due) noexcept {
    uint64_t elapsed=0;
    if(!scale(frames,s.format.clock_rate,1000000000,elapsed)||s.time_origin_ns>=UINT64_MAX-elapsed) return fail(IAP2_INVALID);
    due=s.time_origin_ns+elapsed; return IAP2_OK;
}
int Output::reset_epoch(Slot& s) noexcept {
    int r=s.device->reset(); if(r!=IAP2_OK) return fail(r);
    r=nominal(s); if(r!=IAP2_OK) return r;
    s.running=s.primed=s.draining=s.observed=false; s.written=0;
    s.last_position=s.last_qpc=s.started_ns=s.start_due=s.device_origin_frames=0;
    s.concealed_device.fill(0);
    return refresh(); // Keep input continuity, queued media and original schedule.
}
int Output::nominal(Slot& s) noexcept {
    if(s.drift.ppm) { int r=s.device->adjust(0); if(r!=IAP2_OK) return fail(r); }
    s.drift.clear(); s.drift_seen_ns=0; return refresh();
}
int Output::correct_drift(Slot& s,int observation,uint64_t frames) noexcept {
    if(!drift_ppm_||!s.timed||!s.running) return IAP2_OK;
    if(observation!=IAP2_OK||!s.last_position||frames>=s.written||s.written-frames>s.device->capacity||
       now_-s.last_qpc>100*ms) {
        if(s.drift.anchored&&now_-s.drift_seen_ns>=1000*ms) return nominal(s);
        return IAP2_OK;
    }
    uint64_t due=0;
    if(scheduled(s,s.device_origin_frames+frames,due)!=IAP2_OK) return IAP2_INVALID;
    uint64_t delta=s.last_qpc>due?s.last_qpc-due:due-s.last_qpc;
    if(delta>100*ms) return nominal(s);
    s.drift_seen_ns=s.last_qpc;
    int64_t phase=s.last_qpc>=due?static_cast<int64_t>(delta):-static_cast<int64_t>(delta);
    if(s.drift.update(frames,s.last_qpc,phase,s.format.clock_rate,drift_ppm_)) {
        int r=s.device->adjust(s.drift.ppm); if(r!=IAP2_OK) return fail(r);
        if(refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    }
    return IAP2_OK;
}
int Output::trim_late(Slot& s) noexcept {
    if(!late_ms_||!s.timed||!s.size) return IAP2_OK;
    const size_t frame=2u*s.format.channels,count=s.size/frame;
    const uint64_t first_frame=s.input_frames-count;
    uint64_t first_due=0;
    if(scheduled(s,first_frame,first_due)!=IAP2_OK) return IAP2_INVALID;
    if(!late(now_,first_due)) return IAP2_OK;
    size_t lo=0,hi=count;
    // After crossing the late threshold, catch up to now, not the threshold.
    // This hysteresis avoids repeated resets at the budget's rounding boundary.
    // Bounded by the fixed queue (at most 16 comparisons), not elapsed time.
    while(lo<hi) {
        size_t mid=lo+(hi-lo)/2; uint64_t due=0;
        if(scheduled(s,first_frame+mid,due)!=IAP2_OK) return IAP2_INVALID;
        if(now_>due) lo=mid+1; else hi=mid;
    }
    if(!lo) return IAP2_OK;
    // Skipping queued frames cannot be appended to the old contiguous device
    // epoch, even if its clock observation was unavailable on this poll.
    if(s.running||s.primed) { int r=reset_epoch(s); if(r!=IAP2_OK) return r; }
    size_t bytes=lo*frame,first=std::min(bytes,queue_bytes-s.head);
    pair_crypto_wipe(s.bytes.data()+s.head,first); pair_crypto_wipe(s.bytes.data(),bytes-first);
    for(size_t i=0;i<bytes;i+=2) mark(s.concealed_queue.data(),((s.head+i)%queue_bytes)/2,false);
    s.head=(s.head+bytes)%queue_bytes; s.size-=bytes;
    if(!s.size) s.queued_ns=0;
    return IAP2_OK;
}
int Output::pump(Slot& s) noexcept {
    if(!s.armed) return IAP2_OK;
    if(refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    if(s.primed) return activate(s);
    uint32_t padding=0;
    uint64_t frames=0;
    projection_playback_position observed{};
    if(s.running) {
        int r=observe(s,observed,frames);
        if(r!=IAP2_OK&&r!=IAP2_MORE) return r;
        bool overdue=false;
        if(r==IAP2_OK&&frames<s.written&&s.timed&&late_ms_) {
            uint64_t due=0;
            if(scheduled(s,s.device_origin_frames+frames,due)!=IAP2_OK) return IAP2_INVALID;
            overdue=late(s.last_qpc,due); // Accurate device observation, not guessed playback.
        }
        if(r==IAP2_OK&&(frames>=s.written||overdue)) {
            r=reset_epoch(s); if(r!=IAP2_OK) return r;
            if(!s.size&&!(s.timed&&late_ms_)) s.has_input=false;
        } else {
            int corrected=correct_drift(s,r,frames); if(corrected!=IAP2_OK) return corrected;
        }
    }
    int trimmed=trim_late(s); if(trimmed!=IAP2_OK) return trimmed;
    uint64_t before=now_;
    int r=s.device->padding(padding);
    if(r!=IAP2_OK) return fail(r);
    if(padding>s.device->capacity||(!s.running&&padding)) return fail(IAP2_PROVIDER_FAILED);
    const uint64_t guard=(2*s.device->period_ns*s.format.clock_rate+999999999)/1000000000;
    if(s.running&&padding<=guard) s.draining=true;
    if(s.draining||!s.size) return IAP2_MORE;
    size_t frame=2u*s.format.channels;
    if(!s.running&&s.size/frame<s.device->capacity&&now_-s.queued_ns<uint64_t(startup_ms_)*ms) return IAP2_MORE;
    uint32_t n=static_cast<uint32_t>(std::min<size_t>(s.size/frame,s.device->capacity-padding));
    if(!n) return IAP2_MORE;
    if(s.written>UINT64_MAX-n) return fail(IAP2_PROVIDER_FAILED);
    uint8_t *data=nullptr;
    r=s.device->acquire(n,data);
    if(r!=IAP2_OK) return fail(r);
    if(!data) { s.device->release(0); return fail(IAP2_PROVIDER_FAILED); }
    size_t bytes=size_t(n)*frame,first=std::min(bytes,queue_bytes-s.head);
    std::memcpy(data,s.bytes.data()+s.head,first);
    std::memcpy(data+first,s.bytes.data(),bytes-first);
    r=s.device->release(n);
    if(r!=IAP2_OK) return fail(r);
    if(refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    // A delayed transfer cannot establish continuity with the previous buffer.
    if(s.running&&now_-before>=s.device->period_ns) return fail(IAP2_PROVIDER_FAILED);
    if(!s.running) {
        s.origin=s.next_sample-static_cast<uint32_t>(s.size/frame); s.start_due=0;
        s.device_origin_frames=s.input_frames-s.size/frame;
        if(s.timed) {
            if(scheduled(s,s.device_origin_frames,s.start_due)!=IAP2_OK) return IAP2_INVALID;
        }
    }
    for(size_t j=0;j<n;++j) {
        size_t bit=((s.head+j*frame)%queue_bytes)/2;
        mark(s.concealed_device.data(),static_cast<size_t>((s.written+j)%s.device->capacity),marked(s.concealed_queue.data(),bit));
        for(size_t channel=0;channel<s.format.channels;++channel) mark(s.concealed_queue.data(),bit+channel,false);
    }
    pair_crypto_wipe(s.bytes.data()+s.head,first);
    pair_crypto_wipe(s.bytes.data(),bytes-first);
    s.head=(s.head+bytes)%queue_bytes; s.size-=bytes; s.written+=n;
    if(!s.running) {
        s.primed=true; return activate(s);
    }
    return IAP2_OK;
}
int Output::poll(void *ctx,uint64_t gen,uint64_t lease,uint64_t now) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(!o.valid(gen)) return IAP2_INVALID;
    Slot *s=o.find(lease); if(!s) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    if(now>o.now_) return o.fail(IAP2_PROVIDER_FAILED);
    return o.pump(*s);
}
int Output::playback(void *ctx,uint64_t gen,uint64_t lease,projection_playback_position *out) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(out) *out={};
    if(!o.valid(gen)||!out) return IAP2_INVALID;
    Slot *s=o.find(lease); if(!s) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    uint64_t frames=0; int r=o.observe(*s,*out,frames);
    if(r!=IAP2_OK&&r!=IAP2_MORE) { *out={}; return r; }
    return IAP2_OK;
}
void Output::close(void *ctx,uint64_t gen,uint64_t lease) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(gen!=o.generation_||!o.bindings_.thread(o.bindings_.context)) return;
    Slot *s=o.find(lease); if(s) o.clear(*s);
}
int Output::flush(void *ctx,uint64_t gen,uint64_t lease,const projection_audio_flush_request *request) noexcept {
    auto& o=*static_cast<Output*>(ctx);
    if(!o.valid(gen)) return IAP2_INVALID;
    Slot *s=o.find(lease); if(!s||(request?(!s->armed||s->flushing):!s->flushing)) return IAP2_INVALID;
    if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    if(request) {
        int r=o.reset_epoch(*s); if(r!=IAP2_OK) return r;
        pair_crypto_wipe(s->bytes.data(),s->bytes.size()); s->head=s->size=0;
        s->queued_ns=s->written=s->started_ns=s->last_position=s->last_qpc=0;
        s->next_sample=s->origin=0; s->armed=s->running=s->draining=s->has_input=s->observed=false;
        s->time_origin_ns=s->input_frames=s->start_due=s->device_origin_frames=0; s->timed=s->primed=false;
        s->concealed_queue.fill(0); s->concealed_device.fill(0);
        s->flushing=true;
        if(o.refresh()!=IAP2_OK) return IAP2_PROVIDER_FAILED;
    } else { s->flushing=false; s->armed=true; }
    return IAP2_OK;
}
}
