/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef GT86_PROJECTION_PCM_OUTPUT_HPP
#define GT86_PROJECTION_PCM_OUTPUT_HPP
#include "projection_audio_services.h"
#include <array>
/* Internal output engine/device seam. The public WASAPI C factory always binds
 * actual OS devices; deterministic tests substitute this narrow device seam.
 * Two-phase sink.flush stops/resets the device and clears all owned PCM/clock
 * history without replacing its lease. Reply-drained resume only re-arms normal
 * prefilled startup, never fabricates a played position or recalls played audio. */
namespace projection_pcm {
constexpr size_t queue_bytes=65536;
constexpr size_t device_frames=48000;
struct Device {
    uint32_t capacity=0; uint64_t frequency=0,period_ns=0;
    virtual ~Device() noexcept = default;
    virtual int padding(uint32_t&) noexcept=0;
    virtual int acquire(uint32_t,uint8_t*&) noexcept=0;
    virtual int release(uint32_t) noexcept=0;
    virtual int start() noexcept=0;
    virtual int reset() noexcept=0; /* Stop + Reset, synchronous. */
    /* OK=accurate, MORE=inaccurate; QPC position already in ns, no extrapolation. */
    virtual int position(uint64_t&,uint64_t&) noexcept=0;
};
struct Bindings {
    void *context=nullptr;
    int (*open)(void*,const projection_audio_format&,uint32_t,Device*&) noexcept=nullptr;
    uint64_t (*clock)(void*) noexcept=nullptr;
    bool (*thread)(void*) noexcept=nullptr;
};
bool scale(uint64_t value,uint64_t frequency,uint32_t rate,uint64_t& out) noexcept;
class Output {
public:
    Output(Bindings,uint64_t,uint32_t buffer_ms,uint32_t startup_ms,uint32_t late_ms=0) noexcept;
    ~Output() noexcept;
    Output(const Output&)=delete; Output& operator=(const Output&)=delete;
    projection_audio_sink sink() noexcept;
    void shutdown() noexcept;
private:
    struct Slot {
        Device *device=nullptr; projection_audio_format format{};
        std::array<uint8_t,queue_bytes> bytes{};
        std::array<uint8_t,queue_bytes/16> concealed_queue{};
        std::array<uint8_t,device_frames/8> concealed_device{};
        size_t head=0,size=0;
        uint64_t lease=0,queued_ns=0,written=0,started_ns=0,last_position=0,last_qpc=0;
        uint64_t time_origin_ns=0,input_frames=0,start_due=0,device_origin_frames=0;
        uint32_t type=0,next_sample=0,origin=0;
        bool armed=false,running=false,draining=false,has_input=false,observed=false,flushing=false;
        bool timed=false,primed=false;
    };
    Bindings bindings_; uint64_t generation_,serial_=0,now_=0;
    uint32_t buffer_ms_,startup_ms_,late_ms_; bool failed_=false;
    std::array<Slot,3> slots_{};
    bool valid(uint64_t) const noexcept;
    int refresh() noexcept;
    int fail(int) noexcept;
    Slot *find(uint64_t) noexcept;
    void clear(Slot&) noexcept;
    int observe(Slot&,projection_playback_position&,uint64_t&) noexcept;
    int pump(Slot&) noexcept;
    int activate(Slot&) noexcept;
    bool late(uint64_t now,uint64_t due) const noexcept;
    int scheduled(const Slot&,uint64_t frames,uint64_t& due) noexcept;
    int reset_epoch(Slot&) noexcept;
    int trim_late(Slot&) noexcept;
    static int open(void*,uint64_t,const projection_session_resource*,const projection_audio_format*,uint64_t*) noexcept;
    static int start(void*,uint64_t,uint64_t) noexcept;
    static int submit(void*,uint64_t,uint64_t,const projection_audio_format*,const projection_audio_packet*) noexcept;
    static int poll(void*,uint64_t,uint64_t,uint64_t) noexcept;
    static int playback(void*,uint64_t,uint64_t,projection_playback_position*) noexcept;
    static void close(void*,uint64_t,uint64_t) noexcept;
    static int flush(void*,uint64_t,uint64_t,const projection_audio_flush_request*) noexcept;
};
}
#endif
