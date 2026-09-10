/* SPDX-License-Identifier: GPL-3.0-only
 * PUBLIC SYNTHETIC endpoint leases/ports only, not real listeners or drivers.
 */
#ifndef GT86_PROJECTION_SESSION_FIXTURE_H
#define GT86_PROJECTION_SESSION_FIXTURE_H
#include "projection_session.h"
#include "projection_info_fixture.h"
inline projection_info_profile session_profile() {
    auto p=info_fixture(2); p.icon_count=0;
    for(size_t i=0;i<p.hid_count;++i) p.hids[i].descriptor.size=17;
    return p; // Full stream capabilities without the separate large-icon stress case.
}
struct SessionBackend {
    unsigned opens=0,starts=0,fail_open=0; int bad_output=0,start_error=0; bool same_ports=false;
    uint64_t next_lease=1;
    unsigned polls=0; int poll_error=0; uint32_t poll_delay=2;
    std::vector<uint64_t> live,closed,started;
    std::vector<projection_session_resource> requests;
    std::vector<projection_session_keys> keys;
    projection_session_config config() { return {{this,open,start,close,nullptr,nullptr},15}; }
    static int poll(void* context,uint64_t gen,uint64_t) {
        auto& self=*static_cast<SessionBackend*>(context); CHECK(gen==91); ++self.polls; return self.poll_error;
    }
    static uint32_t next_delay(const void* context,uint64_t gen) {
        CHECK(gen==91); return static_cast<const SessionBackend*>(context)->poll_delay;
    }
    static int open(void* context,uint64_t gen,const projection_session_resource* request,uint8_t features,
                    const projection_session_keys* key,projection_session_endpoint* out) {
        auto& self=*static_cast<SessionBackend*>(context); CHECK(gen==91&&features<=15);
        ++self.opens; self.requests.push_back(*request); self.keys.push_back(*key);
        out->lease=self.next_lease++; self.live.push_back(out->lease);
        if(!request->type) { out->event_port=4000; out->timing_port=4001; out->keep_alive_port=request->keep_alive_low_power?4002:0; }
        else { out->data_port=static_cast<uint16_t>(5000+request->type*2);
            if(request->type>=100&&request->type<=102) out->control_port=static_cast<uint16_t>(out->data_port+1);
            if(request->type==130) out->stream_id=77; }
        if(self.bad_output==1) out->data_port=0;
        if(self.bad_output==2) out->event_port=0;
        if(self.bad_output==3) out->control_port=out->data_port;
        if(self.bad_output==4) out->stream_id=0;
        if(self.bad_output==5) { self.live.pop_back(); out->lease=0; } // Provider cleaned its own partial allocation.
        if(self.bad_output==6) { self.live.pop_back(); CHECK(!self.live.empty()); out->lease=self.live.front(); } // Invalid duplicate, no second owned resource.
        if(self.bad_output==7&&request->type==100) out->control_port=0;
        if(self.bad_output==8) out->data_port=1;
        if(self.same_ports) { if(out->keep_alive_port) out->keep_alive_port=out->event_port; if(out->control_port) out->control_port=out->data_port; }
        return self.fail_open==self.opens?-55:IAP2_OK;
    }
    static int start(void* context,uint64_t gen,const uint64_t* leases,size_t count) {
        auto& self=*static_cast<SessionBackend*>(context); CHECK(gen==91&&count>0); ++self.starts;
        for(size_t i=0;i<count;++i) { CHECK(std::find(self.live.begin(),self.live.end(),leases[i])!=self.live.end()); self.started.push_back(leases[i]); }
        return self.start_error;
    }
    static void close(void* context,uint64_t gen,uint64_t lease) {
        auto& self=*static_cast<SessionBackend*>(context); CHECK(gen==91&&lease);
        auto found=std::find(self.live.begin(),self.live.end(),lease); CHECK(found!=self.live.end()); self.live.erase(found); self.closed.push_back(lease);
    }
};
inline rtsp_message session_message(const Bytes& body,const char* method="SETUP",const char* target="rtsp://127.0.0.1/123") {
    rtsp_message r{}; r.method=info_text(method); r.target=info_text(target); r.body={body.data(),body.size()};
    r.headers[0]={info_text("Content-Type"),info_text("application/x-apple-binary-plist")}; r.header_count=1; r.has_cseq=1; r.cseq=1; return r;
}
#endif
