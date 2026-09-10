/* SPDX-License-Identifier: GPL-3.0-only */
#include "projection_timing.h"
#include "pair_test_support.h"
using Packet=std::array<uint8_t,32>;
static constexpr uint64_t second=1000000000, epoch=UINT64_C(0x1234567880000000);
static uint64_t read64(const uint8_t* p) { uint64_t n=0; for(unsigned i=0;i<8;++i) n=(n<<8)|p[i]; return n; }
static void write64(uint8_t* p,uint64_t n) { for(unsigned i=0;i<8;++i) p[7-i]=static_cast<uint8_t>(n>>(8*i)); }
static Packet packet(uint8_t type,uint64_t a=0,uint64_t b=0,uint64_t c=0) {
    Packet p{}; p[0]=0x80; p[1]=type; p[3]=7; write64(p.data()+8,a); write64(p.data()+16,b); write64(p.data()+24,c); return p;
}
static projection_timing fresh(uint64_t origin=0,uint64_t ntp=epoch) {
    projection_timing s{}; projection_timing_config cfg{}; projection_timing_default_config(&cfg);
    CHECK(projection_timing_init(&s,&cfg,origin,ntp)==IAP2_OK); return s;
}
static int sample(projection_timing& s,uint64_t start,uint64_t duration,uint64_t elapsed_ticks,uint64_t offset) {
    Packet probe{},out{}; CHECK(projection_timing_probe(&s,start,probe.data())==IAP2_OK);
    auto t1=read64(probe.data()+24); CHECK(projection_timing_sent(&s,start,t1)==IAP2_OK);
    auto p=packet(211,t1,t1+elapsed_ticks/2+offset,t1+elapsed_ticks/2+offset);
    out.fill(0xab); auto old=out; int r=projection_timing_feed(&s,p.data(),p.size(),start+duration,start+duration,out.data()); CHECK(out==old); return r;
}
static void wire_and_commit() {
    auto s=fresh(); Packet p{},out{}; CHECK(projection_timing_next_delay(&s)==0);
    CHECK(projection_timing_probe(&s,0,p.data())==IAP2_OK&&p==packet(210,0,0,epoch)&&!s.pending);
    CHECK(projection_timing_sent(&s,0,epoch+1)==IAP2_ARGUMENT&&!s.pending);
    CHECK(projection_timing_sent(&s,0,epoch)==IAP2_OK&&s.pending);
    CHECK(projection_timing_sent(&s,0,epoch)==IAP2_MORE&&projection_timing_next_delay(&s)==3000);
    out.fill(0x55); auto old=out;
    CHECK(projection_timing_probe(&s,second,out.data())==IAP2_MORE&&out==old);
    p=packet(210,0,0,UINT64_MAX); p[4]=0xac; // Reserved header is deliberately ignored.
    CHECK(projection_timing_feed(&s,p.data(),32,second,second+second/4,out.data())==PROJECTION_TIMING_REPLY);
    CHECK(out==packet(211,UINT64_MAX,epoch+(UINT64_C(1)<<32),epoch+(UINT64_C(5)<<30)));
    CHECK(s.pending&&!s.synced&&s.last_sync_ns==0);
}
static void malformed_and_matching() {
    for(unsigned i=0;i<4;++i) for(unsigned value=0;value<256;++value) {
        auto s=fresh(); auto p=packet(210); auto original=p[i]; p[i]=static_cast<uint8_t>(value); Packet out{}; out.fill(0xb1);
        int r=projection_timing_feed(&s,p.data(),32,0,0,out.data());
        if(value==original) CHECK(r==PROJECTION_TIMING_REPLY);
        else if(i==1&&value==211) CHECK(r==IAP2_MORE);
        else CHECK(r==IAP2_INVALID&&out[0]==0xb1&&!s.synced);
    }
    for(size_t n=0;n<34;++n) if(n!=32) { auto s=fresh(); std::array<uint8_t,34> p{}; Packet out{};
        CHECK(projection_timing_feed(&s,p.data(),n,0,0,out.data())==IAP2_INVALID); }
    auto s=fresh(); Packet p{},out{}; CHECK(projection_timing_probe(&s,0,p.data())==IAP2_OK);
    CHECK(projection_timing_sent(&s,0,epoch)==IAP2_OK);
    p=packet(211,epoch+1,epoch,epoch); CHECK(projection_timing_feed(&s,p.data(),32,1,1,out.data())==IAP2_MORE&&s.pending);
    p=packet(211,epoch,epoch,epoch+1); CHECK(projection_timing_feed(&s,p.data(),32,1,1,out.data())==IAP2_OK&&!s.pending);
    CHECK(projection_timing_feed(&s,p.data(),32,1,1,out.data())==IAP2_MORE&&s.picks==1);
    s=fresh(); CHECK(projection_timing_sent(&s,0,epoch)==IAP2_OK);
    p=packet(211,epoch,epoch,epoch+(UINT64_C(1)<<32)); CHECK(projection_timing_feed(&s,p.data(),32,1,1,out.data())==IAP2_INVALID&&!s.pending);
    s=fresh(); CHECK(sample(s,0,second,UINT64_C(1)<<32,0)==IAP2_INVALID&&!s.synced);
    s=fresh(); CHECK(sample(s,0,second/4,UINT64_C(1)<<30,UINT64_C(1)<<63)==IAP2_INVALID&&!s.synced);
}
static void filter_and_modular_clock(bool trace=false) {
    for(auto sign:{UINT64_C(1),UINT64_MAX}) {
        auto s=fresh(); uint64_t offset=sign*(UINT64_C(1)<<31);
        CHECK(sample(s,0,second/4,UINT64_C(1)<<30,offset+7)==IAP2_OK);
        CHECK(sample(s,second,second/8,UINT64_C(1)<<29,offset)==PROJECTION_TIMING_SAMPLE);
        CHECK(s.ntp_origin==epoch+offset&&s.samples==1&&s.synced);
        if(trace) std::cout<<"phase "<<sign<<" 0 "<<s.ntp_origin<<'\n';
        auto before=s.ntp_origin; uint64_t small=sign*(UINT64_C(1)<<26);
        CHECK(sample(s,2*second,second/8,UINT64_C(1)<<29,small)==IAP2_OK);
        CHECK(sample(s,3*second,second/8,UINT64_C(1)<<29,small)==PROJECTION_TIMING_SAMPLE);
        CHECK(s.ntp_origin==before+sign*(UINT64_C(1)<<23)&&s.samples==2&&s.delay_count==1);
        if(trace) std::cout<<"phase "<<sign<<" 1 "<<s.ntp_origin<<'\n';
        before=s.ntp_origin; auto deadline=s.last_sync_ns;
        CHECK(sample(s,4*second,second/4,UINT64_C(1)<<30,small)==IAP2_OK);
        CHECK(sample(s,5*second,second/4,UINT64_C(1)<<30,small)==IAP2_OK);
        CHECK(s.ntp_origin==before&&s.last_sync_ns==deadline&&s.delay_count==2);
        if(trace) std::cout<<"phase "<<sign<<" 2 "<<s.ntp_origin<<'\n';
        CHECK(sample(s,6*second,second/8,UINT64_C(1)<<29,offset)==IAP2_OK);
        CHECK(sample(s,7*second,second/8,UINT64_C(1)<<29,offset)==PROJECTION_TIMING_SAMPLE);
        CHECK(s.ntp_origin==before+offset&&s.delay_count==0);
        if(trace) std::cout<<"phase "<<sign<<" 3 "<<s.ntp_origin<<'\n';
    }
    auto s=fresh(0,UINT64_MAX-(UINT64_C(1)<<30)); CHECK(projection_timing_now(&s,second)==UINT64_C(3221225471));
    CHECK(sample(s,0,second/4,UINT64_C(1)<<30,UINT64_C(1)<<30)==IAP2_OK);
    CHECK(sample(s,second,second/4,UINT64_C(1)<<30,UINT64_C(1)<<30)==PROJECTION_TIMING_SAMPLE&&s.ntp_origin==UINT64_MAX);
    for(uint64_t n: {UINT64_C(1),UINT64_C(999999999),UINT64_C(1000000001),UINT64_MAX}) {
        auto expected=((n/second)<<32)+((n%second)*UINT64_C(4294967296))/second;
        s=fresh(); CHECK(projection_timing_now(&s,n)==epoch+expected);
        if(trace) std::cout<<"clock "<<n<<' '<<projection_timing_now(&s,n)<<'\n';
    }
    s=fresh();
    for(unsigned i=0;i<4;++i) CHECK(sample(s,i*second,second/8,UINT64_C(1)<<29,0)==(i%2?PROJECTION_TIMING_SAMPLE:IAP2_OK));
    auto last=s.last_sync_ns;
    for(unsigned group=0;group<9;++group) {
        auto at=(4+2*group)*second;
        CHECK(sample(s,at,second/4,UINT64_C(1)<<30,0)==IAP2_OK);
        CHECK(sample(s,at+second,second/4,UINT64_C(1)<<30,0)==(group==8?PROJECTION_TIMING_SAMPLE:IAP2_OK));
        if(group<8) CHECK(s.last_sync_ns==last);
    }
    CHECK(s.delay_count==8&&s.samples==3); // Old low-delay observation ages out; filter cannot lock forever.
}
static void deadlines_and_validation() {
    auto s=fresh(UINT64_MAX-4000000000); Packet p{};
    CHECK(projection_timing_sent(&s,s.now_ns,epoch)==IAP2_OK);
    CHECK(projection_timing_check(&s,UINT64_MAX-1000000001)==IAP2_OK&&s.pending&&projection_timing_next_delay(&s)==1);
    CHECK(projection_timing_check(&s,UINT64_MAX-1000000000)==IAP2_OK&&!s.pending&&s.timeouts==1);
    CHECK(projection_timing_probe(&s,UINT64_MAX,p.data())==IAP2_OK);
    s=fresh(); CHECK(projection_timing_check(&s,1)==IAP2_OK); auto saved=s;
    CHECK(projection_timing_check(&s,0)==IAP2_ARGUMENT&&std::memcmp(&s,&saved,sizeof(s))==0);
    CHECK(projection_timing_check(&s,30*second-1)==IAP2_OK);
    CHECK(projection_timing_check(&s,30*second)==PROJECTION_TIMING_CLOSED&&zeroed(&s,sizeof(s)));
    CHECK(projection_timing_next_delay(&s)==UINT32_MAX&&projection_timing_check(&s,30*second)==PROJECTION_TIMING_CLOSED);
    for(unsigned mode=0;mode<8;++mode) { projection_timing_config cfg{}; projection_timing_default_config(&cfg); s=fresh(); saved=s;
        if(mode==0) cfg.interval_ms=0; if(mode==1) cfg.interval_ms=60001; if(mode==2) cfg.response_ms=0;
        if(mode==3) cfg.response_ms=60001; if(mode==4) cfg.sync_ms=0; if(mode==5) cfg.sync_ms=60001;
        if(mode==6) cfg.max_rtt_ms=0; if(mode==7) cfg.max_rtt_ms=3001;
        CHECK(projection_timing_init(&s,&cfg,0,0)==IAP2_ARGUMENT&&std::memcmp(&s,&saved,sizeof(s))==0);
    }
    // Deterministic malformed traffic cannot write outside the reply or renew sync.
    uint32_t rng=7919; s=fresh(); std::array<uint8_t,34> out{}; out.fill(0xed);
    for(unsigned i=0;i<10000;++i) { Packet input{}; for(auto& b:input) { rng=rng*1664525+1013904223; b=static_cast<uint8_t>(rng>>24); }
        (void)projection_timing_feed(&s,input.data(),32,i,i,out.data()+1); CHECK(out.front()==0xed&&out.back()==0xed&&!s.synced); }
}
int main(int argc,char** argv) {
    try { if(argc==2&&std::string(argv[1])=="--trace") { filter_and_modular_clock(true); return 0; } CHECK(argc==1);
        wire_and_commit(); malformed_and_matching(); filter_and_modular_clock(); deadlines_and_validation();
        std::cout<<"PASS: 4 timing groups; exact wire, bounded modular clock/filter, validation/deadlines and 10000 malformed packets\n"; return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
