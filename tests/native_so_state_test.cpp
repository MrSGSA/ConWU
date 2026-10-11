#include "native_so_state.h"
#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <vector>
using namespace streamlink;
void check(bool value, const char *why) { if (!value) throw std::runtime_error(why); }
struct Flight { unsigned to; std::uint64_t due; ShapePacket packet; };
int main() {
    int cases = 0;
    // Each mechanism gets 30 deterministic independent ISS pairs, including wrap.
    for (int run=0; run<30; ++run) for (int offset : {-500,-100,0,100,500}) for (int loss=0;loss<4;++loss) {
        SimultaneousOpen a(run==0 ? UINT32_MAX : 0x91370000u+run*131u), b(run==0 ? UINT32_MAX-1 : 0xb3110031u+run*193u);
        SimultaneousOpen *nodes[]={&a,&b};
        std::uint64_t starts[]={std::uint64_t(offset<0?-offset:0), std::uint64_t(offset>0?offset:0)};
        std::vector<Flight> flights; bool dropped=false;
        auto queue=[&](unsigned from, ShapePacket p, std::uint64_t now) {
            if (!dropped && ((loss==1 && p.flags==2) || (loss==2 && p.flags==18) || (loss==3 && p.flags==16))) { dropped=true; return; }
            flights.push_back({1-from,now+25,p});
            if (run%3==0) flights.push_back({1-from,now+40,p}); // duplicate/delayed
        };
        for (std::uint64_t now=0;now<8500 && !(a.established()&&b.established());now+=5) {
            for (unsigned n=0;n<2;++n) {
                if (now==starts[n]) check(nodes[n]->start(now), "initial start");
                if (auto p=nodes[n]->tick(now)) queue(n,*p,now);
            }
            // Reverse delivery order also exercises crossing SYN+ACK/duplicate ACK.
            for (int i=int(flights.size())-1;i>=0;--i) if (flights[i].due<=now) {
                auto f=flights[i]; flights.erase(flights.begin()+i);
                if (auto response=nodes[f.to]->receive(f.packet,now)) queue(f.to,*response,now);
            }
        }
        check(a.established()&&b.established(), "positive simultaneous-open did not converge");
        check(a.irs()==b.iss() && b.irs()==a.iss(), "wrong sequence identity"); ++cases;
    }
    for (int i=0;i<30;++i) {
        SimultaneousOpen s(UINT32_MAX); check(s.start(100),"start"); check(!s.start(101),"duplicate Start cannot allocate ISS");
        s.receive({42,1,18},110); check(!s.established(),"wrong ACK accepted");
        s.receive({42,1,20},111); check(s.phase()==ShapePhase::syn_sent,"stale RST closed attempt");
        auto response=s.receive({42,0,2},112); check(response && response->seq==UINT32_MAX && response->ack==43,"SYN crossing/wrap");
        check(!s.receive({41,0,2},113),"old peer SYN changed IRS");
        s.receive({43,0,16},114); check(s.established(),"wrapped SYN confirmation");
        s.cancel(); s.receive({42,0,18},115); check(s.phase()==ShapePhase::closed,"late SYNACK revived canceled attempt");
        SimultaneousOpen timeout(17); timeout.start(100); timeout.tick(8100); timeout.receive({2,18,18},8101);
        check(timeout.phase()==ShapePhase::expired,"expired attempt revived");
        SimultaneousOpen reset(17); reset.start(100); reset.receive({2,18,20},110);
        check(reset.phase()==ShapePhase::closed,"matching handshake RST not recorded"); ++cases;
    }
    std::printf("{\"scope\":\"pure C++ TCP-shape model; not native integration or NAT\",\"cases\":%d,\"status\":\"Pass\"}\n",cases);
}
