#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "native_attach.h"
#include "native_so.h"
#include "native_so_state.h"
#include <memory>
#ifdef STREAMLINK_LINUX
#include <chrono>
static unsigned long long GetTickCount64(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
#endif

namespace {
std::unique_ptr<streamlink::SimultaneousOpen> state;
raw_info_t shape;
bool client_entered=false, outer_complete=false;
void send(const streamlink::ShapePacket &p);
void ensure() {
    if (state) return;
    state=std::make_unique<streamlink::SimultaneousOpen>(get_true_random_number());
    state->start(native_attachment_start_tick());
    address_t local,peer; native_attachment_endpoints(local,peer);
    shape.send_info.new_src_ip.from_address_t(local); shape.send_info.src_port=local.get_port();
    shape.send_info.new_dst_ip.from_address_t(peer); shape.send_info.dst_port=peer.get_port();
    // Always emit our own initial SYN before processing a queued crossed SYN.
    // Otherwise event-loop ordering could silently turn one side into passive.
    if (auto p=state->tick(GetTickCount64())) send(*p);
}
void send(const streamlink::ShapePacket &p) {
    auto &s=shape.send_info; s.seq=p.seq; s.ack_seq=p.ack;
    s.syn=(p.flags&2)!=0; s.ack=(p.flags&16)!=0; s.psh=false; s.rst=false;
    s.ts_ack=shape.recv_info.ts;
    send_raw0(shape,nullptr,0);
    mylog(log_debug,"SO shape sent flags=%u seq=%u ack=%u\n",unsigned(p.flags),p.seq,p.ack);
}
void tick() {
    ensure();
    // This is the native share of the same Start deadline. Product path auth and
    // nomination must consume the remaining deadline, never get another 8 sec.
    if (!outer_complete && GetTickCount64()>=state->deadline()) {
        mylog(log_warn,"SO attempt expired before outer authentication\n"); myexit(74);
    }
    if (auto p=state->tick(GetTickCount64())) send(*p);
    if (state->phase()==streamlink::ShapePhase::closed) { mylog(log_warn,"SO SYN state rejected\n"); myexit(74); }
}
}
bool native_so_receive() {
    if (!native_attachment_so()) return false;
    ensure();
    if (!outer_complete && GetTickCount64()>=state->deadline()) { mylog(log_warn,"SO shared deadline exceeded\n"); myexit(74); }
    raw_info_t incoming; incoming.peek=true; char *payload=nullptr; int size=0;
    if (recv_raw0(incoming,payload,size)!=0) { discard_raw_packet(); return true; }
    const auto &r=incoming.recv_info; auto &s=shape.send_info;
    const auto *raw=reinterpret_cast<const unsigned char*>(g_packet_buf);
    unsigned ihl=raw_ip_version==AF_INET6?40:(raw[0]&15)*4;
    std::uint8_t flags=raw[ihl+13];
    if (!r.new_src_ip.equal(s.new_dst_ip) || !r.new_dst_ip.equal(s.new_src_ip) || r.dst_port!=s.src_port) {
        discard_raw_packet(); return true;
    }
    if(r.src_port!=s.dst_port) {
        if(outer_complete || state->phase()!=streamlink::ShapePhase::syn_sent || size!=0 ||
            !(flags==2 || (flags==18 && r.ack_seq==state->iss()+1u)) || !native_attachment_learn_peer_port(r.src_port)) {
            discard_raw_packet(); return true;
        }
        s.dst_port=r.src_port;
        mylog(log_info,"SO tentative peer port learned; authentication still required\n");
    }
    if ((flags&4) && outer_complete) return false; // retain the legacy data-phase reset policy
    shape.recv_info=r;
    bool before=state->established();
    if (auto response=state->receive({r.seq,r.ack_seq,flags,unsigned(size)},GetTickCount64())) send(*response);
    if (!before && state->established()) mylog(log_info,"SO TcpShapeEstablished; continuing legacy HTTP/udp2raw\n");
    // Never deliver duplicate SYN/SYNACK or pure ACK to the legacy server, whose
    // old SYN handler intentionally implements only passive open.
    if (!state->established() || (flags&7) || size==0) { discard_raw_packet(); return true; }
    return false;
}
bool native_so_client_gate(conn_info_t &connection) {
    if (!native_attachment_so()) return true;
    if (connection.state.client_current_state==client_ready) outer_complete=true;
    tick();
    if (!state->established()) return false;
    if (!client_entered) {
        client_entered=true;
        connection.raw_info.send_info=shape.send_info;
        connection.raw_info.recv_info=shape.recv_info;
        // The existing client_handshake1 advances ISS once and emits ACK,
        // HTTP, bare exactly as before, including the overlapping HTTP seq.
        connection.raw_info.send_info.seq=state->iss();
        connection.raw_info.recv_info.seq=state->irs();
        connection.my_id=get_true_random_number_nz(); connection.blob->anti_replay.re_init();
        connection.state.client_current_state=client_handshake1;
        connection.last_state_time=get_current_time(); connection.last_hb_sent_time=0;
    } else if (connection.state.client_current_state==client_idle) {
        mylog(log_warn,"SO owned tuple retired; parent must acquire a new attempt\n"); myexit(74);
    }
    return true;
}
void native_so_server_tick() {
    if (!native_attachment_so()) return;
    for (auto &entry:conn_manager.mp) if (entry.second->state.server_current_state==server_ready) outer_complete=true;
    tick();
}
