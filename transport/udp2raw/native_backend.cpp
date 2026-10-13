#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "native_backend.h"
#include "native_attach.h"
#include "native_so.h"
#include "native_broker.h"
#include "native_legacy_control.h"
#include "native_legacy_egress.h"
#include <atomic>
#include <thread>
#include "windivert.h"

int client_on_raw_recv(conn_info_t &);
int server_on_raw_recv_multi();

namespace {
// Only this source knows about WinDivert. No EasyTier FakeTCP code is used.
HMODULE library = nullptr;
HANDLE handle = INVALID_HANDLE_VALUE;
decltype(&WinDivertOpen) wd_open;
decltype(&WinDivertRecv) wd_recv;
decltype(&WinDivertSend) wd_send;
decltype(&WinDivertClose) wd_close;
decltype(&WinDivertShutdown) wd_shutdown;
decltype(&WinDivertSetParam) wd_set;
decltype(&WinDivertHelperCalcChecksums) wd_checksums;
std::thread reader;
std::atomic<bool> stopping{false};
std::atomic<bool> receiving{false};
std::string capture_descriptor;
std::atomic<unsigned long long> suppressed_outbound{0};
std::atomic<DWORD> reader_error{0};
std::atomic<unsigned long long> queue_drops{0};
// Local, opt-in cumulative telemetry only; no public packet/profile changes.
// Broker workers already report at the parent injection point, so exclude them.
std::string wire_report_id;
unsigned long long wire_counts[5]{}, wire_bytes[5]{}, wire_failures=0, wire_report_sequence=0;
std::atomic<unsigned long long> wire_received{0}, wire_received_bytes{0};
unsigned long long wire_report_at=0, wire_source_changes=0;
std::string wire_source="Unknown";
std::mutex wire_statistics;
bool inject_legacy_now(const char *packet,int length,native_wire_kind kind);
struct wire_reporter {
    std::mutex gate;
    std::string latest;
    HANDLE wake=CreateEventW(nullptr,FALSE,FALSE,nullptr);
};
wire_reporter *reports=nullptr; // bounded process-lifetime state, no packet payload
DWORD WINAPI report_worker(void *state) {
    auto &r=*static_cast<wire_reporter *>(state);
    while(WaitForSingleObject(r.wake,INFINITE)==WAIT_OBJECT_0) {
        std::string line;
        {std::lock_guard<std::mutex> lock(r.gate);line.swap(r.latest);}
        if(line.empty())continue;
        // A slow log sink blocks ONLY this worker. Producers coalesce at most
        // one newer cumulative snapshot; the protocol event loop never writes
        // or waits on stdout. Parent JobObject teardown owns process exit.
        DWORD written=0;
        if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),line.data(),static_cast<DWORD>(line.size()),&written,nullptr))return 0;
    }
    return 0;
}
void initialize_reports() {
    if(reports||wire_report_id.empty()||native_broker_mode())return;
    auto *r=new wire_reporter;
    if(!r->wake){delete r;wire_report_id.clear();return;}
    HANDLE worker=CreateThread(nullptr,0,report_worker,r,0,nullptr);
    if(!worker){CloseHandle(r->wake);delete r;wire_report_id.clear();return;}
    CloseHandle(worker);reports=r;
}
void emit_wire_report_locked(bool final=false) {
    if(wire_report_id.empty() || native_broker_mode()) return;
    auto now=GetTickCount64();
    if(!final && wire_report_sequence && now-wire_report_at<1000) return;
    wire_report_at=now; ++wire_report_sequence;
    if(!reports)return;
    char text[1024]{};
    int size=snprintf(text,sizeof(text),"SLW1 %s %llu %s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %u\n",
        wire_report_id.c_str(),wire_report_sequence,wire_source.c_str(),wire_source_changes,
        wire_counts[0],wire_bytes[0],wire_counts[1],wire_bytes[1],wire_counts[2],wire_bytes[2],
        wire_counts[3],wire_bytes[3],wire_counts[4],wire_bytes[4],wire_failures,
        wire_received.load(),wire_received_bytes.load(),queue_drops.load(),suppressed_outbound.load(),final?1:0);
    if(size<=0 || size>=static_cast<int>(sizeof(text)))return;
    std::string lines(text,size);
    if(native_legacy_control_enabled()) {
        unsigned long long counts[6];native_legacy_control_stats(counts);char queue[256]{};
        int n=snprintf(queue,sizeof(queue),"SLGQ1 %s %llu %llu %llu %llu %llu %llu %llu\n",wire_report_id.c_str(),wire_report_sequence,
            counts[0],counts[1],counts[2],counts[3],counts[4],counts[5]);
        if(n>0&&n<static_cast<int>(sizeof(queue)))lines.append(queue,n);
    }
    if(native_legacy_egress_enabled()) {
        unsigned long long c[8];native_legacy_egress_stats(c);char telemetry[320]{};
        int n=snprintf(telemetry,sizeof(telemetry),"SLGE1 %s %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",wire_report_id.c_str(),wire_report_sequence,c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7]);
        if(n>0&&n<static_cast<int>(sizeof(telemetry)))lines.append(telemetry,n);
    }
    {std::lock_guard<std::mutex> lock(reports->gate);reports->latest=std::move(lines);}
    SetEvent(reports->wake);
}
void emit_wire_report(bool final=false) {std::lock_guard<std::mutex> lock(wire_statistics);emit_wire_report_locked(final);}
void count_wire_send(const char *packet,int length,bool accepted,native_wire_kind label) {
    if(wire_report_id.empty() || native_broker_mode()) return;
    std::lock_guard<std::mutex> lock(wire_statistics);
    if(!accepted) { ++wire_failures; emit_wire_report_locked(); return; }
    unsigned kind=static_cast<unsigned>(label);
    if(kind>4)kind=0;
    ++wire_counts[kind];wire_bytes[kind]+=length;
    if(length>=40 && (static_cast<unsigned char>(packet[0])>>4)==4) {
        unsigned ihl=(static_cast<unsigned char>(packet[0])&15)*4;
        if(ihl>=20 && ihl+4<=static_cast<unsigned>(length)) {
            char ip[16]{};inet_ntop(AF_INET,packet+12,ip,sizeof(ip));
            unsigned port=(static_cast<unsigned char>(packet[ihl])<<8)|static_cast<unsigned char>(packet[ihl+1]);
            std::string source=std::string(ip)+":"+std::to_string(port);
            if(wire_source=="Unknown")wire_source=source;
            else if(wire_source!=source)++wire_source_changes;
        }
    }
    emit_wire_report_locked();
}

#ifdef UDP2RAW_TEST_IO
SOCKET test_socket = INVALID_SOCKET;
sockaddr_in test_peer{};
#endif

void stop_capture() {
    // Join any already-started control injection before closing its handle.
    // In-flight authorization can finish later, but cannot inject old epochs.
    native_legacy_control_pause();
    native_legacy_egress_pause();
    bool observed_window=reader.joinable();
    stopping.store(true);
    const bool broker_reader=native_broker_mode() && reader.joinable();
    if(broker_reader) native_broker_shutdown();
#ifdef UDP2RAW_TEST_IO
    if (test_socket != INVALID_SOCKET) {
        closesocket(test_socket);
    }
#else
    if (handle != INVALID_HANDLE_VALUE) wd_shutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
#endif
    if (reader.joinable()) reader.join();
    if(observed_window)emit_wire_report(true);
    if(broker_reader) native_broker_close();
#ifdef UDP2RAW_TEST_IO
    test_socket = INVALID_SOCKET;
#endif
    if (handle != INVALID_HANDLE_VALUE) {
        wd_close(handle);
        handle = INVALID_HANDLE_VALUE;
    }
}

void fail(const char *message) {
    mylog(log_fatal, "%s, Windows error=%lu\n", message, GetLastError());
    myexit(-1);
}

template<class T> void symbol(T &output, const char *name) {
    output = reinterpret_cast<T>(GetProcAddress(library, name));
    if (!output) fail("incompatible WinDivert DLL");
}

[[maybe_unused]] void load_driver_api() {
    if (library) return;
    wchar_t path[32768];
    const DWORD length = GetModuleFileNameW(nullptr, path, 32768);
    if (length == 0 || length >= 32768) fail("cannot resolve executable path");
    wchar_t *separator = wcsrchr(path, L'\\');
    if (!separator || separator - path + 16 >= 32768) fail("invalid executable path");
    wcscpy(separator + 1, L"WinDivert.dll");
    // Do not load a DLL from the working directory or an unrelated installation.
    library = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) fail("place the official WinDivert DLL beside this executable");
    symbol(wd_open, "WinDivertOpen");
    symbol(wd_recv, "WinDivertRecv");
    symbol(wd_send, "WinDivertSend");
    symbol(wd_close, "WinDivertClose");
    symbol(wd_shutdown, "WinDivertShutdown");
    symbol(wd_set, "WinDivertSetParam");
    symbol(wd_checksums, "WinDivertHelperCalcChecksums");
}

void capture() {
    char packet[huge_buf_len];
    receiving.store(true);
    while (!stopping.load()) {
        UINT length = 0;
        if(native_broker_mode()) {
            int n=native_broker_receive(packet,sizeof(packet));
            if(n<0) {
                if(!stopping.load()) reader_error.store(ERROR_BROKEN_PIPE);
                ev_async_send(g_default_loop,&async_watcher); break;
            }
            length=n;
        } else {
#ifdef UDP2RAW_TEST_IO
        int received = recv(test_socket, packet, sizeof(packet), 0);
        if (received == SOCKET_ERROR) {
            const auto error = WSAGetLastError();
            // A test peer may not have bound its UDP carriage yet (SO starts
            // both directions). ICMP port-unreachable models a dropped packet,
            // not a WinDivert receive failure. Production branch is unchanged.
            if (error == WSAETIMEDOUT || error == WSAECONNRESET) continue;
            if (!stopping.load()) reader_error.store(error);
            ev_async_send(g_default_loop, &async_watcher);
            break;
        }
        length = received;
#else
        WINDIVERT_ADDRESS address{};
        if (!wd_recv(handle, packet, sizeof(packet), &length, &address)) {
            if (!stopping.load()) reader_error.store(GetLastError());
            ev_async_send(g_default_loop, &async_watcher);
            break;
        }
        // Managed capture owns exactly the authorized wire tuple. Raw injection
        // bypasses its own handle; kernel-generated responses must not escape.
        if (native_attached() && address.Outbound) { ++suppressed_outbound; continue; }
        // Checksums may be omitted by hardware offload. The protocol parser
        // expects a complete packet, so normalize only when flags say necessary.
        if ((!address.IPChecksum || (raw_mode == mode_udp ? !address.UDPChecksum : !address.TCPChecksum)) &&
            !wd_checksums(packet, length, &address, 0)) continue;
#endif
        }
        if (length == 0 || length > huge_data_len) continue;
        if(!wire_report_id.empty() && !native_broker_mode()){++wire_received;wire_received_bytes+=length;}
        pthread_mutex_lock(&queue_mutex);
        if (!my_queue.full()) my_queue.push_back(packet, length);
        else ++queue_drops;
        pthread_mutex_unlock(&queue_mutex);
        ev_async_send(g_default_loop, &async_watcher);
    }
}

#ifdef UDP2RAW_TEST_IO
int test_port(const char *name, bool allow_zero=false) {
    const char *value = getenv(name);
    char *end = nullptr;
    long port = value ? strtol(value, &end, 10) : 0;
    if (!value || !end || *end || (!(allow_zero && port==0) && port < 1024) || port > 65535)
        fail("test transport requires explicit loopback ports");
    return static_cast<int>(port);
}
#endif
}

int init_raw_socket() {
    if ((raw_ip_version != AF_INET && !(raw_ip_version==AF_INET6 && native_broker_mode() && raw_mode==mode_faketcp)) || (raw_mode != mode_faketcp && raw_mode != mode_udp) || use_tcp_dummy_socket || lower_level) {
        mylog(log_fatal, "native backend requires IPv4, or authorized brokered IPv6 FakeTCP (without --easy-tcp)\n");
        myexit(-1);
    }
    send_with_pcap = 0;
    pcap_header_captured = 1;
    pcap_link_header_len = 0;
    extern unsigned short g_ip_id_counter;
    g_ip_id_counter = get_true_random_number() % 65535;
    std::atexit(stop_capture);
    return 0;
}

void init_filter(int port) {
    if (port <= 0 || port > 65535) fail("invalid native filter port");
    if(wire_report_id.empty()) {
        const char *id=getenv("STREAMLINK_LEGACY_WIRE_ID");
        if(id && strlen(id)==32 && strspn(id,"0123456789abcdef")==32) wire_report_id=id;
    }
    initialize_reports();
    if(!native_broker_mode()&&!native_legacy_control_init(inject_legacy_now))fail("legacy control authorization failed");
    if(!native_broker_mode()&&!native_legacy_egress_init())fail("legacy egress authorization failed");
    // Compare the whole capture description, not just the local port. No
    // overlapping old/new handles: retire the previous capture before reopening.
    std::string descriptor=std::to_string(port)+"/"+std::to_string(raw_mode)+"/"+std::to_string(program_mode)+
        "/"+remote_addr.get_str()+"/"+local_addr.get_str()+"/"+std::to_string(bind_addr_used)+"/100/NETWORK/"+
        (getenv("STREAMLINK_STUN_ENDPOINT") ? getenv("STREAMLINK_STUN_ENDPOINT") : "")+"/"+
        (getenv("STREAMLINK_ALLOW_DRIVER_INSTALL") ? getenv("STREAMLINK_ALLOW_DRIVER_INSTALL") : "");
    if (native_attached()) descriptor += native_attachment_filter();
    if (capture_descriptor == descriptor && reader.joinable()) return;
    if (native_attached() && !capture_descriptor.empty()) fail("managed capture descriptor is immutable; acquire a new attachment");
    stop_capture();
    capture_descriptor=descriptor;
    stopping.store(false);
    receiving.store(false);
    reader_error.store(0);
    pthread_mutex_lock(&queue_mutex);
    my_queue.clear();
    pthread_mutex_unlock(&queue_mutex);
    filter_port = port;
    if(!native_broker_mode()) {
#ifdef UDP2RAW_TEST_IO
    // Test-only datagram carriage of raw packets, always loopback. Never shipped.
    test_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons(test_port("STREAMLINK_TEST_BIND", true));
    test_peer = local;
    test_peer.sin_port = htons(test_port("STREAMLINK_TEST_PEER"));
    DWORD timeout = 100;
    setsockopt(test_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int size = 4 * 1024 * 1024;
    int exclusive = 1;
    setsockopt(test_socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &exclusive, sizeof(exclusive));
    setsockopt(test_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if (bind(test_socket, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0 ||
        connect(test_socket, reinterpret_cast<sockaddr *>(&test_peer), sizeof(test_peer)) != 0)
        fail("test socket setup failed");
    if (local.sin_port==0) {
        // Test fixture registration only, not a raw IP/TCP packet. Let the
        // actual owner allocate its UDP carriage instead of closing/rebinding
        // a port which another fixture bridge can claim in the meantime.
        const char *token=getenv("STREAMLINK_TEST_HELLO");
        if (!token || strlen(token)!=32 || strspn(token,"0123456789abcdef")!=32)
            fail("ephemeral test transport needs registration token");
        char hello[36]; memcpy(hello,"SLT1",4); memcpy(hello+4,token,32);
        if (::send(test_socket,hello,sizeof(hello),0)!=sizeof(hello)) fail("test registration failed");
    }
#else
    load_driver_api();
    const std::string protocol = raw_mode == mode_udp ? "udp" : "tcp";
    std::string filter = "inbound and !loopback and ip and " + protocol + " and " + protocol + ".DstPort == " + std::to_string(port);
    if (program_mode == client_mode) {
        filter += " and ip.SrcAddr == " + std::string(remote_addr.get_ip());
        filter += " and " + protocol + ".SrcPort == " + std::to_string(remote_addr.get_port());
    } else if (bind_addr_used) {
        filter += " and ip.DstAddr == " + std::string(local_addr.get_ip());
    }
    if (raw_mode == mode_udp && program_mode == server_mode) {
        const char *stun_endpoint = getenv("STREAMLINK_STUN_ENDPOINT");
        if (stun_endpoint && *stun_endpoint) {
            address_t stun;
            std::string endpoint(stun_endpoint);
            if (endpoint.size() > 64 || stun.from_str(endpoint.data()) != 0 || stun.get_type() != AF_INET)
                fail("invalid native STUN endpoint");
            filter += " and (ip.SrcAddr != " + std::string(stun.get_ip()) + " or udp.SrcPort != " + std::to_string(stun.get_port()) + ")";
        }
    }
    if (native_attached()) filter = native_attachment_filter();
    // The packaged, elevated launcher explicitly opts into the official signed
    // driver's on-demand installation. Standalone developer runs stay read-only.
    const char *install = getenv("STREAMLINK_ALLOW_DRIVER_INSTALL");
    const UINT64 flags = install && strcmp(install, "1") == 0 ? 0 : WINDIVERT_FLAG_NO_INSTALL;
    mylog(log_info, "opening native capture: %s\n", filter.c_str());
    handle = wd_open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 100, flags);
    if (handle == INVALID_HANDLE_VALUE) fail("WinDivertOpen failed (administrator and installed driver required)");
    if (!wd_set(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096) ||
        !wd_set(handle, WINDIVERT_PARAM_QUEUE_TIME, 100) ||
        !wd_set(handle, WINDIVERT_PARAM_QUEUE_SIZE, 4 * 1024 * 1024))
        fail("cannot configure bounded WinDivert queue");
    mylog(log_info, "native capture: %s\n", filter.c_str());
#endif
    }
    reader = std::thread(capture);
    while (!receiving.load()) Sleep(1);
    native_attachment_armed();
    native_legacy_control_arm();
    native_legacy_egress_arm();
}

namespace {
bool inject_legacy_now(const char *packet,int length,native_wire_kind kind) {
#ifdef UDP2RAW_TEST_IO
    bool accepted=send(test_socket,packet,length,0)==length;
#else
    if(handle==INVALID_HANDLE_VALUE)return false;
    WINDIVERT_ADDRESS address{};address.Outbound=1;address.IPChecksum=1;address.TCPChecksum=1;address.UDPChecksum=1;
    UINT sent=0;bool accepted=wd_send(handle,packet,length,&sent,&address)&&sent==static_cast<UINT>(length);
    if(!accepted)mylog(log_warn,"WinDivertSend failed, error=%lu\n",GetLastError());
#endif
    count_wire_send(packet,length,accepted,kind);return accepted;
}
}

int send_raw_packet(raw_info_t &, const char *packet, int length) {
    std::unique_lock<std::mutex> lock(native_injection_mutex, std::defer_lock);
    if (native_attached()) lock.lock();
    if (!native_attachment_packet(packet,length)) return -1;
    if(native_broker_mode()) return native_broker_send(packet,length);
    if(native_legacy_egress_enabled()&&native_wire_current()==native_wire_kind::business)
        return native_legacy_egress_send(packet,length,native_wire_peer())?0:-1;
    auto kind=native_wire_current();
    if(native_legacy_control_enabled()&&kind!=native_wire_kind::business)
        return native_legacy_control_enqueue(packet,length,kind)?0:-1;
    return inject_legacy_now(packet,length,kind)?0:-1;
}

void native_capture_shutdown() { stop_capture(); }

void native_drain_packets(conn_info_t *client) {
    if(native_legacy_control_failed()){mylog(log_fatal,"legacy control owner lost\n");myexit(74);}
    if(native_legacy_egress_failed()){mylog(log_fatal,"legacy egress owner lost\n");myexit(74);}
    if (reader_error.load()) {
        mylog(log_fatal, "native receive loop failed: %lu\n", reader_error.load());
        myexit(-1);
    }
    // Bound work per callback so UDP send/receive and heartbeats stay responsive.
    for (int count = 0; count < 64; ++count) {
        pthread_mutex_lock(&queue_mutex);
        if (my_queue.empty()) {
            pthread_mutex_unlock(&queue_mutex);
            return;
        }
        char *packet;
        int length;
        my_queue.peek_front(packet, length);
        // Copy while holding the lock; the producer may reuse a popped slot.
        memcpy(g_packet_buf, packet, length);
        my_queue.pop_front();
        pthread_mutex_unlock(&queue_mutex);
        g_packet_buf_len = length;
        g_packet_buf_cnt = 1;
        if (native_so_receive()) continue;
        if (client) client_on_raw_recv(*client);
        else server_on_raw_recv_multi();
        assert(g_packet_buf_cnt == 0);
    }
    ev_async_send(g_default_loop, &async_watcher);
}
