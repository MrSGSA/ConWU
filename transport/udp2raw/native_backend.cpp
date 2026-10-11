#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "native_backend.h"
#include "native_attach.h"
#include "native_so.h"
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

#ifdef UDP2RAW_TEST_IO
SOCKET test_socket = INVALID_SOCKET;
sockaddr_in test_peer{};
#endif

void stop_capture() {
    stopping.store(true);
#ifdef UDP2RAW_TEST_IO
    if (test_socket != INVALID_SOCKET) {
        closesocket(test_socket);
    }
#else
    if (handle != INVALID_HANDLE_VALUE) wd_shutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
#endif
    if (reader.joinable()) reader.join();
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
        if (length == 0 || length > huge_data_len) continue;
        pthread_mutex_lock(&queue_mutex);
        if (!my_queue.full()) my_queue.push_back(packet, length);
        else ++queue_drops;
        pthread_mutex_unlock(&queue_mutex);
        ev_async_send(g_default_loop, &async_watcher);
    }
}

#ifdef UDP2RAW_TEST_IO
int test_port(const char *name) {
    const char *value = getenv(name);
    char *end = nullptr;
    long port = value ? strtol(value, &end, 10) : 0;
    if (!value || !end || *end || port < 1024 || port > 65535)
        fail("test transport requires explicit loopback ports");
    return static_cast<int>(port);
}
#endif
}

int init_raw_socket() {
    if (raw_ip_version != AF_INET || (raw_mode != mode_faketcp && raw_mode != mode_udp) || use_tcp_dummy_socket || lower_level) {
        mylog(log_fatal, "native backend requires IPv4 --raw-mode faketcp or udp (without --easy-tcp)\n");
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
#ifdef UDP2RAW_TEST_IO
    // Test-only datagram carriage of raw packets, always loopback. Never shipped.
    test_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons(test_port("STREAMLINK_TEST_BIND"));
    test_peer = local;
    test_peer.sin_port = htons(test_port("STREAMLINK_TEST_PEER"));
    DWORD timeout = 100;
    setsockopt(test_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int size = 4 * 1024 * 1024;
    setsockopt(test_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    if (bind(test_socket, reinterpret_cast<sockaddr *>(&local), sizeof(local)) != 0 ||
        connect(test_socket, reinterpret_cast<sockaddr *>(&test_peer), sizeof(test_peer)) != 0)
        fail("test socket setup failed");
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
    reader = std::thread(capture);
    while (!receiving.load()) Sleep(1);
    native_attachment_armed();
}

int send_raw_packet(raw_info_t &, const char *packet, int length) {
    std::unique_lock<std::mutex> lock(native_injection_mutex, std::defer_lock);
    if (native_attached()) lock.lock();
    if (!native_attachment_packet(packet,length)) return -1;
#ifdef UDP2RAW_TEST_IO
    return send(test_socket, packet, length, 0) == length ? 0 : -1;
#else
    if (handle == INVALID_HANDLE_VALUE) return -1;
    WINDIVERT_ADDRESS address{};
    address.Outbound = 1;
    address.IPChecksum = 1;
    address.TCPChecksum = 1;
    address.UDPChecksum = 1;
    UINT sent = 0;
    if (!wd_send(handle, packet, length, &sent, &address) || sent != static_cast<UINT>(length)) {
        mylog(log_warn, "WinDivertSend failed, error=%lu\n", GetLastError());
        return -1;
    }
    return 0;
#endif
}

void native_capture_shutdown() { stop_capture(); }

void native_drain_packets(conn_info_t *client) {
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
