// SPDX-License-Identifier: GPL-2.0-only
// AF_XDP-only Ethernet I/O. Wire protocol, authentication and approval stay above this layer.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define XDP_INCLUDE_WINCOMMON
#define XDP_API_VERSION 3
#include <xdp/wincommon.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <xdpapi.h>
#include <xdpapi_experimental.h>
#include <afxdp.h>
#include <afxdp_helper.h>
#include "xdp_io.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {
constexpr UINT32 RingSize = 512, ChunkSize = 2048;
constexpr UINT32 MaximumQueues = 64, MaximumAdapters = 16;
using Clock = std::chrono::steady_clock;
void check(HRESULT status, const char *stage) {
    if (FAILED(status)) {
        char text[192];
        snprintf(text, sizeof(text), "XDP %s failed (0x%08lx)", stage, (unsigned long)status);
        throw std::runtime_error(text);
    }
}
void wincheck(DWORD status, const char *stage) {
    if (status != NO_ERROR) check(HRESULT_FROM_WIN32(status), stage);
}
uint16_t word(const uint8_t *p) { return uint16_t((uint16_t(p[0]) << 8) | p[1]); }
uint32_t address(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return v; }
uint64_t tuple(uint32_t ip, uint16_t port) { return (uint64_t(ip) << 16) | port; }
struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    ~Handle() { reset(); }
    void reset() { if (value) { CloseHandle(value); value = nullptr; } }
};
struct Memory {
    void *value = nullptr;
    Memory() {
        value = VirtualAlloc(nullptr, SIZE_T(RingSize) * ChunkSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!value) throw std::bad_alloc();
    }
    ~Memory() { VirtualFree(value, 0, MEM_RELEASE); }
};
struct Socket {
    // The kernel must release UMEM registration before its storage is freed.
    Memory memory;
    Handle handle;
    XSK_RING_INFO_SET info{};
    void open(UINT32 index, UINT32 queue, bool receive, bool inject_receive = false) {
        check(XskCreate(&handle.value), "create (install Microsoft XDP 1.4 runtime if unavailable)");
        XSK_UMEM_REG reg{uint64_t(RingSize) * ChunkSize, ChunkSize, 0, memory.value};
        check(XskSetSockopt(handle.value, XSK_SOCKOPT_UMEM_REG, &reg, sizeof(reg)), "register UMEM");
        for (auto option : receive ? std::array<UINT32,2>{XSK_SOCKOPT_RX_RING_SIZE, XSK_SOCKOPT_RX_FILL_RING_SIZE}
                                   : std::array<UINT32,2>{XSK_SOCKOPT_TX_RING_SIZE, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE}) {
            check(XskSetSockopt(handle.value, option, &RingSize, sizeof(RingSize)), "configure rings");
        }
        if (inject_receive) {
            XDP_HOOK_ID hook{XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INJECT};
            check(XskSetSockopt(handle.value, XSK_SOCKOPT_TX_HOOK_ID, &hook, sizeof(hook)), "configure receive injection");
        }
        char binding[128];
        snprintf(binding, sizeof(binding), "bind Generic interface %u queue %u %s", index, queue,
                 receive ? "RX" : inject_receive ? "RX_INJECT" : "TX");
        check(XskBind(handle.value, index, queue, XSK_BIND_FLAG_GENERIC | (receive ? XSK_BIND_FLAG_RX : XSK_BIND_FLAG_TX)), binding);
        check(XskActivate(handle.value, XSK_ACTIVATE_FLAG_NONE), "activate");
        UINT32 size = sizeof(info);
        check(XskGetSockopt(handle.value, XSK_SOCKOPT_RING_INFO, &info, &size), "get rings");
    }
};
struct Transmitter {
    Socket socket;
    XSK_RING tx{}, completion{};
    std::mutex mutex;
    std::vector<UINT64> free;
    void open(UINT32 index, bool receive_inject) {
        socket.open(index, 0, false, receive_inject);
        XskRingInitialize(&tx, &socket.info.Tx);
        XskRingInitialize(&completion, &socket.info.Completion);
        for (UINT32 i = 0; i < RingSize; ++i) free.push_back(UINT64(i) * ChunkSize);
    }
    DWORD send(const uint8_t *frame, UINT32 length) {
        if (length < 14 || length > ChunkSize) return ERROR_INVALID_PARAMETER;
        std::lock_guard<std::mutex> lock(mutex);
        UINT32 ci, count = XskRingConsumerReserve(&completion, RingSize, &ci);
        for (UINT32 i = 0; i < count; ++i) {
            UINT64 offset = *static_cast<UINT64 *>(XskRingGetElement(&completion, ci + i));
            if (offset >= uint64_t(RingSize) * ChunkSize || offset % ChunkSize) return ERROR_INVALID_DATA;
            free.push_back(offset);
        }
        XskRingConsumerRelease(&completion, count);
        if (XskRingError(&tx) || XskRingError(&completion)) return ERROR_DEVICE_NOT_CONNECTED;
        UINT32 ti;
        if (free.empty() || XskRingProducerReserve(&tx, 1, &ti) != 1) return ERROR_RETRY;
        UINT64 offset = free.back(); free.pop_back();
        memcpy(static_cast<uint8_t *>(socket.memory.value) + offset, frame, length);
        auto *descriptor = static_cast<XSK_BUFFER_DESCRIPTOR *>(XskRingGetElement(&tx, ti));
        *descriptor = {};
        descriptor->Address.AddressAndOffset = offset;
        descriptor->Length = length;
        XskRingProducerSubmit(&tx, 1);
        if (XskRingProducerNeedPoke(&tx)) {
            XSK_NOTIFY_RESULT_FLAGS result{};
            auto status = XskNotifySocket(socket.handle.value, XSK_NOTIFY_FLAG_POKE_TX, 0, &result);
            if (FAILED(status)) return ERROR_DEVICE_NOT_CONNECTED;
        }
        return NO_ERROR;
    }
};
struct Context;
struct Interface;
struct Receiver {
    Socket socket;
    XSK_RING rx{}, fill{};
    std::thread thread;
    void open(UINT32 index, UINT32 queue) {
        socket.open(index, queue, true);
        XskRingInitialize(&rx, &socket.info.Rx);
        XskRingInitialize(&fill, &socket.info.Fill);
        UINT32 at;
        if (XskRingProducerReserve(&fill, RingSize, &at) != RingSize) throw std::runtime_error("XDP fill ring unavailable");
        for (UINT32 i = 0; i < RingSize; ++i) *static_cast<UINT64 *>(XskRingGetElement(&fill, at + i)) = UINT64(i) * ChunkSize;
        XskRingProducerSubmit(&fill, RingSize);
    }
    void run(Context *context, Interface *adapter);
    ~Receiver() { if (thread.joinable()) thread.join(); }
};
struct Interface {
    UINT32 index = 0;
    UINT32 mtu = 1500;
    std::array<uint8_t,6> mac{};
    std::vector<uint32_t> addresses;
    std::vector<std::unique_ptr<Receiver>> receivers;
    Transmitter output, pass;
    // XDP pins the caller's bitmap pages with an MDL; it does not copy them.
    // Keep storage stable until the attached program has been closed.
    std::array<UINT8,XDP_PORT_SET_BUFFER_SIZE> ports{};
    Handle program, map;
    void open_io() {
        Handle object;
        check(XdpInterfaceOpen(index, &object.value), "open interface");
        XDP_RSS_CAPABILITIES capabilities{};
        XdpInitializeRssCapabilities(&capabilities);
        UINT32 size = sizeof(capabilities);
        auto status = XdpRssGetCapabilities(object.value, &capabilities, &size);
        UINT32 queues;
        if (status == XDP_STATUS_NOT_SUPPORTED) queues = 1;
        else {
            check(status, "query RSS queues");
            queues = std::max(1u, capabilities.NumberOfReceiveQueues);
        }
        if (queues > MaximumQueues) throw std::runtime_error("XDP interface exceeds the supported 64 receive queues");
        output.open(index, false);
        pass.open(index, true);
        check(XdpMapCreate(&map.value, XDP_MAP_TYPE_XSKMAP), "create receive map");
        for (UINT32 i = 0; i < queues; ++i) {
            auto queue = std::make_unique<Receiver>();
            queue->open(index, i);
            check(XdpMapInsert(map.value, &i, &queue->socket.handle.value), "map receive queue");
            receivers.push_back(std::move(queue));
        }
    }
    void open(uint16_t port, uint32_t local_ip) {
        open_io();
        // Match only owned IPv4 destinations, leaving IPv6 sockets on the same
        // port and other adapters/addresses entirely outside the capture path.
        ports.fill(0);
        UINT16 network_port=htons(port);
        ports[network_port/8] |= UINT8(1u << (network_port%8));
        std::vector<XDP_RULE> rules;
        for (auto ip : addresses) {
            if (local_ip && ip!=local_ip) continue;
            XDP_RULE rule{};
            rule.Match = XDP_MATCH_IPV4_TCP_PORT_SET;
            rule.Pattern.IpPortSet.Address.Ipv4.s_addr = ip;
            rule.Pattern.IpPortSet.PortSet.PortSet = ports.data();
            rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
            rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSKMAP_BY_QUEUEID;
            rule.Redirect.Target = map.value;
            rules.push_back(rule);
        }
        XDP_HOOK_ID hook{XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INSPECT};
        check(XdpCreateProgram(index, &hook, 0, XDP_CREATE_PROGRAM_FLAG_GENERIC | XDP_CREATE_PROGRAM_FLAG_ALL_QUEUES, rules.data(),UINT32(rules.size()), &program.value), "attach owned IPv4 TCP port");
    }
};
struct Route {
    Interface *adapter = nullptr;
    std::array<uint8_t,14> ethernet{};
    Clock::time_point expires;
};
struct Context {
    CW_XDP_CONFIG config;
    CW_XDP_RECEIVE receive;
    CW_XDP_FAILURE failure;
    void *callback_context;
    std::atomic<bool> closing{false}, failed{false};
    std::atomic<uint64_t> protected_peer;
    std::vector<std::unique_ptr<Interface>> interfaces;
    std::mutex routes_mutex;
    std::unordered_map<uint64_t, Route> routes;
    Context(const CW_XDP_CONFIG &c, CW_XDP_RECEIVE r, CW_XDP_FAILURE f, void *p)
        : config(c), receive(r), failure(f), callback_context(p), protected_peer(tuple(c.protected_ip,c.protected_port)) {}
    ~Context() {
        closing.store(true);
        for (auto &adapter : interfaces) adapter->program.reset();
        for (auto &adapter : interfaces) for (auto &queue : adapter->receivers) if (queue->thread.joinable()) queue->thread.join();
    }
    void fail(const char *message) {
        if (!failed.exchange(true)) failure(callback_context, message);
        closing.store(true);
    }
    void start() {
        ULONG size = 16384;
        std::vector<uint8_t> buffer(size);
        ULONG status = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr,
                                            reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
        if (status == ERROR_BUFFER_OVERFLOW) {
            buffer.resize(size);
            status = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, nullptr,
                                          reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()), &size);
        }
        wincheck(status, "enumerate adapters");
        std::string rejected;
        for (auto *a = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(buffer.data()); a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp || a->PhysicalAddressLength != 6 || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL) continue;
            auto adapter = std::make_unique<Interface>();
            adapter->index = a->IfIndex;
            adapter->mtu = a->Mtu;
            memcpy(adapter->mac.data(), a->PhysicalAddress, 6);
            for (auto *u = a->FirstUnicastAddress; u; u = u->Next) {
                if (u->Address.lpSockaddr && u->Address.lpSockaddr->sa_family == AF_INET)
                    adapter->addresses.push_back(reinterpret_cast<sockaddr_in *>(u->Address.lpSockaddr)->sin_addr.s_addr);
            }
            if (adapter->addresses.empty() || (config.local_ip && std::find(adapter->addresses.begin(),adapter->addresses.end(),config.local_ip)==adapter->addresses.end())) continue;
            if (interfaces.size() == MaximumAdapters) throw std::runtime_error("XDP active adapter limit exceeded");
            try {
                adapter->open(config.local_port,config.local_ip);
                interfaces.push_back(std::move(adapter));
            } catch (const std::exception &error) {
                rejected += " interface=" + std::to_string(a->IfIndex) + ": " + error.what() + ";";
                if (config.local_ip) throw;
                fprintf(stderr, "XDP interface %lu not attached: %s\n", (unsigned long)a->IfIndex, error.what());
            }
        }
        if (interfaces.empty()) throw std::runtime_error("Mimic requires an XDP-enabled IPv4 Ethernet adapter and Microsoft XDP 1.4 runtime;" + rejected);
        for (auto &adapter : interfaces) for (auto &queue : adapter->receivers)
            queue->thread = std::thread(&Receiver::run, queue.get(), this, adapter.get());
    }
    bool owned(const uint8_t *ip, size_t length) const {
        if (length < 40 || (ip[0] >> 4) != 4 || ip[9] != 6) return false;
        auto header = size_t(ip[0] & 15) * 4;
        if (header < 20 || length < header + 20 || (word(ip+6) & 0x3fff)) return false;
        uint32_t local = address(ip+16), remote = address(ip+12);
        uint16_t source_port = word(ip+header), destination_port = word(ip+header+2);
        if (destination_port != config.local_port || (config.local_ip && local != config.local_ip)) return false;
        if (protected_peer.load() == tuple(remote,source_port)) return false;
        return config.server || (remote == config.remote_ip && (config.peer_reflexive || source_port == config.remote_port));
    }
    Route resolve(uint32_t local, uint32_t remote) {
        std::lock_guard<std::mutex> lock(routes_mutex);
        uint64_t key = (uint64_t(local) << 32) | remote;
        auto found = routes.find(key);
        if (found != routes.end() && found->second.expires > Clock::now()) return found->second;
        SOCKADDR_INET source{}, destination{};
        source.Ipv4.sin_family = AF_INET; source.Ipv4.sin_addr.s_addr = local;
        destination.Ipv4.sin_family = AF_INET; destination.Ipv4.sin_addr.s_addr = remote;
        MIB_IPFORWARD_ROW2 best{};
        SOCKADDR_INET selected{};
        wincheck(GetBestRoute2(nullptr,0,&source,&destination,0,&best,&selected), "resolve IPv4 route");
        Interface *adapter = nullptr;
        for (auto &candidate : interfaces) if (candidate->index == best.InterfaceIndex) { adapter = candidate.get(); break; }
        if (!adapter) throw std::runtime_error("Selected egress interface has no XDP attachment; reconnect after the route/interface change");
        MIB_IPNET_ROW2 neighbor{};
        neighbor.InterfaceLuid = best.InterfaceLuid;
        neighbor.Address = best.NextHop;
        if (!neighbor.Address.Ipv4.sin_addr.s_addr) neighbor.Address = destination;
        auto status = GetIpNetEntry2(&neighbor);
        if (status != NO_ERROR || neighbor.State == NlnsUnreachable || neighbor.State == NlnsIncomplete || neighbor.PhysicalAddressLength != 6)
            wincheck(ResolveIpNetEntry2(&neighbor,&source), "resolve Ethernet next hop");
        if (neighbor.PhysicalAddressLength != 6) throw std::runtime_error("XDP requires a six-byte Ethernet next hop");
        Route route;
        route.adapter = adapter;
        memcpy(route.ethernet.data(),neighbor.PhysicalAddress,6);
        memcpy(route.ethernet.data()+6,adapter->mac.data(),6);
        route.ethernet[12] = 8; route.ethernet[13] = 0;
        route.expires = Clock::now() + std::chrono::seconds(3);
        if (routes.size() >= 256) routes.clear();
        routes[key] = route;
        return route;
    }
    DWORD send(const uint8_t *ip, UINT32 length) {
        if (closing.load() || failed.load()) return ERROR_DEVICE_NOT_CONNECTED;
        if (length < 40 || length > 1500 || (ip[0]>>4)!=4 || ip[9]!=6 || word(ip+2)!=length) return ERROR_INVALID_PARAMETER;
        auto offset = size_t(ip[0]&15)*4;
        if (offset < 20 || length < offset+20 || word(ip+offset)!=config.local_port) return ERROR_INVALID_PARAMETER;
        if (config.local_ip && address(ip+12) != config.local_ip) return ERROR_INVALID_PARAMETER;
        auto route = resolve(address(ip+12),address(ip+16));
        if (length>route.adapter->mtu) return WSAEMSGSIZE;
        uint8_t frame[1514];
        memcpy(frame,route.ethernet.data(),14);
        memcpy(frame+14,ip,length);
        return route.adapter->output.send(frame,length+14);
    }
};
void Receiver::run(Context *context, Interface *adapter) {
    try {
        while (!context->closing.load(std::memory_order_relaxed)) {
            if (XskRingError(&rx) || XskRingError(&fill)) throw std::runtime_error("XDP receive interface/ring detached");
            UINT32 ri, fi;
            UINT32 n = XskRingConsumerReserve(&rx,64,&ri);
            if (!n) {
                XSK_NOTIFY_RESULT_FLAGS result{};
                auto status = XskNotifySocket(socket.handle.value,XSK_NOTIFY_FLAG_POKE_RX | XSK_NOTIFY_FLAG_WAIT_RX,100,&result);
                if (FAILED(status) && status != XDP_STATUS_TIMEOUT) check(status,"receive wait");
                continue;
            }
            if (XskRingProducerReserve(&fill,n,&fi)!=n) throw std::runtime_error("XDP recycle ring unavailable");
            for (UINT32 i=0;i<n;++i) {
                auto *d = static_cast<XSK_BUFFER_DESCRIPTOR *>(XskRingGetElement(&rx,ri+i));
                uint64_t pos = d->Address.BaseAddress+d->Address.Offset;
                if (pos > uint64_t(RingSize)*ChunkSize || d->Length > uint64_t(RingSize)*ChunkSize-pos)
                    throw std::runtime_error("XDP receive descriptor out of bounds");
                auto *frame = static_cast<uint8_t *>(socket.memory.value)+pos;
                size_t start=14;
                uint16_t type = d->Length>=14 ? word(frame+12) : 0;
                if ((type==0x8100 || type==0x88a8) && d->Length>=18) { type=word(frame+16); start=18; }
                bool ipv4 = type==0x0800 && d->Length>=start+20;
                size_t length = ipv4 ? word(frame+start+2) : 0;
                bool valid = ipv4 && length>=20 && length<=d->Length-start;
                if (valid && context->owned(frame+start,length)) {
                    if (length<=1500) context->receive(context->callback_context,frame+start,UINT32(length));
                } else {
                    // Protected STUN and unrelated traffic resume at RX_INJECT,
                    // above this XDP inspection hook, so they cannot loop.
                    auto status=adapter->pass.send(frame,d->Length);
                    if (status!=NO_ERROR) throw std::runtime_error("XDP protected/unrelated receive reinjection failed");
                }
                *static_cast<UINT64 *>(XskRingGetElement(&fill,fi+i))=d->Address.BaseAddress;
            }
            XskRingConsumerRelease(&rx,n);
            XskRingProducerSubmit(&fill,n);
        }
    } catch (const std::exception &error) {
        if (!context->closing.load()) context->fail(error.what());
    }
}
} // namespace

extern "C" void *cw_xdp_open(const CW_XDP_CONFIG *config, CW_XDP_RECEIVE receive,
                              CW_XDP_FAILURE failure, void *context, char *error, uint32_t error_size) {
    try {
        if (!config || !receive || !failure || !config->local_port) throw std::runtime_error("invalid XDP adapter configuration");
        auto result=std::make_unique<Context>(*config,receive,failure,context);
        result->start();
        return result.release();
    } catch (const std::exception &e) {
        if (error && error_size) snprintf(error,error_size,"%s",e.what());
        return nullptr;
    }
}
extern "C" uint32_t cw_xdp_send(void *device,const uint8_t *ipv4,uint32_t length) {
    try { return static_cast<Context *>(device)->send(ipv4,length); }
    catch (const std::exception &) { return ERROR_NETWORK_UNREACHABLE; }
}
extern "C" void cw_xdp_protect(void *device,uint32_t ip,uint16_t port) {
    static_cast<Context *>(device)->protected_peer.store(tuple(ip,port));
}
extern "C" uint32_t cw_xdp_interfaces(void *device) { return UINT32(static_cast<Context *>(device)->interfaces.size()); }
extern "C" uint32_t cw_xdp_queues(void *device) {
    UINT32 total=0; for (auto &a:static_cast<Context *>(device)->interfaces) total+=UINT32(a->receivers.size()); return total;
}
extern "C" uint32_t cw_xdp_probe(uint32_t index, uint32_t *queues, char *error, uint32_t error_size) {
    try {
        if (!index || !queues) throw std::runtime_error("invalid XDP interface index");
        Interface adapter;
        adapter.index = index;
        // Exercise the actual RX/TX queues without attaching a packet rule,
        // redirecting traffic, or sending a frame. All handles close on return.
        adapter.open_io();
        *queues = UINT32(adapter.receivers.size());
        return NO_ERROR;
    } catch (const std::exception &e) {
        if (error && error_size) snprintf(error,error_size,"%s",e.what());
        return ERROR_GEN_FAILURE;
    }
}
extern "C" void cw_xdp_close(void *device) { delete static_cast<Context *>(device); }
