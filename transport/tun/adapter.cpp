// StreamLink's user-mode adapter bridge. Wintun's signed driver is unmodified.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>
#include <cstring>
#include <atomic>
#include "wintun.h"

using CloseTrace = void (__cdecl *)(unsigned);
struct Adapter {
    CloseTrace trace = nullptr;
    HMODULE library = nullptr;
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    HANDLE event = nullptr;
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    NET_LUID luid{};
    std::atomic<unsigned long long> counts[7]{};
    WINTUN_CLOSE_ADAPTER_FUNC *close = nullptr;
    WINTUN_END_SESSION_FUNC *end = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC *receive = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate = nullptr;
    WINTUN_SEND_PACKET_FUNC *send = nullptr;
    // Diagnostic callbacks are synchronous and installed only for traced close.
    // The normal production close order and ownership are unchanged.
    void note(unsigned phase) { if (trace) trace(phase); }
    ~Adapter() {
        note(1); if (stop) CloseHandle(stop); note(2);
        note(3); if (session && end) end(session); note(4);
        note(5); if (adapter && close) close(adapter); note(6);
        note(7); if (library) FreeLibrary(library); note(8);
    }
};
#define API extern "C" __declspec(dllexport)
API void sltun_close(Adapter *a) { delete a; }
// Additive ABI-2 diagnostic export; old callers still use sltun_close.
API void sltun_close_with_trace(Adapter *a, CloseTrace trace) { if (a) a->trace = trace; delete a; }
API DWORD sltun_abi() { return 2; }
API void sltun_stop(Adapter *a) { if(a&&a->stop)SetEvent(a->stop); }
API DWORD sltun_stats(Adapter *a, unsigned long long *counts) {if(!a||!counts)return ERROR_INVALID_PARAMETER;for(unsigned i=0;i<7;i++)counts[i]=a->counts[i].load();return ERROR_SUCCESS;}
// Additive ABI-2 read-only identity export. No ownership or close behavior changes.
API DWORD sltun_luid(Adapter *a, unsigned long long *value) {if(!a||!value)return ERROR_INVALID_PARAMETER;*value=a->luid.Value;return ERROR_SUCCESS;}

static DWORD open_adapter(const wchar_t *dll, const wchar_t *name, const GUID *guid, const BYTE *ip, Adapter **result, CloseTrace trace) {
    if (!result) return ERROR_INVALID_PARAMETER;
    *result = nullptr;
    if (!dll || !name || !guid || !ip) return ERROR_INVALID_PARAMETER;
    Adapter *a = new Adapter();
    a->trace = trace;
    auto fail = [a](DWORD error) { delete a; return error ? error : ERROR_GEN_FAILURE; };
    if(!a->stop)return fail(GetLastError());
    a->note(101);
    a->library = LoadLibraryExW(dll, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!a->library) return fail(GetLastError());
    a->note(102);
#define LOAD(field, type, symbol) a->field = reinterpret_cast<type *>(GetProcAddress(a->library, symbol)); if (!a->field) return fail(ERROR_PROC_NOT_FOUND)
    LOAD(close, WINTUN_CLOSE_ADAPTER_FUNC, "WintunCloseAdapter");
    LOAD(end, WINTUN_END_SESSION_FUNC, "WintunEndSession");
    LOAD(receive, WINTUN_RECEIVE_PACKET_FUNC, "WintunReceivePacket");
    LOAD(release, WINTUN_RELEASE_RECEIVE_PACKET_FUNC, "WintunReleaseReceivePacket");
    LOAD(allocate, WINTUN_ALLOCATE_SEND_PACKET_FUNC, "WintunAllocateSendPacket");
    LOAD(send, WINTUN_SEND_PACKET_FUNC, "WintunSendPacket");
#undef LOAD
    auto create = reinterpret_cast<WINTUN_CREATE_ADAPTER_FUNC *>(GetProcAddress(a->library, "WintunCreateAdapter"));
    auto luid = reinterpret_cast<WINTUN_GET_ADAPTER_LUID_FUNC *>(GetProcAddress(a->library, "WintunGetAdapterLUID"));
    auto start = reinterpret_cast<WINTUN_START_SESSION_FUNC *>(GetProcAddress(a->library, "WintunStartSession"));
    auto event = reinterpret_cast<WINTUN_GET_READ_WAIT_EVENT_FUNC *>(GetProcAddress(a->library, "WintunGetReadWaitEvent"));
    if (!create || !luid || !start || !event) return fail(ERROR_PROC_NOT_FOUND);
    // Never open or take ownership of an existing adapter, even with our name.
    a->note(103); a->adapter = create(name, L"StreamLink", guid); if (!a->adapter) return fail(GetLastError()); a->note(104);
    NET_LUID id{}; luid(a->adapter, &id);a->luid=id;
    MIB_IPINTERFACE_ROW interfaceRow{}; InitializeIpInterfaceEntry(&interfaceRow);
    interfaceRow.Family = AF_INET; interfaceRow.InterfaceLuid = id;
    a->note(105); DWORD error = GetIpInterfaceEntry(&interfaceRow); if (error) return fail(error); a->note(106);
    interfaceRow.NlMtu = 1280; interfaceRow.SitePrefixLength = 0;
    interfaceRow.ForwardingEnabled = FALSE; interfaceRow.WeakHostSend = FALSE; interfaceRow.WeakHostReceive = FALSE;
    interfaceRow.RouterDiscoveryBehavior = RouterDiscoveryDisabled; interfaceRow.DadTransmits = 0;
    a->note(107); error = SetIpInterfaceEntry(&interfaceRow); if (error) return fail(error); a->note(108);
    MIB_UNICASTIPADDRESS_ROW address{}; InitializeUnicastIpAddressEntry(&address);
    address.InterfaceLuid = id; address.Address.Ipv4.sin_family = AF_INET;
    std::memcpy(&address.Address.Ipv4.sin_addr, ip, 4);
    address.OnLinkPrefixLength = 24; address.DadState = IpDadStatePreferred;
    a->note(109); error = CreateUnicastIpAddressEntry(&address); if (error) return fail(error); a->note(110);
    a->note(111); a->session = start(a->adapter, 0x400000); if (!a->session) return fail(GetLastError()); a->note(112);
    a->note(113); a->event = event(a->session); if (!a->event) return fail(GetLastError()); a->note(114);
    a->note(115); a->trace = nullptr; // The synchronous open never retains a managed callback.
    *result = a; return ERROR_SUCCESS;
}
API DWORD sltun_open(const wchar_t *dll, const wchar_t *name, const GUID *guid, const BYTE *ip, Adapter **result) {
    return open_adapter(dll, name, guid, ip, result, nullptr);
}
// Additive ABI-2 diagnostic export. No retry, wait or ownership change.
API DWORD sltun_open_with_trace(const wchar_t *dll, const wchar_t *name, const GUID *guid, const BYTE *ip, Adapter **result, CloseTrace trace) {
    return open_adapter(dll, name, guid, ip, result, trace);
}

API DWORD sltun_read(Adapter *a, BYTE *buffer, DWORD capacity, DWORD *length) {
    if(!a||!buffer||!length)return ERROR_INVALID_PARAMETER;
    *length = 0;
    if(WaitForSingleObject(a->stop,0)==WAIT_OBJECT_0)return ERROR_OPERATION_ABORTED;
    DWORD size = 0; BYTE *packet = a->receive(a->session, &size);
    if (!packet) {
        DWORD error = GetLastError(); if (error != ERROR_NO_MORE_ITEMS) return error;
        HANDLE events[]={a->stop,a->event};a->counts[6]++;
        DWORD waited = WaitForMultipleObjects(2,events,FALSE,100);
        if (waited == WAIT_FAILED) return GetLastError();
        if(waited==WAIT_OBJECT_0)return ERROR_OPERATION_ABORTED;
        return ERROR_NO_MORE_ITEMS;
    }
    if (size <= capacity) { std::memcpy(buffer, packet, size); *length = size;a->counts[0]++;a->counts[1]+=size; }
    else a->counts[5]++;
    a->release(a->session, packet);
    return size <= capacity ? ERROR_SUCCESS : ERROR_INSUFFICIENT_BUFFER;
}
API DWORD sltun_write(Adapter *a, const BYTE *buffer, DWORD length) {
    if(!a||!buffer)return ERROR_INVALID_PARAMETER;
    if(WaitForSingleObject(a->stop,0)==WAIT_OBJECT_0)return ERROR_OPERATION_ABORTED;
    if (length < 20 || length > 1280) return ERROR_INVALID_DATA;
    BYTE *packet = a->allocate(a->session, length); if (!packet) {DWORD error=GetLastError();if(error==ERROR_BUFFER_OVERFLOW)a->counts[4]++;return error;}
    std::memcpy(packet, buffer, length); a->send(a->session, packet);a->counts[2]++;a->counts[3]+=length;return ERROR_SUCCESS;
}
