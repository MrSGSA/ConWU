// StreamLink's user-mode adapter bridge. Wintun's signed driver is unmodified.
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>
#include <cstring>
#include "wintun.h"

struct Adapter {
    HMODULE library = nullptr;
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    HANDLE event = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC *close = nullptr;
    WINTUN_END_SESSION_FUNC *end = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC *receive = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC *release = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC *allocate = nullptr;
    WINTUN_SEND_PACKET_FUNC *send = nullptr;
    ~Adapter() { if (session && end) end(session); if (adapter && close) close(adapter); if (library) FreeLibrary(library); }
};
#define API extern "C" __declspec(dllexport)
API void sltun_close(Adapter *a) { delete a; }

API DWORD sltun_open(const wchar_t *dll, const wchar_t *name, const GUID *guid, const BYTE *ip, Adapter **result) {
    *result = nullptr;
    Adapter *a = new Adapter();
    auto fail = [a](DWORD error) { delete a; return error ? error : ERROR_GEN_FAILURE; };
    a->library = LoadLibraryExW(dll, nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!a->library) return fail(GetLastError());
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
    a->adapter = create(name, L"StreamLink", guid); if (!a->adapter) return fail(GetLastError());
    NET_LUID id{}; luid(a->adapter, &id);
    MIB_IPINTERFACE_ROW interfaceRow{}; InitializeIpInterfaceEntry(&interfaceRow);
    interfaceRow.Family = AF_INET; interfaceRow.InterfaceLuid = id;
    DWORD error = GetIpInterfaceEntry(&interfaceRow); if (error) return fail(error);
    interfaceRow.NlMtu = 1280; interfaceRow.SitePrefixLength = 0;
    interfaceRow.ForwardingEnabled = FALSE; interfaceRow.WeakHostSend = FALSE; interfaceRow.WeakHostReceive = FALSE;
    interfaceRow.RouterDiscoveryBehavior = RouterDiscoveryDisabled; interfaceRow.DadTransmits = 0;
    error = SetIpInterfaceEntry(&interfaceRow); if (error) return fail(error);
    MIB_UNICASTIPADDRESS_ROW address{}; InitializeUnicastIpAddressEntry(&address);
    address.InterfaceLuid = id; address.Address.Ipv4.sin_family = AF_INET;
    std::memcpy(&address.Address.Ipv4.sin_addr, ip, 4);
    address.OnLinkPrefixLength = 24; address.DadState = IpDadStatePreferred;
    error = CreateUnicastIpAddressEntry(&address); if (error) return fail(error);
    a->session = start(a->adapter, 0x400000); if (!a->session) return fail(GetLastError());
    a->event = event(a->session); if (!a->event) return fail(GetLastError());
    *result = a; return ERROR_SUCCESS;
}

API DWORD sltun_read(Adapter *a, BYTE *buffer, DWORD capacity, DWORD *length) {
    *length = 0;
    DWORD size = 0; BYTE *packet = a->receive(a->session, &size);
    if (!packet) {
        DWORD error = GetLastError(); if (error != ERROR_NO_MORE_ITEMS) return error;
        DWORD waited = WaitForSingleObject(a->event, 100);
        if (waited == WAIT_FAILED) return GetLastError();
        return ERROR_NO_MORE_ITEMS;
    }
    if (size <= capacity) { std::memcpy(buffer, packet, size); *length = size; }
    a->release(a->session, packet);
    return size <= capacity ? ERROR_SUCCESS : ERROR_INSUFFICIENT_BUFFER;
}
API DWORD sltun_write(Adapter *a, const BYTE *buffer, DWORD length) {
    if (length < 20 || length > 1280) return ERROR_INVALID_DATA;
    BYTE *packet = a->allocate(a->session, length); if (!packet) return GetLastError();
    std::memcpy(packet, buffer, length); a->send(a->session, packet); return ERROR_SUCCESS;
}
