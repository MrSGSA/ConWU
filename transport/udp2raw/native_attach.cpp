#include "common.h"
#include "network.h"
#include "misc.h"
#include "native_attach.h"
#include "native_broker.h"
#include <tlhelp32.h>
#include <atomic>
#include <thread>
#include <mutex>

std::mutex native_injection_mutex;
namespace {
constexpr unsigned frame_size = 96;
unsigned char authorization[frame_size]{};
HANDLE pipe_handle = INVALID_HANDLE_VALUE;
std::string pipe_name;
std::atomic<bool> started{false};
std::atomic<bool> armed{false};
std::atomic<unsigned long long> start_tick{0};
address_t local, helper, peer;
unsigned last_request = 1;
unsigned short read16(const unsigned char *p) { return p[0] | (p[1] << 8); }
unsigned read32(const unsigned char *p) { return read16(p) | (unsigned(read16(p+2)) << 16); }
void write16(unsigned char *p, unsigned n) { p[0]=n; p[1]=n>>8; }
[[noreturn]] void reject(const char *reason) {
    // No payload, secrets or caller-supplied strings in control error logs.
    mylog(log_fatal, "managed attach rejected: %s\n", reason);
    ExitProcess(72);
}
bool read_frame(unsigned char *out, ULONGLONG deadline) {
    DWORD count = 0;
    while (count < frame_size && GetTickCount64() < deadline) {
        DWORD available = 0, received = 0;
        if (!PeekNamedPipe(pipe_handle, nullptr, 0, nullptr, &available, nullptr)) return false;
        if (!available) { Sleep(5); continue; }
        if (!ReadFile(pipe_handle, out+count, std::min<DWORD>(available, frame_size-count), &received, nullptr) || !received) return false;
        count += received;
    }
    return count == frame_size;
}
bool base_valid(const unsigned char *p) {
    return memcmp(p, "SLNA", 4)==0 && read16(p+4)==1 && read32(p+8)==frame_size;
}
void reply(unsigned type, const unsigned char *input) {
    unsigned char message[frame_size]; memcpy(message, input, frame_size); write16(message+6, type);
    DWORD sent = 0;
    if (!WriteFile(pipe_handle, message, frame_size, &sent, nullptr) || sent != frame_size) reject("IPC reply unavailable");
}
address_t endpoint(const unsigned char *ip, unsigned short port) {
    address_t result;
    result.inner.ipv4.sin_family = AF_INET;
    memcpy(&result.inner.ipv4.sin_addr.s_addr, ip, 4);
    result.inner.ipv4.sin_port = htons(port);
    if (!port || !result.inner.ipv4.sin_addr.s_addr || (ip[0] >= 224)) reject("invalid endpoint");
#ifndef UDP2RAW_TEST_IO
    if (ip[0] == 127) reject("managed production capture requires a non-loopback peer");
#endif
    return result;
}
DWORD parent_id() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) reject("parent lookup unavailable");
    PROCESSENTRY32 entry{}; entry.dwSize=sizeof(entry); DWORD parent=0;
    if (Process32First(snapshot, &entry)) do {
        if (entry.th32ProcessID == GetCurrentProcessId()) { parent=entry.th32ParentProcessID; break; }
    } while(Process32Next(snapshot, &entry));
    CloseHandle(snapshot); return parent;
}
void monitor() {
    unsigned char message[frame_size];
    while (true) {
        if (!read_frame(message, GetTickCount64()+10000)) break;
        if (!base_valid(message) || memcmp(message+16, authorization+16, frame_size-16)!=0 || read32(message+12) != last_request+1) break;
        last_request++;
        unsigned type = read16(message+6);
        if (type == 3 && !started.load()) { start_tick.store(GetTickCount64()); started.store(true); reply(7,message); }
        else if (type == 6) { reply(6,message); } // also keeps a Prepared owner alive
        else if (type == 4) {
            { std::lock_guard<std::mutex> lock(native_injection_mutex); started.store(false); }
            native_capture_shutdown();
            reply(5,message);
            ExitProcess(0);
        } else break;
    }
    { std::lock_guard<std::mutex> lock(native_injection_mutex); started.store(false); }
    native_capture_shutdown();
    // A broken/expired control session cannot leave the raw owner injecting.
    ExitProcess(73);
}
}

void native_attach_arguments(int &argc, char **argv) {
    for (int i=1; i<argc; ++i) if (strcmp(argv[i], "--managed-pipe")==0) {
        if (!pipe_name.empty() || i+1>=argc) reject("invalid IPC argument");
        pipe_name=argv[i+1];
        if (pipe_name.size()!=50 || pipe_name.substr(0,18)!="StreamLink.Attach.") reject("invalid IPC name");
        for (size_t c=18;c<pipe_name.size();++c) if (!isxdigit(static_cast<unsigned char>(pipe_name[c]))) reject("invalid IPC name");
        for (int j=i;j+2<argc;++j) argv[j]=argv[j+2];
        argc-=2; argv[argc]=nullptr; --i;
    }
}

void native_attach_configure() {
    if (pipe_name.empty()) return;
    const std::string path="\\\\.\\pipe\\"+pipe_name;
    pipe_handle=CreateFileA(path.c_str(), GENERIC_READ|GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION, nullptr);
    if (pipe_handle==INVALID_HANDLE_VALUE) reject("IPC unavailable");
    ULONG server=0;
    if (!GetNamedPipeServerProcessId(pipe_handle,&server) || !server || server!=parent_id()) reject("IPC server is not launcher");
    if (!read_frame(authorization, GetTickCount64()+8000) || !base_valid(authorization) || read16(authorization+6)!=1 || read32(authorization+12)!=1) reject("invalid Attach frame");
    unsigned char zero[16]{};
    for (int offset: {16,32,48}) if (memcmp(authorization+offset,zero,16)==0) reject("empty identity");
    if (raw_mode!=mode_faketcp || raw_ip_version!=AF_INET || (authorization[83]!=1 && authorization[83]!=2) || read32(authorization+84)!=10000 || read32(authorization+88)!=1 || read32(authorization+92)>1) reject("unsupported profile or descriptor");
    local=endpoint(authorization+64,read16(authorization+68));
    helper=endpoint(authorization+70,read16(authorization+74));
    peer=endpoint(authorization+76,read16(authorization+80));
    if (helper==peer || local==peer || authorization[82]!=(program_mode==client_mode?1:2)) reject("tuple or role conflict");
    if (program_mode==client_mode) {
        if (!(remote_addr==peer)) reject("configured peer differs from authorization");
        source_addr=local; force_source_ip=1; source_port=local.get_port(); force_source_port=1;
    } else if (!(local_addr==local)) reject("configured listener differs from authorization");
    if(read32(authorization+92)==1) native_broker_configure(pipe_name,authorization,server);
    mylog(log_info,"managed endpoint authorized; ABI=1, %s, source=%s\n",native_broker_mode()?"brokered worker":"single peer",local.get_str());
}
bool native_attached() { return pipe_handle!=INVALID_HANDLE_VALUE; }
bool native_attachment_so() { return native_attached() && authorization[83]==2; }
unsigned long long native_attachment_start_tick() { return start_tick.load(); }
void native_attachment_endpoints(address_t &source, address_t &destination) { source=local; destination=peer; }
bool native_attachment_started() { return !native_attached() || started.load(); }
std::string native_attachment_filter() {
    std::string inbound="inbound and ip.DstAddr == "+std::string(local.get_ip())+" and tcp.DstPort == "+std::to_string(local.get_port())+
        " and ip.SrcAddr == "+std::string(peer.get_ip())+" and tcp.SrcPort == "+std::to_string(peer.get_port());
    std::string outbound="outbound and ip.SrcAddr == "+std::string(local.get_ip())+" and tcp.SrcPort == "+std::to_string(local.get_port())+
        " and ip.DstAddr == "+std::string(peer.get_ip())+" and tcp.DstPort == "+std::to_string(peer.get_port());
    // The authorized peer differs from helper. Both directions of helper are
    // excluded by exact tuple construction. Injected packets bypass this handle.
    return "!loopback and ip and tcp and (("+inbound+") or ("+outbound+"))";
}
void native_attachment_armed() {
    if (!native_attached() || armed.exchange(true)) return;
    reply(2,authorization);
    // Parent must validate Armed then send Start; even server replies are gated.
    std::thread(monitor).detach();
    // Resource preparation precedes the separate 8-second SO attempt. Bounded
    // wait permits peer Ready coordination; heartbeats cannot extend it forever.
    ULONGLONG deadline=GetTickCount64()+30000;
    while (!started.load()) { if (GetTickCount64()>=deadline) reject("Start timeout"); Sleep(2); }
}
bool native_attachment_packet(const char *bytes,int length) {
    if (!native_attached()) return true;
    if (!started.load() || length<40) return false;
    auto p=reinterpret_cast<const unsigned char*>(bytes);
    unsigned ihl=(p[0]&15)*4;
    if (p[0]>>4!=4 || p[9]!=6 || ihl<20 || length<int(ihl+20) || (p[6]&0x3f) || p[7]) return false;
    return memcmp(p+12,&local.inner.ipv4.sin_addr.s_addr,4)==0 && memcmp(p+16,&peer.inner.ipv4.sin_addr.s_addr,4)==0 &&
        ((p[ihl]<<8)|p[ihl+1])==local.get_port() && ((p[ihl+2]<<8)|p[ihl+3])==peer.get_port();
}
