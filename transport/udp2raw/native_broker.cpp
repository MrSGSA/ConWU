#include "common.h"
#include "log.h"
#include "native_broker.h"
#include <atomic>
#include <vector>

namespace {
HANDLE channel=INVALID_HANDLE_VALUE, halt=nullptr;
bool enabled=false;
// Overlapped I/O allows shutdown to cancel both a blocked receive and a write.
// A partial/cancelled frame poisons the channel; it must never be reused.
bool exact(void *buffer,unsigned count,bool write,DWORD timeout) {
    unsigned done=0;
    while(done<count) {
        OVERLAPPED op{}; op.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!op.hEvent) return false;
        DWORD transferred=0;
        BOOL ok=write ? WriteFile(channel,static_cast<char*>(buffer)+done,count-done,&transferred,&op)
                      : ReadFile(channel,static_cast<char*>(buffer)+done,count-done,&transferred,&op);
        if(!ok && GetLastError()==ERROR_IO_PENDING) {
            HANDLE events[]={op.hEvent,halt};
            DWORD wait=WaitForMultipleObjects(2,events,FALSE,timeout);
            if(wait==WAIT_OBJECT_0) ok=GetOverlappedResult(channel,&op,&transferred,FALSE);
            else { CancelIoEx(channel,&op); GetOverlappedResult(channel,&op,&transferred,TRUE); ok=FALSE; }
        }
        CloseHandle(op.hEvent);
        if(!ok || !transferred) { SetEvent(halt); CancelIoEx(channel,nullptr); return false; }
        done+=transferred;
    }
    return true;
}
[[noreturn]] void invalid(const char *reason) { mylog(log_fatal,"capture broker rejected: %s\n",reason); ExitProcess(74); }
}

void native_broker_configure(const std::string &control_name,const unsigned char *authorization,unsigned parent) {
    if(enabled || control_name.size()!=50) invalid("configuration");
    std::string name="\\\\.\\pipe\\StreamLink.Raw."+control_name.substr(18);
    halt=CreateEventW(nullptr,TRUE,FALSE,nullptr); if(!halt) invalid("stop event");
    channel=CreateFileA(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
    ULONG server=0;
    if(channel==INVALID_HANDLE_VALUE || !GetNamedPipeServerProcessId(channel,&server) || server!=parent) invalid("parent identity");
    unsigned char hello[96]; memcpy(hello,authorization,sizeof(hello));
    if(!exact(hello,sizeof(hello),true,5000) || !exact(hello,sizeof(hello),false,5000) || memcmp(hello,authorization,sizeof(hello))) invalid("attachment identity");
    enabled=true;
}
bool native_broker_mode() { return enabled; }
int native_broker_receive(char *packet,unsigned capacity) {
    unsigned char prefix[4]; if(!exact(prefix,4,false,INFINITE)) return -1;
    unsigned size=prefix[0]|(unsigned(prefix[1])<<8)|(unsigned(prefix[2])<<16)|(unsigned(prefix[3])<<24);
    if(size<40 || size>65535 || size>capacity) { SetEvent(halt); return -1; }
    return exact(packet,size,false,2000) ? int(size) : -1;
}
int native_broker_send(const char *packet,unsigned size) {
    if(size<40 || size>65535) return -1;
    std::vector<char> frame(size+4);
    for(unsigned i=0;i<4;++i) frame[i]=size>>(i*8);
    memcpy(frame.data()+4,packet,size);
    return exact(frame.data(),unsigned(frame.size()),true,1000) ? 0 : -1;
}
void native_broker_shutdown() { if(halt) SetEvent(halt); if(channel!=INVALID_HANDLE_VALUE) CancelIoEx(channel,nullptr); }
void native_broker_close() { if(channel!=INVALID_HANDLE_VALUE) { CloseHandle(channel); channel=INVALID_HANDLE_VALUE; } if(halt) { CloseHandle(halt); halt=nullptr; } }
