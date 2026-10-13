#define SLT_BUILD_DLL
#include <winsock2.h>
#include "user_api.h"
#include <netioapi.h>
#include <atomic>
#include <map>
#include <memory>
#include <mutex>

namespace {
struct session {
    HANDLE device=INVALID_HANDLE_VALUE,stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    std::mutex readGate;
    std::mutex configGate;
    MIB_UNICASTIPADDRESS_ROW address{};bool addressOwned=false;
    SLT_INFO info{};
    ~session(){if(addressOwned)DeleteUnicastIpAddressEntry(&address);if(device!=INVALID_HANDLE_VALUE)CloseHandle(device);if(stop)CloseHandle(stop);}
    void cancel(){SetEvent(stop);CancelIoEx(device,nullptr);}
};
std::mutex registryGate;
std::map<SLT_HANDLE,std::shared_ptr<session>> registry;
SLT_HANDLE next=0;
std::shared_ptr<session> get(SLT_HANDLE id){std::lock_guard<std::mutex> lock(registryGate);auto found=registry.find(id);if(found==registry.end()){SetLastError(ERROR_INVALID_HANDLE);return {};}return found->second;}
bool io(session &s,void *data,unsigned length,unsigned *done,bool writing,DWORD code=0){
    if(WaitForSingleObject(s.stop,0)==WAIT_OBJECT_0){SetLastError(ERROR_OPERATION_ABORTED);return false;}
    OVERLAPPED op{};op.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!op.hEvent)return false;
    DWORD count=0;BOOL ok=code?DeviceIoControl(s.device,code,nullptr,0,data,length,&count,&op):writing?WriteFile(s.device,data,length,&count,&op):ReadFile(s.device,data,length,&count,&op);
    if(!ok&&GetLastError()==ERROR_IO_PENDING){HANDLE events[]={op.hEvent,s.stop};
        auto wait=WaitForMultipleObjects(2,events,FALSE,INFINITE);
        if(wait==WAIT_OBJECT_0)ok=GetOverlappedResult(s.device,&op,&count,FALSE);
        else{CancelIoEx(s.device,&op);GetOverlappedResult(s.device,&op,&count,TRUE);ok=FALSE;SetLastError(ERROR_OPERATION_ABORTED);}
    }
    DWORD error=ok?ERROR_SUCCESS:GetLastError();CloseHandle(op.hEvent);if(done)*done=count;SetLastError(error);return ok!=FALSE;
}
}
unsigned __cdecl SLT_UserAbi(){return SLT_ABI;}
SLT_HANDLE __cdecl SLT_Open(unsigned index){
    if(!index){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    wchar_t path[80];swprintf_s(path,L"\\\\.\\StreamLinkTun-%u",index);
    auto s=std::make_shared<session>();if(!s->stop)return 0;
    s->device=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);if(s->device==INVALID_HANDLE_VALUE)return 0;
    unsigned got=0;if(!io(*s,&s->info,sizeof(s->info),&got,false,SLT_IOCTL_INFO)||got!=sizeof(s->info)||s->info.Size!=sizeof(SLT_INFO)||s->info.Abi!=SLT_ABI||s->info.Mtu!=SLT_MTU||s->info.QueuePackets!=SLT_QUEUE_PACKETS||s->info.IfIndex!=index||s->info.Luid==0){s->cancel();SetLastError(ERROR_REVISION_MISMATCH);return 0;}
    std::lock_guard<std::mutex> lock(registryGate);if(registry.size()>=8||next==~SLT_HANDLE(0)){SetLastError(ERROR_TOO_MANY_OPEN_FILES);return 0;}
    auto id=++next;registry.emplace(id,std::move(s));return id;
}
BOOL __cdecl SLT_Info(SLT_HANDLE id,SLT_INFO *info){auto s=get(id);if(!s||!info){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}*info=s->info;return TRUE;}
BOOL __cdecl SLT_Stats(SLT_HANDLE id,SLT_STATS *stats){auto s=get(id);if(!s||!stats){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}unsigned got=0;return io(*s,stats,sizeof(*stats),&got,false,SLT_IOCTL_STATS)&&got==sizeof(*stats)&&stats->Size==sizeof(*stats)&&stats->Abi==SLT_ABI;}
BOOL __cdecl SLT_ConfigureIpv4(SLT_HANDLE id,const unsigned char *address){
    auto s=get(id);if(!s||!address||address[0]==0||address[0]==127||address[0]>=224){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    std::lock_guard<std::mutex> lock(s->configGate);if(s->addressOwned||WaitForSingleObject(s->stop,0)==WAIT_OBJECT_0){SetLastError(ERROR_INVALID_STATE);return FALSE;}
    InitializeUnicastIpAddressEntry(&s->address);s->address.InterfaceLuid.Value=s->info.Luid;s->address.Address.Ipv4.sin_family=AF_INET;memcpy(&s->address.Address.Ipv4.sin_addr,address,4);s->address.OnLinkPrefixLength=24;s->address.DadState=IpDadStatePreferred;
    DWORD error=CreateUnicastIpAddressEntry(&s->address);if(error!=NO_ERROR){SetLastError(error);return FALSE;}s->addressOwned=true;return TRUE;
}
int __cdecl SLT_Read(SLT_HANDLE id,void *data,unsigned capacity){auto s=get(id);if(!s)return -1;if(!data||capacity<SLT_MTU){SetLastError(ERROR_INVALID_PARAMETER);return -1;}
    std::lock_guard<std::mutex> lock(s->readGate);unsigned got=0;if(!io(*s,data,SLT_MTU,&got,false))return -1;if(got<20||got>SLT_MTU){SetLastError(ERROR_INVALID_DATA);return -1;}return static_cast<int>(got);
}
BOOL __cdecl SLT_Write(SLT_HANDLE id,const void *data,unsigned length){auto s=get(id);if(!s)return FALSE;if(!data||length<20||length>SLT_MTU){SetLastError(ERROR_INVALID_PARAMETER);return FALSE;}
    unsigned sent=0;return io(*s,const_cast<void*>(data),length,&sent,true)&&sent==length;
}
BOOL __cdecl SLT_Stop(SLT_HANDLE id){auto s=get(id);if(!s)return FALSE;s->cancel();return TRUE;}
BOOL __cdecl SLT_Close(SLT_HANDLE id){
    std::shared_ptr<session> s;{std::lock_guard<std::mutex> lock(registryGate);auto found=registry.find(id);if(found==registry.end()){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}s=found->second;registry.erase(found);}s->cancel();return TRUE;
}
static_assert(sizeof(SLT_INFO)==32&&sizeof(SLT_STATS)==80,"Driver ABI layout changed");
