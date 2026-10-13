#include "common.h"
#include "native_legacy_egress.h"
#include <atomic>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

// No native business queue. One pending pipe write plus at most 64 receipts;
// payloads are queued only by the parent's bounded whole-device egress owner.
namespace {
struct sender {
    HANDLE pipe=INVALID_HANDLE_VALUE,halt=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    OVERLAPPED write{};
    std::mutex gate;
    std::vector<unsigned char> frame;
    std::map<unsigned long long,unsigned> outstanding;
    bool pending=false,armed=false;
    unsigned long long sequence=0,epoch=0;
    std::atomic<bool> failed{false};
    std::atomic<unsigned long long> counts[8]{}; // offered, busy/rejected, submitted, injected, bytes, refused, fault, pending peak
};
sender *owner=nullptr;
void put(unsigned char *p,unsigned long long v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=static_cast<unsigned char>(v>>(8*i));}
unsigned long long get(const unsigned char *p,unsigned n){unsigned long long v=0;for(unsigned i=0;i<n;i++)v|=static_cast<unsigned long long>(p[i])<<(8*i);return v;}
void fault(sender &s){s.failed=true;s.counts[6]++;SetEvent(s.halt);CancelIoEx(s.pipe,nullptr);}
bool exact(sender &s,void *buffer,unsigned length,bool writing,DWORD timeout){
    unsigned done=0;
    while(done<length){
        OVERLAPPED op{};op.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!op.hEvent)return false;
        DWORD n=0;BOOL ok=writing?WriteFile(s.pipe,static_cast<char*>(buffer)+done,length-done,&n,&op):ReadFile(s.pipe,static_cast<char*>(buffer)+done,length-done,&n,&op);
        if(!ok&&GetLastError()==ERROR_IO_PENDING){HANDLE handles[]={op.hEvent,s.halt};
            if(WaitForMultipleObjects(2,handles,FALSE,timeout)==WAIT_OBJECT_0)ok=GetOverlappedResult(s.pipe,&op,&n,FALSE);
            else{CancelIoEx(s.pipe,&op);GetOverlappedResult(s.pipe,&op,&n,TRUE);ok=FALSE;}}
        CloseHandle(op.hEvent);if(!ok||n==0)return false;done+=n;
    }return true;
}
void receipts(sender &s){
    unsigned char ack[16];
    while(exact(s,ack,16,false,INFINITE)){
        std::lock_guard<std::mutex> lock(s.gate);auto sequence=get(ack,8);auto found=s.outstanding.find(sequence);
        if(found==s.outstanding.end()||ack[8]>1||ack[9]||ack[10]||ack[11]||get(ack+12,4)!=found->second){fault(s);return;}
        if(found->second>0){if(ack[8]==0){s.counts[3]++;s.counts[4]+=found->second;}else s.counts[5]++;}
        s.outstanding.erase(found);
    }fault(s);
}
int hex(char c){if(c>='0'&&c<='9')return c-'0';if(c>='A'&&c<='F')return c-'A'+10;if(c>='a'&&c<='f')return c-'a'+10;return -1;}
}
bool native_legacy_egress_init(){
    if(owner)return !owner->failed;
    const char *name=getenv("STREAMLINK_LEGACY_EGRESS"),*auth=getenv("STREAMLINK_LEGACY_AUTH"),*parent=getenv("STREAMLINK_LEGACY_PARENT");
    if(!name)return true;
    if(strlen(name)!=50||strncmp(name,"StreamLink.Egress.",18)||strspn(name+18,"0123456789abcdef")!=32||!auth||strlen(auth)!=128||!parent||strlen(parent)>10)return false;
    char *end=nullptr;unsigned long pid=strtoul(parent,&end,10);if(!pid||!end||*end)return false;
    auto *s=new sender;unsigned char hello[64];
    for(unsigned i=0;i<64;i++){int a=hex(auth[2*i]),b=hex(auth[2*i+1]);if(a<0||b<0)return false;hello[i]=(a<<4)|b;}
    std::string path="\\\\.\\pipe\\"+std::string(name);
    s->write.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!s->halt||!s->write.hEvent)return false;
    s->pipe=CreateFileA(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
    ULONG actual=0;unsigned char reply[64];
    if(s->pipe==INVALID_HANDLE_VALUE||!GetNamedPipeServerProcessId(s->pipe,&actual)||actual!=pid||!exact(*s,hello,64,true,5000)||!exact(*s,reply,64,false,5000)||memcmp(hello,reply,64))return false;
    SecureZeroMemory(hello,64);owner=s;std::thread([s]{receipts(*s);}).detach();return true;
}
bool native_legacy_egress_enabled(){return owner!=nullptr;}
bool native_legacy_egress_send(const char *packet,int length,unsigned peer){
    auto &s=*owner;s.counts[0]++;
    std::lock_guard<std::mutex> lock(s.gate);
    if(s.pending){DWORD n=0;
        if(!GetOverlappedResult(s.pipe,&s.write,&n,FALSE)){
            if(GetLastError()==ERROR_IO_INCOMPLETE){s.counts[1]++;return false;}fault(s);return false;}
        if(n!=s.frame.size()){fault(s);return false;}s.pending=false;
    }
    if(s.failed||!s.armed||length<40||length>6144||peer<1||peer>8||s.outstanding.size()>=64){s.counts[1]++;return false;}
    auto sequence=++s.sequence;s.frame.assign(24+length,0);put(s.frame.data(),length,4);put(s.frame.data()+4,sequence,8);put(s.frame.data()+12,s.epoch,8);s.frame[20]=static_cast<unsigned char>(peer);memcpy(s.frame.data()+24,packet,length);
    ResetEvent(s.write.hEvent);DWORD n=0;BOOL ok=WriteFile(s.pipe,s.frame.data(),static_cast<DWORD>(s.frame.size()),&n,&s.write);
    if(!ok&&GetLastError()!=ERROR_IO_PENDING){fault(s);return false;}
    if(ok&&n!=s.frame.size()){fault(s);return false;}
    s.pending=!ok;s.outstanding.emplace(sequence,length);s.counts[2]++;
    auto peak=s.counts[7].load();if(s.outstanding.size()>peak)s.counts[7]=s.outstanding.size();
    return true;
}
void native_legacy_egress_pause(){
    if(!owner)return;auto &s=*owner;unsigned long long fence=0;
    {
        std::lock_guard<std::mutex> lock(s.gate);s.armed=false;if(s.failed)return;
        if(s.pending){DWORD n=0;
            if(WaitForSingleObject(s.write.hEvent,1000)!=WAIT_OBJECT_0||!GetOverlappedResult(s.pipe,&s.write,&n,FALSE)||n!=s.frame.size()){fault(s);ExitProcess(74);}
            s.pending=false;
        }
        unsigned char frame[24]{};fence=++s.sequence;put(frame+4,fence,8);put(frame+12,++s.epoch,8);
        s.outstanding.emplace(fence,0);
        if(!exact(s,frame,24,true,1000)){fault(s);ExitProcess(74);}
    }
    // Parent cancels queued old-generation business and joins any injection
    // before acknowledging. Capture cannot be closed while a late send survives.
    auto until=GetTickCount64()+3000;
    while(GetTickCount64()<until){
        {std::lock_guard<std::mutex> lock(s.gate);if(!s.outstanding.count(fence))return;if(s.failed)ExitProcess(74);}
        Sleep(1);
    }fault(s);ExitProcess(74);
}
void native_legacy_egress_arm(){if(owner){std::lock_guard<std::mutex> lock(owner->gate);owner->armed=true;}}
bool native_legacy_egress_failed(){return owner&&owner->failed;}
void native_legacy_egress_stats(unsigned long long counts[8]){if(owner){std::lock_guard<std::mutex> lock(owner->gate);for(unsigned i=0;i<8;i++)counts[i]=owner->counts[i].load();}else for(unsigned i=0;i<8;i++)counts[i]=0;}
