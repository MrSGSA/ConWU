#include "common.h"
#include "native_legacy_control.h"
#include "log.h"
#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>
#include <map>

namespace {
struct item { std::vector<char> packet; native_wire_kind kind; bool secure; unsigned long long epoch, at; };
struct controller {
    std::mutex gate;
    std::deque<item> queue;
    HANDLE wake=CreateEventW(nullptr,FALSE,FALSE,nullptr), ready=CreateEventW(nullptr,TRUE,FALSE,nullptr), halt=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    HANDLE pipe=INVALID_HANDLE_VALUE;
    std::atomic<bool> failed{false};
    bool armed=false;
    unsigned long long epoch=0, sequence=0;
    std::atomic<unsigned long long> stats[6]{}; // queued, full/closed, parent denied, expired, stale capture, IPC fault
    legacy_inject inject;
    std::string name; unsigned parent; unsigned char authorization[64]{};
    std::map<std::string,std::chrono::steady_clock::time_point> http_until; // worker-only, bounded; preserves legacy GET -> bare gap
};
controller *control=nullptr; // bounded process lifetime, parent JobObject owns exit
bool exact(controller &c,void *bytes,unsigned count,bool write,DWORD timeout=1000) {
    unsigned done=0;
    while(done<count) {
        OVERLAPPED op{}; op.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr); if(!op.hEvent)return false;
        DWORD transferred=0;
        BOOL ok=write?WriteFile(c.pipe,static_cast<char*>(bytes)+done,count-done,&transferred,&op)
                     :ReadFile(c.pipe,static_cast<char*>(bytes)+done,count-done,&transferred,&op);
        if(!ok&&GetLastError()==ERROR_IO_PENDING) {
            HANDLE events[]={op.hEvent,c.halt}; auto result=WaitForMultipleObjects(2,events,FALSE,timeout);
            if(result==WAIT_OBJECT_0)ok=GetOverlappedResult(c.pipe,&op,&transferred,FALSE);
            else {CancelIoEx(c.pipe,&op);GetOverlappedResult(c.pipe,&op,&transferred,TRUE);ok=FALSE;}
        }
        CloseHandle(op.hEvent); if(!ok||!transferred)return false;done+=transferred;
    }
    return true;
}
void word(unsigned char *p,unsigned long long value,unsigned size) { for(unsigned i=0;i<size;i++)p[i]=static_cast<unsigned char>(value>>(i*8)); }
bool metadata(const item &i,unsigned long long sequence,unsigned char frame[56]) {
    const auto *p=reinterpret_cast<const unsigned char*>(i.packet.data()); auto size=i.packet.size();
    if(size<28||(p[0]>>4)!=4)return false;
    unsigned ip=(p[0]&15)*4;if(ip<20||ip+8>size||(p[9]!=6&&p[9]!=17))return false;
    if(p[9]==6&&ip+20>size)return false;
    unsigned headers=ip+(p[9]==6?(p[ip+12]>>4)*4:8);
    if((p[9]==6&&headers<ip+20)||headers>size)return false;
    memset(frame,0,56);word(frame,sequence,8);word(frame+8,i.epoch,8);
    frame[16]=static_cast<unsigned char>(i.kind);frame[17]=p[9];frame[18]=p[9]==6?p[ip+13]:0;frame[19]=i.secure?1:0;
    word(frame+20,size,4);memcpy(frame+24,p+12,8);memcpy(frame+32,p+ip,4);
    if(p[9]==6)memcpy(frame+36,p+ip+4,8);
    word(frame+44,headers,2);word(frame+48,i.at,8);return true;
}
void fault(controller &c) { c.failed=true;c.stats[5]++;SetEvent(c.halt);SetEvent(c.ready); }
void run(controller &c) {
    std::string path="\\\\.\\pipe\\"+c.name;
    c.pipe=CreateFileA(path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr);
    ULONG parent=0;unsigned char hello[64];memcpy(hello,c.authorization,64);
    if(c.pipe==INVALID_HANDLE_VALUE||!GetNamedPipeServerProcessId(c.pipe,&parent)||parent!=c.parent||
        !exact(c,hello,64,true,5000)||!exact(c,hello,64,false,5000)||memcmp(hello,c.authorization,64)) {fault(c);return;}
    SetEvent(c.ready);
    while(WaitForSingleObject(c.wake,INFINITE)==WAIT_OBJECT_0&&!c.failed) {
        while(true) {
            item next;
            {std::lock_guard<std::mutex> lock(c.gate);if(c.queue.empty())break;next=std::move(c.queue.front());c.queue.pop_front();}
            if(GetTickCount64()-next.at>250){c.stats[3]++;continue;}
            unsigned char frame[56],reply[16];auto sequence=++c.sequence;
            if(!metadata(next,sequence,frame)){fault(c);return;}
            std::string tuple(reinterpret_cast<char*>(frame+24),12);tuple.append(reinterpret_cast<char*>(frame+8),8);
            auto http=c.http_until.find(tuple);
            // GetTickCount64 is quantized on Windows: subtracting two ticks
            // can shorten a 32ms interval by one system tick. Preserve the
            // existing HTTP gap using a monotonic high-resolution deadline.
            if(http!=c.http_until.end())
                while(std::chrono::steady_clock::now()<http->second)std::this_thread::sleep_until(http->second);
            if(GetTickCount64()-next.at>250){c.stats[3]++;continue;}
            if(!exact(c,frame,56,true)||!exact(c,reply,16,false)){fault(c);return;}
            unsigned char expected[16]{};word(expected,sequence,8);expected[8]=reply[8];
            if(reply[8]>3||memcmp(reply,expected,16)){fault(c);return;}
            if(reply[8]!=0){c.stats[2]++;continue;}
            std::lock_guard<std::mutex> lock(c.gate);
            if(!c.armed||c.epoch!=next.epoch){c.stats[4]++;continue;}
            if(GetTickCount64()-next.at>250){c.stats[3]++;continue;}
            auto injection_at=std::chrono::steady_clock::now();
            bool sent=c.inject(next.packet.data(),static_cast<int>(next.packet.size()),next.kind);
            if(sent&&http!=c.http_until.end()) {
                auto us=std::chrono::duration_cast<std::chrono::microseconds>(injection_at-(http->second-std::chrono::milliseconds(32))).count();
                mylog(log_debug,"[legacy-http-spacing] elapsed_us=%llu\n",static_cast<unsigned long long>(us));
            }
            unsigned headers=frame[44]|(unsigned(frame[45])<<8);
            if(sent&&frame[17]==6&&next.packet.size()>=headers+4&&!memcmp(next.packet.data()+headers,"GET ",4)) {
                if(c.http_until.size()>=64)c.http_until.erase(c.http_until.begin());
                c.http_until[tuple]=std::chrono::steady_clock::now()+std::chrono::milliseconds(32);
            }
        }
    }
}
int hex(char c) { if(c>='0'&&c<='9')return c-'0';if(c>='A'&&c<='F')return c-'A'+10;if(c>='a'&&c<='f')return c-'a'+10;return -1; }
}
bool native_legacy_control_init(legacy_inject inject) {
    if(control)return !control->failed;
    const char *name=getenv("STREAMLINK_LEGACY_CONTROL"),*auth=getenv("STREAMLINK_LEGACY_AUTH"),*parent=getenv("STREAMLINK_LEGACY_PARENT");
    if(!name&&!auth&&!parent)return true;
    if(!name||strlen(name)!=50||strncmp(name,"StreamLink.Legacy.",18)||strspn(name+18,"0123456789abcdef")!=32||
        !auth||strlen(auth)!=128||!parent||strlen(parent)>10)return false;
    char *end=nullptr;unsigned long pid=strtoul(parent,&end,10);if(!pid||!end||*end)return false;
    auto *c=new controller;c->inject=inject;c->name=name;c->parent=static_cast<unsigned>(pid);
    if(!c->wake||!c->ready||!c->halt)return false;
    for(unsigned i=0;i<64;i++){int a=hex(auth[i*2]),b=hex(auth[i*2+1]);if(a<0||b<0)return false;c->authorization[i]=(a<<4)|b;}
    control=c;std::thread([c]{run(*c);}).detach();
    return WaitForSingleObject(c->ready,5000)==WAIT_OBJECT_0&&!c->failed;
}
bool native_legacy_control_enabled() {return control!=nullptr;}
bool native_legacy_control_enqueue(const char *packet,int length,native_wire_kind kind) {
    auto &c=*control;
    if(length<28||length>6144||(kind!=native_wire_kind::handshake&&kind!=native_wire_kind::maintenance&&kind!=native_wire_kind::completion)){c.stats[1]++;return false;}
    std::lock_guard<std::mutex> lock(c.gate);
    if(!c.armed||c.failed||c.queue.size()>=8){c.stats[1]++;return false;}
    c.queue.push_back({std::vector<char>(packet,packet+length),kind,native_wire_secure(),c.epoch,GetTickCount64()});c.stats[0]++;SetEvent(c.wake);return true;
}
void native_legacy_control_pause(){if(control){std::lock_guard<std::mutex> lock(control->gate);control->armed=false;control->epoch++;control->stats[4]+=control->queue.size();control->queue.clear();}}
void native_legacy_control_arm(){if(control){std::lock_guard<std::mutex> lock(control->gate);control->armed=true;}}
bool native_legacy_control_failed(){return control&&control->failed;}
void native_legacy_control_stats(unsigned long long counts[6]){for(unsigned i=0;i<6;i++)counts[i]=control?control->stats[i].load():0;}
