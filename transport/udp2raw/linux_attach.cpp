#include "common.h"
#include "network.h"
#include "misc.h"
#include "native_attach.h"
#include <sys/un.h>
#include <poll.h>
#include <atomic>
#include <chrono>
#include <thread>

std::mutex native_injection_mutex;
namespace {
std::string control_path;
int channel=-1;
unsigned char identity[96]{};
address_t local,helper,peer;
std::atomic<bool> started{false},armed{false};
std::atomic<unsigned long long> start_tick{0};
unsigned request=1;
unsigned read16(const unsigned char *p){return p[0]|unsigned(p[1])<<8;}
unsigned read32(const unsigned char *p){return read16(p)|read16(p+2)<<16;}
void write16(unsigned char *p,unsigned value){p[0]=value;p[1]=value>>8;}
unsigned long long now(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();}
[[noreturn]]void reject(const char *reason){mylog(log_fatal,"Linux managed attach rejected: %s\n",reason);_exit(72);}
bool read_frame(unsigned char *frame){
    unsigned offset=0;auto deadline=now()+10000;
    while(offset<96&&now()<deadline){pollfd wait{channel,POLLIN,0};int ready=poll(&wait,1,100);if(ready<0&&errno==EINTR)continue;if(ready<0)return false;if(!ready)continue;int n=recv(channel,frame+offset,96-offset,0);if(n<=0)return false;offset+=n;}
    return offset==96;
}
void reply(unsigned type,const unsigned char *frame){
    unsigned char result[96];memcpy(result,frame,96);write16(result+6,type);
    unsigned offset=0;while(offset<96){int n=send(channel,result+offset,96-offset,MSG_NOSIGNAL);if(n<=0)reject("reply failed");offset+=n;}
}
void monitor(){
    unsigned char frame[96];
    while(read_frame(frame)){
        unsigned type=read16(frame+6),sequence=read32(frame+12);
        unsigned char expected[96];memcpy(expected,identity,96);memcpy(expected+6,frame+6,2);memcpy(expected+12,frame+12,4);
        if(memcmp(expected,frame,96)||sequence!=++request)reject("identity or request changed");
        if(type==3){if(!started.exchange(true))start_tick.store(now());reply(7,frame);}
        else if(type==6)reply(6,frame);
        else if(type==4){started.store(false);reply(5,frame);_exit(0);}
        else reject("unexpected control type");
    }
    started.store(false);_exit(73);
}
address_t endpoint(const unsigned char *p,unsigned port){address_t address;memset(&address.inner,0,sizeof(address.inner));address.inner.ipv4.sin_family=AF_INET;memcpy(&address.inner.ipv4.sin_addr,p,4);address.inner.ipv4.sin_port=htons(port);return address;}
}
void native_attach_arguments(int &argc,char **argv){
    for(int i=1;i<argc;++i)if(!strcmp(argv[i],"--managed-pipe")){
        if(!control_path.empty()||i+1>=argc)reject("invalid control argument");
        control_path=argv[i+1];
        if(control_path.empty()||control_path[0]!='/'||control_path.size()>=sizeof(sockaddr_un::sun_path))reject("invalid socket path");
        for(int j=i;j+2<argc;++j)argv[j]=argv[j+2];
        argc-=2;argv[argc]=nullptr;--i;
    }
}
void native_attach_configure(){
    if(control_path.empty())return;
    channel=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(channel<0)reject("socket creation");
    sockaddr_un address{};address.sun_family=AF_UNIX;memcpy(address.sun_path,control_path.c_str(),control_path.size()+1);
    if(connect(channel,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0)reject("socket connect");
    ucred parent{};socklen_t length=sizeof(parent);
    if(getsockopt(channel,SOL_SOCKET,SO_PEERCRED,&parent,&length)!=0||parent.pid!=getppid()||parent.uid!=geteuid())reject("launcher identity");
    if(!read_frame(identity)||memcmp(identity,"SLNA",4)||read16(identity+4)!=1||read16(identity+6)!=1||read32(identity+8)!=96||read32(identity+12)!=1)reject("invalid authorization");
    unsigned char zero[16]{};for(int offset:{16,32,48})if(!memcmp(identity+offset,zero,16))reject("empty identity");
    if(raw_mode!=mode_faketcp||raw_ip_version!=AF_INET||identity[83]!=2||read32(identity+84)!=10000||read32(identity+88)!=1||read32(identity+92)!=0)reject("unsupported descriptor");
    local=endpoint(identity+64,read16(identity+68));helper=endpoint(identity+70,read16(identity+74));peer=endpoint(identity+76,read16(identity+80));
    if(!local.get_port()||!peer.get_port()||helper==peer||local==peer||identity[82]!=(program_mode==client_mode?1:2))reject("tuple conflict");
    if(program_mode==client_mode){if(!(remote_addr==peer))reject("peer differs");source_addr=local;force_source_ip=1;source_port=local.get_port();force_source_port=1;}
    else if(!(local_addr==local))reject("listener differs");
}
bool native_attached(){return channel>=0;}
bool native_attachment_so(){return native_attached();}
bool native_attachment_started(){return !native_attached()||started.load();}
unsigned long long native_attachment_start_tick(){return start_tick.load();}
void native_attachment_endpoints(address_t &source,address_t &destination){source=local;destination=peer;}
bool native_attachment_learn_peer_port(unsigned short){return false;}
std::string native_attachment_filter(){return "linux-authorized-tuple";}
void native_capture_shutdown(){started.store(false);}
void native_attachment_armed(){
    if(!native_attached()||armed.exchange(true))return;
    reply(2,identity);std::thread(monitor).detach();auto deadline=now()+30000;
    while(!started.load()){if(now()>=deadline)reject("Start expired");std::this_thread::sleep_for(std::chrono::milliseconds(2));}
}
bool native_attachment_packet(const char *bytes,int length){
    if(!native_attached())return true;
    if(!started.load()||length<40)return false;
    auto p=reinterpret_cast<const unsigned char*>(bytes);unsigned ihl=(p[0]&15)*4;
    return p[0]>>4==4&&p[9]==6&&ihl>=20&&length>=int(ihl+20)&&!(p[6]&0x3f)&&!p[7]&&
        !memcmp(p+12,&local.inner.ipv4.sin_addr.s_addr,4)&&!memcmp(p+16,&peer.inner.ipv4.sin_addr.s_addr,4)&&
        ((p[ihl]<<8)|p[ihl+1])==local.get_port()&&((p[ihl+2]<<8)|p[ihl+3])==peer.get_port();
}
