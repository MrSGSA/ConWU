// Offline tests of the complete production recv_raw0/recv_raw_tcp pipeline.
// No stubbed parser, raw sockets, driver handles or external packet injection.
// SPDX-License-Identifier: MIT
#include "common.h"
#include "network.h"
#include "misc.h"
#include "log.h"
#include <array>
#include <random>
#include <vector>

namespace {
unsigned cases=0, failures=0;
FILE *corpus=nullptr;
void record(const std::vector<char>& p,int result) {
    if(!corpus)return;
    fprintf(corpus,"%c ",result==0?'1':'0');
    for(unsigned char b:p)fprintf(corpus,"%02x",b);
    fputc('\n',corpus);
}
void check(bool pass,const char *name) {
    ++cases;
    if(!pass) { if(failures<12)fprintf(stderr,"parser failure: %s\n",name); ++failures; }
}
std::vector<char> frame(int tcp_length,unsigned doff=5,const std::vector<unsigned char> &options={},const char *data=nullptr) {
    std::vector<char> p(20+tcp_length,0);
    auto *ip=reinterpret_cast<my_iphdr *>(p.data());
    ip->version=4;ip->ihl=5;ip->protocol=IPPROTO_TCP;ip->ttl=64;
    ip->tot_len=htons(static_cast<uint16_t>(p.size()));
    ip->saddr=htonl(0x0a010002);ip->daddr=htonl(0x0a010001);
    if(tcp_length>=20) {
        auto *tcp=reinterpret_cast<my_tcphdr *>(p.data()+20);
        tcp->source=htons(32001);tcp->dest=htons(41080);tcp->doff=doff;
        tcp->seq=htonl(0xfffffffeu);tcp->ack_seq=htonl(123);tcp->ack=1;tcp->psh=data!=nullptr;
        const size_t option_size=std::min(options.size(),static_cast<size_t>(tcp_length-20));
        if(option_size)memcpy(p.data()+40,options.data(),option_size);
        if(data&&tcp_length>=static_cast<int>(doff*4))memcpy(p.data()+20+doff*4,data,tcp_length-doff*4);
        pseudo_header pseudo{};pseudo.source_address=ip->saddr;pseudo.dest_address=ip->daddr;
        pseudo.protocol=IPPROTO_TCP;pseudo.tcp_length=htons(tcp_length);
        tcp->check=csum_with_header(reinterpret_cast<char *>(&pseudo),sizeof(pseudo),reinterpret_cast<unsigned short *>(tcp),tcp_length);
    } else if(tcp_length>12) {
        p[32]=static_cast<char>(doff<<4);
    }
    ip->check=csum(reinterpret_cast<unsigned short *>(ip),20);
    return p;
}
std::vector<char> frame6(int tcp_length,unsigned doff=5) {
    auto v4=frame(tcp_length,doff);
    std::vector<char> p(40+tcp_length,0);auto *ip=reinterpret_cast<my_ip6hdr *>(p.data());
    ip->version=6;ip->next_header=IPPROTO_TCP;ip->hop_limit=64;ip->payload_len=htons(tcp_length);
    inet_pton(AF_INET6,"2001:db8::2",&ip->src);inet_pton(AF_INET6,"2001:db8::1",&ip->dst);
    if(tcp_length)memcpy(p.data()+40,v4.data()+20,tcp_length);
    if(tcp_length>=20){auto *tcp=reinterpret_cast<my_tcphdr *>(p.data()+40);tcp->check=0;
        pseudo_header6 pseudo{};pseudo.src=ip->src;pseudo.dst=ip->dst;pseudo.next_header=IPPROTO_TCP;pseudo.tcp_length=htons(tcp_length);
        tcp->check=csum_with_header(reinterpret_cast<char *>(&pseudo),sizeof(pseudo),reinterpret_cast<unsigned short *>(tcp),tcp_length);}
    return p;
}
void run(const std::vector<char>& p,bool expect_valid,int expected_size=-1) {
    raw_info_t info;
    info.recv_info.seq=73;info.recv_info.ack_seq=41;info.recv_info.ack_seq_counter=3;
    info.rst_received=2;info.disabled=false;info.reserved_send_seq=75;
    std::array<unsigned char,sizeof(info)> before{};memcpy(before.data(),&info,sizeof(info));
    memset(g_packet_buf,0xa5,sizeof(g_packet_buf));
    if(!p.empty())memcpy(g_packet_buf,p.data(),p.size());
    g_packet_buf_len=static_cast<int>(p.size());g_packet_buf_cnt=1;
    char *payload=reinterpret_cast<char *>(static_cast<uintptr_t>(0x1234));int length=987;
    int result=recv_raw0(info,payload,length);
    record(p,result);
    check((result==0)==expect_valid,"classification");
    check(g_packet_buf_cnt==0,"one input consumed");
    if(result!=0) {
        check(result<0&&payload==nullptr&&length==0,"failure outputs cleared");
        check(memcmp(before.data(),&info,sizeof(info))==0,"failure does not commit receive state");
    } else {
        const auto start=reinterpret_cast<uintptr_t>(g_packet_buf),end=start+p.size(),ptr=reinterpret_cast<uintptr_t>(payload);
        check(ptr>=start&&ptr<=end&&length>=0&&static_cast<size_t>(length)<=end-ptr,"success payload bounded");
        check(info.recv_info.data_len==length,"success data length committed");
        if(expected_size>=0)check(length==expected_size,"valid payload length");
    }
}
}
int native_parser_test_main() {
    // Even offline inet_ntop used by normal RST logging requires Winsock init.
#ifdef _WIN32
    WSADATA winsock{};
    if(WSAStartup(MAKEWORD(2,2),&winsock)!=0)return 2;
#endif
    if(const char *path=getenv("STREAMLINK_PARSER_CORPUS")){corpus=fopen(path,"wb");if(!corpus)return 2;}
    log_level=log_never;enable_log_color=0;
    raw_mode=mode_faketcp;raw_ip_version=AF_INET;filter_port=41080;bind_addr_used=0;
    // Minimum IP and TCP lengths, all data offsets, and declared TCP options.
    for(int ip=0;ip<20;++ip) { auto p=frame(20);p.resize(ip);run(p,false); }
    for(int length=0;length<=80;++length)for(unsigned doff=0;doff<16;++doff)
        run(frame(length,doff),length>=20&&doff>=5&&static_cast<int>(doff*4)<=length);
    run(frame(24,6,{2,255,0,0}),false);
    run(frame(24,6,{2,1,0,0}),false);
    run(frame(24,6,{1,1,1,2}),false);
    run(frame(24,6,{8,10,0,0}),false);
    run(frame(24,6,{8,4,0,0}),false);
    run(frame(32,8,{1,1,8,10,0,0,0,1,0,0,0,2}),true,0);
    const char http[]="GET / HTTP/1.1\r\nHost: test.ustc.edu.cn\r\n\r\n";
    run(frame(20+sizeof(http)-1,5,{},http),true,sizeof(http)-1);
    const char bare[]={0,'b',0,'a','r','e',static_cast<char>(0xff)};
    run(frame(20+sizeof(bare),5,{},bare),true,sizeof(bare));
    // Malformed IP length and wrong protocol must have the same error contract.
    auto bad=frame(20);reinterpret_cast<my_iphdr *>(bad.data())->tot_len=htons(10);
    reinterpret_cast<my_iphdr *>(bad.data())->check=0;
    reinterpret_cast<my_iphdr *>(bad.data())->check=csum(reinterpret_cast<unsigned short *>(bad.data()),20);run(bad,false);
    bad=frame(20);reinterpret_cast<my_iphdr *>(bad.data())->protocol=IPPROTO_UDP;
    reinterpret_cast<my_iphdr *>(bad.data())->check=0;
    reinterpret_cast<my_iphdr *>(bad.data())->check=csum(reinterpret_cast<unsigned short *>(bad.data()),20);run(bad,false);
    for(uint16_t flags:{uint16_t(0x2000),uint16_t(1)}) {
        auto p=frame(20);auto *ip=reinterpret_cast<my_iphdr *>(p.data());
        ip->frag_off=htons(flags);ip->check=0;ip->check=csum(reinterpret_cast<unsigned short *>(ip),20);run(p,false);
    }
    bad=frame(20);bad[36]^=1;run(bad,false);
    raw_ip_version=AF_INET6;
    for(int size=0;size<40;++size){auto p=frame6(20);p.resize(size);run(p,false);}
    for(int length=0;length<=64;++length)for(unsigned doff=0;doff<16;++doff)
        run(frame6(length,doff),length>=20&&doff>=5&&static_cast<int>(doff*4)<=length);
    for(unsigned next:{0u,43u,44u,60u}){auto p=frame6(20);p[6]=next;run(p,false);}
    auto jumbo=frame6(20);jumbo[4]=jumbo[5]=0;run(jumbo,false);
    raw_ip_version=AF_INET;
    // Deterministic offline mutation corpus. This asserts error/success bounds,
    // not that every random byte pattern is a valid/invalid authenticated frame.
    std::mt19937 random(0x53454301u);
    for(unsigned i=0;i<20000;++i) {
        auto p=frame(static_cast<int>(random()%129),random()%16);
        if(p.size()>40)for(unsigned j=0;j<4;++j)p[20+random()%(p.size()-20)]=static_cast<char>(random());
        raw_info_t info;std::array<unsigned char,sizeof(info)> before{};memcpy(before.data(),&info,sizeof(info));
        memcpy(g_packet_buf,p.data(),p.size());g_packet_buf_len=p.size();g_packet_buf_cnt=1;
        char *payload=nullptr;int length=0;int result=recv_raw0(info,payload,length);
        record(p,result);
        if(result!=0)check(result<0&&payload==nullptr&&length==0&&memcmp(before.data(),&info,sizeof(info))==0,"mutation error contract");
        else {const auto start=reinterpret_cast<uintptr_t>(g_packet_buf),end=start+p.size(),ptr=reinterpret_cast<uintptr_t>(payload);check(ptr>=start&&ptr<=end&&length>=0&&static_cast<size_t>(length)<=end-ptr,"mutation success bounds");}
    }
    printf("{\"scope\":\"complete production TCP parser offline; no driver or WAN\",\"cases\":%u,\"failures\":%u,\"mutations\":20000,\"status\":\"%s\"}\n",cases,failures,failures?"Fail":"Pass");
    if(corpus)fclose(corpus);
#ifdef _WIN32
    WSACleanup();
#endif
    return failures?1:0;
}
