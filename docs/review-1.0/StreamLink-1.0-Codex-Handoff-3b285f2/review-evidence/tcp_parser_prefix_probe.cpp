// Generated audit fixture. This is NOT a full parser/native/network test.
// my_tcphdr declaration and recv_raw_tcp validation prefix copied verbatim from pinned source.
#include <cstdint>
#include <sys/types.h>
#include <array>
#include <iostream>
#include <cstring>
#define UDP2RAW_LITTLE_ENDIAN
constexpr int IPPROTO_TCP=6, log_debug=0;
struct my_tcphdr {
    /*__extension__*/ union {
        struct
        {
            u_int16_t th_sport; /* source port */
            u_int16_t th_dport; /* destination port */
            u_int32_t th_seq;   /* sequence number */
            u_int32_t th_ack;   /* acknowledgement number */
#ifdef UDP2RAW_LITTLE_ENDIAN
            u_int8_t th_x2 : 4;  /* (unused) */
            u_int8_t tc_off : 4; /* data offset */
#else
            u_int8_t th_off : 4; /* data offset */
            u_int8_t th_x2 : 4;  /* (unused) */
#endif
            u_int8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
            u_int16_t th_win; /* window */
            u_int16_t th_sum; /* checksum */
            u_int16_t th_urp; /* urgent pointer */
        };
        struct
        {
            u_int16_t source;
            u_int16_t dest;
            u_int32_t seq;
            u_int32_t ack_seq;
#ifdef UDP2RAW_LITTLE_ENDIAN
            u_int16_t res1 : 4;
            u_int16_t doff : 4;
            u_int16_t fin : 1;
            u_int16_t syn : 1;
            u_int16_t rst : 1;
            u_int16_t psh : 1;
            u_int16_t ack : 1;
            u_int16_t urg : 1;
            u_int16_t res2 : 2;
#else
            u_int16_t doff : 4;
            u_int16_t res1 : 4;
            u_int16_t res2 : 2;
            u_int16_t urg : 1;
            u_int16_t ack : 1;
            u_int16_t psh : 1;
            u_int16_t rst : 1;
            u_int16_t syn : 1;
            u_int16_t fin : 1;
#endif
            u_int16_t window;
            u_int16_t check;
            u_int16_t urg_ptr;
        };
    };
};
struct packet_info_t { int protocol=IPPROTO_TCP; };
struct raw_info_t { packet_info_t send_info,recv_info; };
std::array<char,64> backing{}; int logical_length=20;
int recv_raw_ip(raw_info_t &,char *&p,int &n) { p=backing.data(); n=logical_length; return 0; }
void mylog(int,const char*,...) {}
int recv_raw_tcp(raw_info_t &raw_info, char *&payload, int &payloadlen) {
    const packet_info_t &send_info = raw_info.send_info;
    packet_info_t &recv_info = raw_info.recv_info;

    // static char recv_raw_tcp_buf[buf_len];

    char *ip_payload;
    int ip_payloadlen;

    if (recv_raw_ip(raw_info, ip_payload, ip_payloadlen) != 0) {
        mylog(log_debug, "recv_raw_ip error\n");
        return -1;
    }

    if (recv_info.protocol != IPPROTO_TCP) {
        // printf("not tcp protocol\n");
        return -1;
    }

    my_tcphdr *tcph = (struct my_tcphdr *)ip_payload;

    unsigned short tcphdrlen = tcph->doff * 4;

    if (!(tcphdrlen > 0 && tcphdrlen <= 60)) {
        mylog(log_debug, "tcph error\n");
        return 0;
    }

    if (tcphdrlen > ip_payloadlen) {
        mylog(log_debug, "error,tcphdrlen >ip_payloadlen\n");
        return 0;
    }

    return 99; // Test-only sentinel: prefix accepted; rest of production parser is not exercised.
}
int main() {
  static_assert(sizeof(my_tcphdr)==20);
  const int cases[][2]={{0,20},{15,20},{1,20},{4,20},{5,10},{5,20}};
  std::cout << "["; bool first=true;
  for(auto &t: cases) {
    backing.fill(0); auto *h=reinterpret_cast<my_tcphdr*>(backing.data()); h->doff=t[0]; logical_length=t[1];
    raw_info_t raw; char sentinel='x'; char *out=&sentinel; int n=-777; int rc=recv_raw_tcp(raw,out,n);
    if(!first) std::cout << ","; first=false;
    std::cout << "{\"doff\":" << t[0] << ",\"logical_length\":"<<t[1]<<",\"return\":"<<rc<<",\"output_untouched\":"<<((out==&sentinel&&n==-777)?"true":"false")<<"}";
  }
  std::cout << "]\n";
}
