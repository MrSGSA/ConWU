#pragma once

// The protocol remains in the upstream files. This boundary owns Windows I/O.
struct conn_info_t;
void native_watch_udp(fd64_t fd);
void native_unwatch_udp(fd64_t fd);
void native_drain_packets(conn_info_t *client);
void native_check_health();
bool native_udp_readable(int fd);
int send_raw_packet(raw_info_t &info, const char *packet, int length);
