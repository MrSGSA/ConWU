#pragma once
struct conn_info_t;
bool native_so_receive(); // consumes handshake packet, or leaves legacy payload queued
bool native_so_client_gate(conn_info_t &connection);
void native_so_server_tick();
