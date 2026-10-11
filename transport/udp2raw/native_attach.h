#pragma once
#include <string>
#include <mutex>
extern std::mutex native_injection_mutex;

// Managed ABI 1 (IPv4) / ABI 2 (brokered IPv6): one authorized peer per worker.
// A managed capture owner can route multiple non-overlapping worker tuples.
// No environment variable can authorize skipping bind.
void native_attach_arguments(int &argc, char **argv);
void native_attach_configure();
bool native_attached();
bool native_attachment_started();
std::string native_attachment_filter();
void native_attachment_armed();
bool native_attachment_packet(const char *packet, int length);
void native_capture_shutdown();
bool native_attachment_so();
unsigned long long native_attachment_start_tick();
void native_attachment_endpoints(address_t &source, address_t &destination);
