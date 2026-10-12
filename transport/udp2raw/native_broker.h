#pragma once
#include <string>
// Local pipe metadata only. Public TCP bytes and sequence behaviour stay intact.
enum class native_wire_kind : unsigned { handshake=0, maintenance=1, business=2, completion=3, diagnostic=4 };
native_wire_kind native_wire_classify(char type, const char *data, int length);
native_wire_kind native_wire_current();
struct native_wire_scope {
    native_wire_kind previous;
    explicit native_wire_scope(native_wire_kind kind);
    ~native_wire_scope();
};
void native_broker_configure(const std::string &control_name, const unsigned char *authorization, unsigned size, unsigned parent);
bool native_broker_mode();
int native_broker_receive(char *packet, unsigned capacity);
int native_broker_send(const char *packet, unsigned length);
void native_broker_shutdown();
void native_broker_close();
