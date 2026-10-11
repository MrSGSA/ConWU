#pragma once
#include <string>
void native_broker_configure(const std::string &control_name, const unsigned char *authorization, unsigned parent);
bool native_broker_mode();
int native_broker_receive(char *packet, unsigned capacity);
int native_broker_send(const char *packet, unsigned length);
void native_broker_shutdown();
void native_broker_close();
