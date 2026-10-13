#pragma once
#include "native_broker.h"
using legacy_inject = bool (*)(const char *, int, native_wire_kind);
bool native_legacy_control_init(legacy_inject inject);
bool native_legacy_control_enabled();
bool native_legacy_control_enqueue(const char *packet, int length, native_wire_kind kind);
void native_legacy_control_pause();
void native_legacy_control_arm();
bool native_legacy_control_failed();
void native_legacy_control_stats(unsigned long long counts[6]);
