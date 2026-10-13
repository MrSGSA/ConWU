#pragma once
bool native_legacy_egress_init();
bool native_legacy_egress_enabled();
bool native_legacy_egress_send(const char *packet,int length,unsigned peer);
void native_legacy_egress_pause();
void native_legacy_egress_arm();
bool native_legacy_egress_failed();
void native_legacy_egress_stats(unsigned long long counts[8]);
