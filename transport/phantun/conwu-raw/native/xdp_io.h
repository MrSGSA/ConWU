// SPDX-License-Identifier: GPL-2.0-only
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct CW_XDP_CONFIG {
    // IPv4 values have network-byte-order representation in memory; ports are host order.
    uint32_t local_ip;
    uint32_t remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t server;
    uint32_t peer_reflexive;
    uint32_t protected_ip;
    uint16_t protected_port;
    uint16_t reserved;
} CW_XDP_CONFIG;
typedef void (*CW_XDP_RECEIVE)(void *context, const uint8_t *ipv4, uint32_t length);
typedef void (*CW_XDP_FAILURE)(void *context, const char *message);
void *cw_xdp_open(const CW_XDP_CONFIG *config, CW_XDP_RECEIVE receive,
                 CW_XDP_FAILURE failure, void *context, char *error, uint32_t error_size);
uint32_t cw_xdp_send(void *device, const uint8_t *ipv4, uint32_t length);
void cw_xdp_protect(void *device, uint32_t peer_ip, uint16_t peer_port);
uint32_t cw_xdp_interfaces(void *device);
uint32_t cw_xdp_queues(void *device);
uint32_t cw_xdp_probe(uint32_t interface_index, uint32_t *queues, char *error, uint32_t error_size);
void cw_xdp_close(void *device);
#ifdef __cplusplus
}
#endif
