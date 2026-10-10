#pragma once
// Experimental direct-P2P framing with TURN Data Indication wire fields.
// No allocation, TURN service, or relay is involved. Inner authentication stays
// in udp2raw. This is a classification experiment, not a TURN implementation.
inline bool native_udp_stun_shape() {
    static const bool enabled = [] { const char *v = getenv("STREAMLINK_UDP_SHAPE"); return v && strcmp(v, "stun") == 0; }();
    return enabled;
}
inline void shape_u16(char *p, unsigned int v) { uint16_t n = htons(uint16_t(v)); memcpy(p, &n, 2); }
inline unsigned int shape_read16(const char *p) { uint16_t n; memcpy(&n, p, 2); return ntohs(n); }
inline int shape_wrap(const packet_info_t &info, const char *data, int length, char *output, int capacity) {
    if (length < 0 || length > capacity - 40) return -1;
    int padded = (length + 3) & ~3;
    int total = 36 + padded;
    memset(output, 0, total);
    shape_u16(output, 0x0017); shape_u16(output + 2, total - 20);
    const unsigned char cookie[] = {0x21, 0x12, 0xa4, 0x42}; memcpy(output + 4, cookie, 4);
    static uint64_t nonce = (uint64_t(get_true_random_number()) << 32) | get_true_random_number();
    static uint32_t counter = 0;
    memcpy(output + 8, &nonce, 8); uint32_t serial = htonl(++counter); memcpy(output + 16, &serial, 4);
    shape_u16(output + 20, 0x12); shape_u16(output + 22, 8); output[25] = 1;
    shape_u16(output + 26, info.dst_port ^ 0x2112);
    uint32_t ip = info.new_dst_ip.v4 ^ htonl(0x2112a442); memcpy(output + 28, &ip, 4);
    shape_u16(output + 32, 0x13); shape_u16(output + 34, length);
    memcpy(output + 36, data, length); return total;
}
inline int shape_unwrap(char *&data, int &length) {
    const unsigned char cookie[] = {0x21, 0x12, 0xa4, 0x42};
    if (length < 36 || shape_read16(data) != 0x17 || shape_read16(data + 2) != unsigned(length - 20) ||
        memcmp(data + 4, cookie, 4) || shape_read16(data + 20) != 0x12 || shape_read16(data + 22) != 8 ||
        data[25] != 1 || shape_read16(data + 32) != 0x13) return -1;
    unsigned int size = shape_read16(data + 34);
    if (36 + ((size + 3) & ~3u) != unsigned(length)) return -1;
    data += 36; length = size; return 0;
}
