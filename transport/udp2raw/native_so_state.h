#pragma once
#include <cstdint>
#include <optional>

// TCP *shape* handshake only. No retransmission/ordering of business datagrams.
// One instance per owned wire tuple, for one attempt; never reset while Active.
namespace streamlink {
struct ShapePacket {
    std::uint32_t seq, ack;
    std::uint8_t flags;
    unsigned payload = 0;
};
enum class ShapePhase { dormant, syn_sent, syn_received, established, expired, closed };
class SimultaneousOpen {
    std::uint32_t iss_, irs_ = 0;
    std::uint64_t start_ = 0;
    bool peer_ = false;
    unsigned retry_ = 0;
    ShapePhase phase_ = ShapePhase::dormant;
    bool pending() const { return phase_ == ShapePhase::syn_sent || phase_ == ShapePhase::syn_received; }
    ShapePacket syn() const { return {iss_, peer_ ? irs_ + 1u : 0u, std::uint8_t(peer_ ? 0x12 : 0x02)}; }
public:
    explicit SimultaneousOpen(std::uint32_t iss) : iss_(iss) {}
    ShapePhase phase() const { return phase_; }
    bool established() const { return phase_ == ShapePhase::established; }
    std::uint32_t iss() const { return iss_; }
    std::uint32_t irs() const { return irs_; }
    std::uint64_t deadline() const { return start_ + 8000; }
    void cancel() { phase_ = ShapePhase::closed; }
    bool start(std::uint64_t now) {
        if (phase_ != ShapePhase::dormant) return false;
        start_ = now; phase_ = ShapePhase::syn_sent; return true;
    }
    std::optional<ShapePacket> tick(std::uint64_t now) {
        if (!pending()) return {};
        if (now >= deadline()) { phase_ = ShapePhase::expired; return {}; }
        constexpr unsigned times[] = {0, 500, 1500, 3500, 6500};
        if (retry_ < 5 && now - start_ >= times[retry_]) { ++retry_; return syn(); }
        return {};
    }
    std::optional<ShapePacket> receive(const ShapePacket &p, std::uint64_t now) {
        if (phase_ == ShapePhase::dormant || phase_ == ShapePhase::closed || phase_ == ShapePhase::expired) return {};
        if (pending() && now >= deadline()) { phase_ = ShapePhase::expired; return {}; }
        // RST cannot carry an AttemptId. Before shape establishment accept only
        // the exact ACK of this attempt's SYN; stale/mismatched resets are inert.
        if (p.flags & 4) {
            if ((phase_ == ShapePhase::syn_sent && (p.flags & 0x10) && p.ack == iss_ + 1u) ||
                (phase_ == ShapePhase::syn_received && p.seq == irs_ + 1u && (!(p.flags & 0x10) || p.ack == iss_ + 1u)))
                phase_ = ShapePhase::closed;
            return {};
        }
        if (p.flags == 0x02 && p.payload == 0) {
            if (peer_ && p.seq != irs_) return {};
            if (!peer_) { peer_ = true; irs_ = p.seq; }
            if (!established()) phase_ = ShapePhase::syn_received;
            return syn();
        }
        if (p.flags == 0x12 && p.payload == 0) {
            if (p.ack != iss_ + 1u || (peer_ && p.seq != irs_)) return {};
            peer_ = true; irs_ = p.seq; phase_ = ShapePhase::established;
            return ShapePacket{iss_ + 1u, irs_ + 1u, 0x10};
        }
        // Correct ACK+first HTTP/bare payload can finish a lost-final-ACK trace.
        // No payload or TCP window logic is imported into the legacy data plane.
        if (phase_ == ShapePhase::syn_received && (p.flags == 0x10 || p.flags == 0x18) &&
            p.seq == irs_ + 1u && p.ack == iss_ + 1u) phase_ = ShapePhase::established;
        return {};
    }
};
}
