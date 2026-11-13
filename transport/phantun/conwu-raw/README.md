# ConWU optional raw carriers

This separate GPL-2.0-only executable implements two IPv4 datagram carriers:

- `mimic`: Mimic's zero-padding wire conversion, including its twelve-byte
  payload rotation, three-way handshake, window updates and keepalive probes.
  Protocol reference: hack3ric/mimic commit
  `585dee024099575b1a7abb85af78b656ceba9b7c` (GPL-2.0-only).
  Data segments use the upstream-compatible PSH flag to retain boundaries on
  virtual NICs whose GRO stage precedes this userspace capture path.
- `tcpraw`: the operating system performs a real TCP handshake; PSH payloads
  subsequently carry independent datagrams through raw packet I/O. Kernel
  packets use TTL=1 after connection establishment and are suppressed by an
  owned, narrow WinDivert/nft rule. Reference: xtaci/tcpraw commit
  `cbf96359f63c20cfd3b27a9b3927d1ebc6f4182d` (MIT; see TCPRAW-LICENSE).

Neither path writes business datagrams to a reliable TCP byte stream. There
is no data retransmission, ordered delivery wait, automatic UDP fallback, or
business relay. TCPRAW still needs a successful kernel TCP connection. Mimic
needs an inbound TCP-format route to the host. A gateway lease or STUN result
alone does not prove inbound reachability.

Both modes use WinDivert on Windows and AF_PACKET/raw IPv4 on Linux. Only the
packet I/O trait and Linux I/O adapter are shared with the MIT/Apache Phantun
component; its fake TCP stack is not used. The Windows port does not claim
Mimic's eBPF/XDP performance. Datagram size is bounded to 1448 bytes, queues to
512 entries and live flows to 128. Pending handshakes expire within 10 seconds.
No data or identity key is accepted from these unauthenticated carrier headers:
ConWU's parent retains member approval, MeshLink AEAD and replay protection.

The parent owns the public port, firewall resources, private resource journal
and child job. The child exits on input EOF/stop, parent death or capture
failure. TCPRAW releases the parent's temporary port probe before binding its
real socket and confirms the same tuple; failure never silently changes ports.
Distribution must include this source, the pinned Cargo.lock, its referenced
local adapter sources, GPL-2.0 license and dependency notices. The main ConWU
application retains its MIT license and communicates through the documented
process/loopback datagram ABI.
The Windows helper selects WinDivert's GPLv2 licensing alternative; the other
separate components can use its LGPLv3 alternative. Official WinDivert source
and all of its licensing alternatives accompany the Windows bundle.

Upstream binary interoperability and real WAN throughput require separate
validation. The default protocol and existing networks remain unchanged.
