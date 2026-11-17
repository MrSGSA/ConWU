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

Windows Mimic defaults to WinDivert after repeated Generic AF_XDP TX queue
binding failures on the Intel AX211 WLAN adapter. Its inbound packets are
owned, not sniffed, so the kernel cannot race the userspace handshake with a
RST. A narrow guard suppresses kernel RSTs from the owned source port;
same-port protected STUN control packets are reinjected unchanged. Client
peer-reflexive learning stays limited to the selected peer IP and requires
the existing handshake validation. Capture workers join before teardown.

For development only, `CONWU_MIMIC_IO=xdp` requests Microsoft XDP 1.4.0 Generic
AF_XDP receive/transmit. Startup errors emit a backend-fallback event and
select WinDivert. A running XDP failure exits the helper so the parent can
reconnect; protocol/identity are preserved. XDP is no longer an MSI prerequisite
and existing shared XDP drivers are left in place. In the optional XDP path,
all active RSS queues on each attached IPv4 interface are covered.
The port bitmap remains alive until program close because the XDP API pins,
rather than copies, its pages. Ring/UMEM ownership ends after receiver workers
join and socket handles close. Source routing and Ethernet next-hop lookup use
Windows IP Helper; no per-packet raw-IP injection or new kernel driver is used.

Windows TCPRAW retains its independent WinDivert adapter and narrow TTL=1
kernel-output guard. The executable delay-loads the DLL for either WinDivert adapter.
Current XDP built-in predicates cannot express the existing source-port/TTL
guard without broader outbound interception. An individual Mimic device uses
one I/O backend; rules do not intercept unrelated host TCP ports.

Linux continues to use AF_PACKET/raw IPv4 for both carriers. Only the packet
I/O trait and Linux I/O adapter are shared with the MIT/Apache Phantun component;
its fake TCP stack is not used. Mimic wire conversion and MeshLink encryption
remain in user mode; AF_XDP I/O is not a claim of an in-kernel protocol port or
Linux eBPF-equivalent performance. Datagram size is bounded to 1448 bytes, queues to
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
The TCPRAW helper selects WinDivert's GPLv2 licensing alternative; the other
separate components can use its LGPLv3 alternative. Official WinDivert source
and all of its licensing alternatives accompany the Windows bundle.

The vendored XDP SDK headers are unmodified MIT-licensed version 1.4.0 files;
see native/xdp-sdk/PROVENANCE.txt. Build with scripts/Build-Phantun.ps1 on Windows
(MSVC C++ and the Windows SDK are required) or the existing Linux build route.
scripts/Get-XdpRuntime.ps1 pins the official runtime package and verifies its
SHA-256, per-file hashes and Microsoft driver/catalog signatures. New Windows
installations retain these optional diagnostic files. The default installer
checks WinDivert and restores networks without installing/rebinding XDP. An
explicit XDP experiment requires an already installed compatible runtime.

Windows/Linux role swaps, protected STUN, shared receiver, AEAD isolation and
reconnection have independent local integration checks. Real WAN throughput,
power usage and physical streaming require separate validation. The wire
protocol and saved network identities remain compatible.
