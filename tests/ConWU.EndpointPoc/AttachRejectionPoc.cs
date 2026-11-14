using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.EndpointPoc;

static class AttachRejectionPoc
{
    public static async Task<int> Run(string binary, string output)
    {
        using var deadline = new CancellationTokenSource(25000);
        var cases = new List<object>();
        foreach (string scenario in new[] { "wrong-abi", "unknown-capture-mode", "wire-without-broker", "wire-unknown-mode", "wire-reserved-bits", "old-attach", "old-generation", "wrong-request", "ipc-close-before-start", "ipv6-no-broker", "ipv6-noncanonical", "ipv6-mapped", "ipv6-wrong-size" }) {
            bool ipv6 = scenario.StartsWith("ipv6-");
            string name = "StreamLink.Attach." + Guid.NewGuid().ToString("N");
            using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
            var source = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
            await using var reflector = new Reflector(new(source, 0)); var generation = Guid.NewGuid();
            using var owner = await TcpEndpointLease.Open(new(source, 0), reflector.Endpoint, generation, deadline.Token);
            using var resource = owner.AcquireNativeAttachment(generation);
            using var raw = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            using var reserve = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int wire = ((IPEndPoint)reserve.Client.LocalEndPoint!).Port; reserve.Dispose();
            var info = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            string[] args = ["-c", "-l", "127.0.0.1:0", "-r", "127.0.0.1:45454", "-k", "ephemeral-test-only", "--raw-mode", "faketcp", "--managed-pipe", name];
            if (ipv6) args[4] = "[::1]:45454";
            // udp2raw rejects port zero; reserve then release a private test UDP port.
            using var app = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); args[2] = app.Client.LocalEndPoint!.ToString()!; app.Dispose();
            foreach (var arg in args) info.ArgumentList.Add(arg);
            info.Environment["STREAMLINK_TEST_BIND"] = wire.ToString();
            info.Environment["STREAMLINK_TEST_PEER"] = ((IPEndPoint)raw.Client.LocalEndPoint!).Port.ToString();
            using var child = Process.Start(info)!;
            Task<string> logs = child.StandardOutput.ReadToEndAsync(), errors = child.StandardError.ReadToEndAsync();
            bool quiet = false;
            try {
                await pipe.WaitForConnectionAsync(deadline.Token);
                byte[] frame = new byte[ipv6 ? 144 : 96]; "SLNA"u8.CopyTo(frame);
                BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(4), (ushort)(scenario == "wrong-abi" ? 99 : ipv6 ? 2 : 1));
                BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(6), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8), (uint)(scenario == "ipv6-wrong-size" ? 96 : frame.Length));
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(12), 1);
                resource.AttachId.TryWriteBytes(frame.AsSpan(16)); owner.Id.TryWriteBytes(frame.AsSpan(32)); generation.TryWriteBytes(frame.AsSpan(48));
                void Ep(int offset, IPEndPoint ep) { ep.Address.GetAddressBytes().CopyTo(frame, ipv6 ? 96 + (offset - 64) / 6 * 16 : offset); BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(offset+4), (ushort)ep.Port); }
                Ep(64, owner.Local); Ep(70, reflector.Endpoint); Ep(76, new(source, 45454));
                frame[82] = 1; frame[83] = 1;
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(84), 10000); BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(88), 1);
                if (scenario == "unknown-capture-mode") frame[92] = 2;
                if (scenario == "wire-without-broker") frame[93] = 1;
                if (scenario == "wire-unknown-mode") { frame[92] = 1; frame[93] = 2; }
                if (scenario == "wire-reserved-bits") { frame[92] = frame[93] = 1; frame[94] = 1; }
                if (ipv6) frame[92] = (byte)(scenario == "ipv6-no-broker" ? 0 : 1);
                if (scenario == "ipv6-noncanonical") frame[64] = 1;
                if (scenario == "ipv6-mapped") IPAddress.Parse("::ffff:127.0.0.1").GetAddressBytes().CopyTo(frame, 128);
                bool rejectInitial = ipv6 || scenario.StartsWith("wire-") || scenario is "wrong-abi" or "unknown-capture-mode";
                // Header validation can close the pipe before the remaining
                // invalid bytes are written. Exit code and zero I/O still must pass.
                try { await pipe.WriteAsync(frame, deadline.Token); }
                catch (IOException) when (rejectInitial) { }
                if (!rejectInitial) {
                    byte[] armed = new byte[96]; await pipe.ReadExactlyAsync(armed, deadline.Token);
                    if (BinaryPrimitives.ReadUInt16LittleEndian(armed.AsSpan(6)) != 2) throw new Exception("Expected Armed");
                    await Task.Delay(100, deadline.Token); quiet = raw.Available == 0;
                    if (scenario == "ipc-close-before-start") pipe.Dispose();
                    else {
                        BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(6), 3);
                        BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(12), scenario == "wrong-request" ? 99u : 2u);
                        if (scenario == "old-attach") Guid.NewGuid().TryWriteBytes(frame.AsSpan(16));
                        if (scenario == "old-generation") Guid.NewGuid().TryWriteBytes(frame.AsSpan(48));
                        await pipe.WriteAsync(frame, deadline.Token);
                    }
                } else quiet = raw.Available == 0;
                await child.WaitForExitAsync(deadline.Token);
                if (child.ExitCode is not (72 or 73) || raw.Available != 0 || !quiet) throw new Exception("Invalid authorization injected raw traffic or did not terminate");
                cases.Add(new { scenario, code = child.ExitCode, noRawTraffic = true, helperRetained = !owner.Closed });
            } finally { if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); } await logs; await errors; }
        }
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { scope = "real native child/pipe negative tests, no driver", cases }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"PASS {cases.Count} managed authorization negatives; zero raw sends before valid Start"); return 0;
    }
}
