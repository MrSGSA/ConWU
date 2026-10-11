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
        foreach (string scenario in new[] { "wrong-abi", "old-attach", "old-generation", "wrong-request", "ipc-close-before-start" }) {
            string name = "StreamLink.Attach." + Guid.NewGuid().ToString("N");
            using var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly | PipeOptions.FirstPipeInstance);
            await using var reflector = new Reflector(); var generation = Guid.NewGuid();
            using var owner = await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), reflector.Endpoint, generation, deadline.Token);
            using var resource = owner.AcquireNativeAttachment(generation);
            using var raw = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            using var reserve = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            int wire = ((IPEndPoint)reserve.Client.LocalEndPoint!).Port; reserve.Dispose();
            var info = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            string[] args = ["-c", "-l", "127.0.0.1:0", "-r", "127.0.0.1:45454", "-k", "ephemeral-test-only", "--raw-mode", "faketcp", "--managed-pipe", name];
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
                byte[] frame = new byte[96]; "SLNA"u8.CopyTo(frame);
                BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(4), (ushort)(scenario == "wrong-abi" ? 99 : 1));
                BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(6), 1);
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(8), 96);
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(12), 1);
                resource.AttachId.TryWriteBytes(frame.AsSpan(16)); owner.Id.TryWriteBytes(frame.AsSpan(32)); generation.TryWriteBytes(frame.AsSpan(48));
                void Ep(int offset, IPEndPoint ep) { ep.Address.GetAddressBytes().CopyTo(frame, offset); BinaryPrimitives.WriteUInt16LittleEndian(frame.AsSpan(offset+4), (ushort)ep.Port); }
                Ep(64, owner.Local); Ep(70, reflector.Endpoint); Ep(76, new(IPAddress.Loopback, 45454));
                frame[82] = 1; frame[83] = 1;
                BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(84), 10000); BinaryPrimitives.WriteUInt32LittleEndian(frame.AsSpan(88), 1);
                await pipe.WriteAsync(frame, deadline.Token);
                if (scenario != "wrong-abi") {
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
