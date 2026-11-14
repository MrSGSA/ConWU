using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;

static partial class TcpTests
{
    static async Task Contender(int port)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) start.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        start.ArgumentList.Add("--contend"); start.ArgumentList.Add(port.ToString());
        using var child = Process.Start(start)!;
        try { await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)); Program.Check(child.ExitCode == 0, "separate process cannot take the legacy helper's port using SO_REUSEADDR"); }
        finally { if (!child.HasExited) { child.Kill(); await child.WaitForExitAsync(); } }
    }
    static async Task Ownership()
    {
        await using(var fallbackServer=new StunServer()){
            using var occupied=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){ExclusiveAddressUse=true};
            occupied.Bind(new IPEndPoint(IPAddress.Loopback,0));occupied.Listen(1);
            int occupiedPort=((IPEndPoint)occupied.LocalEndPoint!).Port,receiverPort=Port();
            using var fallbackStop=new CancellationTokenSource(10000);var notes=new List<string>();
            var available=await TcpBinding.ConnectAvailable(occupiedPort,receiverPort,IPAddress.Loopback,notes.Add,fallbackStop.Token,[fallbackServer.Address]);
            using(available.Binding){
                Program.Check(available.Result.Local.Port!=occupiedPort&&available.Result.Local.Port!=receiverPort&&available.Binding.Snapshot.Local==available.Result.Local.ToString(),"new mapping uses a real ephemeral STUN source when the preferred port is occupied");
                Program.Check(notes.Any(x=>x.Contains("被占用"))&&fallbackServer.Accepted==1,"port recovery is reported and never connects through the foreign port owner");
                var pulse=await available.Binding.Pulse(fallbackStop.Token);
                Program.Check(pulse.Local.Equals(available.Result.Local)&&pulse.Public.Equals(available.Result.Public),"fallback keeps the same observed socket for subsequent keepalive");
            }
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(40)); var token = deadline.Token;
        await using (var server = new StunServer()) {
            int port = Port(); var (binding, result) = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, token, [server.Address]);
            using (binding) {
                var original = binding.Snapshot;
                Program.Check(original.LeaseId != Guid.Empty && original.Generation != Guid.Empty && original.Local == result.Local.ToString() && original.Reflector == server.Address,
                    "legacy fixed-port observation exposes its actual persistent lease and helper tuple");
                await Contender(port); var clock = Stopwatch.StartNew(); bool busy = false;
                try { var duplicate = await TcpBinding.Connect(port, IPAddress.Loopback, _ => { }, token, [server.Address, server.Address]); duplicate.Binding.Dispose(); }
                catch (TcpEndpointBusyException ex) { busy = ex.Local.Port == port; }
                Program.Check(busy && clock.ElapsedMilliseconds < 1500 && server.Accepted == 1, "second helper owner fails with EndpointBusy before STUN selection retries or extra connects");
                var replies = await Task.WhenAll(binding.Pulse(token), binding.Pulse(token));
                Program.Check(replies.All(r => r.Public.Equals(result.Public)) && binding.Snapshot.LeaseId == original.LeaseId && server.Accepted == 1,
                    "concurrent keepalive calls serialize on the same lease and preserve the observed resource");
                server.WrongTransaction = true; bool invalid = false;
                try { await binding.Pulse(token); } catch (IOException) { invalid = true; }
                int sent = server.Requests; server.WrongTransaction = false;
                try { await binding.Pulse(token); } catch (IOException) { }
                Program.Check(invalid && !binding.Snapshot.QueryUsable && !binding.Snapshot.Closed && server.Requests == sent,
                    "failed STUN transaction marks only query health and cannot reuse the contaminated byte stream");
                await Contender(port);
            }
            await Program.Until(() => server.Active == 0, "retired helper closes after its last reference", 2000);
            Program.Check(binding.Snapshot.Closed && server.Eof == 1 && server.Resets == 0, "normal helper shutdown is EOF at the peer, without configured abortive reset");
        }
        await using (var server = new StunServer()) {
            var (binding, _) = await TcpBinding.Connect(Port(), IPAddress.Loopback, _ => { }, token, [server.Address]);
            using (binding)
            using (var cancel = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                server.Silent = true; int sent = server.Requests;
                var pulse = binding.Pulse(cancel.Token);
                await Program.Until(() => server.Requests > sent, "pending transaction reached the actual helper", 1500);
                binding.Dispose(); Program.Check(!binding.Snapshot.Closed && server.Active == 1, "disposing the binding cannot close a lease with an in-flight observation reference");
                cancel.Cancel(); try { await pulse; } catch (OperationCanceledException) { }
                Program.Check(binding.Snapshot.Closed, "cancellation joins the final observation and returns the owned socket");
            }
            await Program.Until(() => server.Active == 0, "in-flight cancellation releases the peer's TCP connection", 2000);
            Program.Check(server.Resets == 0, "cancellation no longer explicitly resets the helper connection");
        }
        await using (var server = new StunServer()) {
            var owners = new List<TcpEndpointLease>();
            try {
                for (int i = 0; i < 7; i++) owners.Add(await TcpEndpointLease.Open(new(IPAddress.Loopback, 0), IPEndPoint.Parse(server.Address), Guid.NewGuid(), token));
                var (binding, initial) = await TcpBinding.Connect(Port(), IPAddress.Loopback, _ => { }, token, [server.Address]);
                using (binding) {
                    await Program.Until(() => server.Active == 8, "native-source leases and legacy helper reach the common eight-socket limit", 2000);
                    bool bounded = false; try { await Stun.Query(true, server.Address, 0, token, IPAddress.Loopback); } catch (IOException) { bounded = true; }
                    var next = await binding.Pulse(token);
                    Program.Check(bounded && server.Accepted == 8 && next.Public.Equals(initial.Public), "ephemeral TCP screens use the same quota; existing keepalive does not allocate another socket");
                    owners[0].Dispose();
                    var screen = await Stun.Query(true, server.Address, 0, token, IPAddress.Loopback);
                    Program.Check(screen.Local.Port != initial.Local.Port, "releasing one owner admits an independent ephemeral screen without moving the fixed mapping");
                }
            } finally { foreach (var lease in owners) lease.Dispose(); }
            await Program.Until(() => server.Active == 0, "mixed native/legacy/screen owners release every TCP quota", 2000);
        }
    }
}
