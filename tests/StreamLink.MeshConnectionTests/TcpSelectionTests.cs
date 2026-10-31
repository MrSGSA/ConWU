using System.Net;
using System.Net.Sockets;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;

static partial class TcpTests
{
    public static async Task SelectionOwnership()
    {
        // Windows DNS cancellation can report WSA_E_CANCELLED (10111), not an
        // OperationCanceledException. Deliver it only when the winner cancels
        // an already-started screen; the winning STUN socket is real.
        for (int i = 0; i < 10; i++) {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var server = new StunServer { BeforeReply = entered.Task };
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            int before = TcpHelperLedger.Shared.Snapshot().OpenResources;
            async Task Screen(string _, CancellationToken token) {
                entered.TrySetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { throw new SocketException(10111); }
            }
            var (binding, result) = await TcpBinding.ConnectCore(Port(), IPAddress.Loopback, _ => { }, stop.Token,
                [server.Address, "cancelled-dns.invalid:3478"], Screen);
            using (binding) {
                var again = await binding.Pulse(stop.Token);
                Program.Check(result.Public.Equals(again.Public) && server.Accepted == 1,
                    "cancelled Windows DNS screen preserves the successful fixed-port helper, round=" + i);
            }
            Program.Check(TcpHelperLedger.Shared.Snapshot().OpenResources == before,
                "winner disposal returns its quota after late screening failure, round=" + i);
        }
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var server = new StunServer { BeforeReply = entered.Task };
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            int before = TcpHelperLedger.Shared.Snapshot().OpenResources;
            async Task Screen(string _, CancellationToken token) {
                entered.TrySetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { throw new InvalidOperationException("unexpected-screen-fault"); }
            }
            bool failed = false;
            try { var result = await TcpBinding.ConnectCore(Port(), IPAddress.Loopback, _ => { }, stop.Token,
                [server.Address, "unexpected.invalid:3478"], Screen); result.Binding.Dispose(); }
            catch (InvalidOperationException) { failed = true; }
            Program.Check(failed && TcpHelperLedger.Shared.Snapshot().OpenResources == before,
                "unexpected selection cleanup failure cannot orphan an unreturned winning helper");
        }
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            await using var server = new StunServer { BeforeReply = entered.Task };
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            int before = TcpHelperLedger.Shared.Snapshot().OpenResources;
            async Task Screen(string _, CancellationToken token) {
                entered.TrySetResult();
                try { await Task.Delay(Timeout.Infinite, token); }
                catch (OperationCanceledException) { stop.Cancel(); throw new SocketException(10111); }
            }
            bool cancelled = false;
            try { var result = await TcpBinding.ConnectCore(Port(), IPAddress.Loopback, _ => { }, stop.Token,
                [server.Address, "cancelled.invalid:3478"], Screen); result.Binding.Dispose(); }
            catch (OperationCanceledException) { cancelled = true; }
            Program.Check(cancelled && TcpHelperLedger.Shared.Snapshot().OpenResources == before,
                "caller cancellation during loser cleanup closes the successful but unreturned helper");
        }
    }
}
