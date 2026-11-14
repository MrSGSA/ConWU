using System.Net;
using System.Net.Sockets;

namespace StreamLink.Core;

// Some public reflectors return their own address as MAPPED-ADDRESS. A valid
// STUN transaction is not evidence that this address belongs to our NAT.
// Corroborate that exceptional case without guessing/altering the mapped port.
internal static class StunObservationValidation
{
    internal sealed record Sample(IPEndPoint Reflector, IPEndPoint Public);

    internal static async Task Validate(StunResult observation, IPEndPoint reflector, string[] servers,
        CancellationToken token, Func<string, IPAddress, IPEndPoint, CancellationToken, Task<Sample?>>? probe = null)
    {
        token.ThrowIfCancellationRequested();
        if (!PortControlRoute.GlobalV4(reflector.Address) ||
            !observation.Public.Address.Equals(reflector.Address) ||
            observation.Local.Address.Equals(reflector.Address)) return;

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
        budget.CancelAfter(4000);
        int independent = 0;
        foreach (string server in servers.Distinct(StringComparer.OrdinalIgnoreCase).Take(256)) {
            if (independent >= 3) break;
            try {
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
                attempt.CancelAfter(1500);
                var sample = await (probe ?? Probe)(server, observation.Local.Address, reflector, attempt.Token);
                attempt.Token.ThrowIfCancellationRequested();
                if (sample == null || sample.Reflector.Address.Equals(reflector.Address)) continue;
                independent++;
                // Another self-reporting service is not a trustworthy witness.
                if (!PortControlRoute.GlobalV4(sample.Public.Address) || sample.Public.Address.Equals(sample.Reflector.Address)) continue;
                if (sample.Public.Address.Equals(observation.Public.Address)) return;
                throw new StunReflectionException("STUN 返回服务端自身地址，与独立出口观察不符；已丢弃该候选并切换服务");
            } catch (StunReflectionException) { throw; }
            catch (Exception error) when (!token.IsCancellationRequested && error is IOException or SocketException or OperationCanceledException or ArgumentException) {
                if (budget.IsCancellationRequested) break;
            }
        }
        token.ThrowIfCancellationRequested();
        throw new StunReflectionException("STUN 返回服务端自身地址，未能由其他已配置服务确认；未发布该候选");
    }

    static async Task<Sample?> Probe(string server, IPAddress local, IPEndPoint excluded, CancellationToken token)
    {
        var remote = await Stun.Resolve(server, token);
        if (remote.Address.Equals(excluded.Address)) return null;
        // Query a separate ephemeral socket; never change the retained helper
        // tuple or use this probe's port as the network's advertised entry.
        var result = await Stun.Query(true, remote.ToString(), 0, token, local, TcpHelperPurpose.ServerScreening);
        return new(remote, result.Public);
    }
}

internal sealed class StunReflectionException(string message) : IOException(message);
