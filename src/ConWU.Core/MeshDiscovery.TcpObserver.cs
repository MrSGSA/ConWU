using System.Net.Http.Json;

namespace StreamLink.Core;

public interface ITcpObservationControl
{
    Task<TcpObserverReply> TcpObservation(string operation, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token);
}
public sealed partial class MeshDiscoveryClient
{
    public async Task<TcpObserverReply> TcpObservation(string operation, Guid ticket, TcpProbeSpec[]? probes, CancellationToken token)
    {
        var request = TcpObserverProtocol.Create(profile, boot, operation, ticket, probes);
        using var response = await http.PostAsJsonAsync($"v3/mesh/{profile.Pair.Network}/tcp-observer", request, token);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TcpObserverReply>(token) ?? throw new IOException("TCP 观察回复为空");
    }
}
