using System.Net;

namespace StreamLink.Core;

public sealed record UdpGatewaySnapshot(Guid SocketResourceId, PortControlSnapshot Mapping, string Failure);

public sealed partial class UdpTraversal
{
    PortControlLease? gateway;
    IPEndPoint? gatewayEndpoint;
    Task gatewayMaintenance = Task.CompletedTask;
    string gatewayFailure = "";
    public UdpGatewaySnapshot? GatewaySnapshot { get { lock (gate) return gateway == null ? null : new(SocketId, gateway.Snapshot, gatewayFailure); } }
    bool GatewayEligible { get { lock (gate) return gateway == null || gatewayFailure.Length == 0 && gateway.Valid && gateway.External.Equals(gatewayEndpoint); } }
    public bool GatewayCandidateCurrent(IPEndPoint endpoint) { lock (gate) return gateway != null && GatewayEligible && endpoint.Equals(gatewayEndpoint); }

    // Ownership transfers only after successful return. The caller must close a
    // rejected lease. Once attached, lifetime follows the final socket reference,
    // not the gathering token or the original Attempt/Prepared owner reference.
    public void AttachGateway(PortControlLease mapping)
    {
        lock (gate) {
            ObjectDisposedException.ThrowIf(disposed != 0 || resourceClosed, this);
            var observed = mapping.Snapshot;
            if (gateway != null || preparedAttached || begun != 0 || pathAttached || payloadReaders != 0 ||
                observed.Protocol != PortMappingProtocol.Udp || observed.Local != Local.ToString() || !mapping.Valid)
                throw new IOException("UDP 网关租约不属于当前未使用的 socket");
            gateway = mapping; gatewayEndpoint = mapping.External;
            gatewayMaintenance = MaintainGateway(mapping);
        }
    }
    async Task MaintainGateway(PortControlLease mapping)
    {
        try { await mapping.Maintain(stop.Token); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception ex) { lock (gate) gatewayFailure = ex.GetType().Name + ": " + ex.Message; }
        // Gateway loss withdraws a candidate. An already authenticated path is
        // judged by actual data/health, not destroyed merely by metadata loss.
    }
    async Task CloseGateway()
    {
        await gatewayMaintenance;
        if (gateway != null) await gateway.DisposeAsync();
    }
}
