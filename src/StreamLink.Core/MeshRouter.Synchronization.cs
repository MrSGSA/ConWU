namespace StreamLink.Core;

public sealed record MeshSyncFrame(int Slot,byte[] Payload);
public sealed partial class MeshRouter
{
    readonly Queue<MeshSyncFrame> synchronization=[];
    readonly Dictionary<int,(long At,int Count)> syncReceived=[];
    readonly Dictionary<int,long> syncSent=[];
    // Dedicated bounded metadata lane. It cannot consume keepalive admission,
    // impersonate an IP packet or write to Wintun. No unbounded event callbacks
    // run inside the routing guard.
    void ReceiveSynchronization(Peer peer,byte[] payload)
    {
        if(!profile.Pair.Direct||payload.Length is <24 or >MeshLink.Mtu)return;
        long now=Environment.TickCount64;
        var window=syncReceived.GetValueOrDefault(peer.Member.Slot);
        if(now-window.At>=5000)window=(now,0);
        if(window.Count>=64)return;
        syncReceived[peer.Member.Slot]=(window.At,window.Count+1);
        if(synchronization.Count<128)synchronization.Enqueue(new(peer.Member.Slot,payload));
    }
    public MeshSyncFrame[] DrainSynchronization()
    {
        lock(gate){var frames=synchronization.ToArray();synchronization.Clear();return frames;}
    }
    public bool SendSynchronization(int slot,ReadOnlySpan<byte> payload)
    {
        lock(gate){
            long now=Environment.TickCount64;
            if(!profile.Pair.Direct||payload.Length is <24 or >MeshLink.Mtu||!peers.TryGetValue(slot,out var peer)||!Healthy(peer)||now-syncSent.GetValueOrDefault(slot)<100)return false;
            syncSent[slot]=now;
            var frame=peer.Link.Synchronize(payload);
            return peer.Managed is {} managed?SendManaged(frame,managed.Active):Send(frame,peer.Active);
        }
    }
}
