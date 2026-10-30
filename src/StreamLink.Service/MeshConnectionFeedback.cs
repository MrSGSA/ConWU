using StreamLink.Core;

namespace StreamLink.Service;

internal sealed class MeshConnectionFeedback(Action<string> log)
{
    sealed class Observation(long now) { public long Since = now; public bool Connected, EverConnected; public string Reason = ""; }
    readonly Dictionary<int,Observation> peers = [];
    public MeshPeerStatus Observe(MeshPeerStatus peer, ConnectionProgress? attempt, bool freshRemote, long now)
    {
        if(!peers.TryGetValue(peer.Slot,out var prior))peers[peer.Slot]=prior=new(now);
        string reason = peer.Liveness?.Reason ?? "WaitingForPath";
        if(prior.Connected != peer.Connected || prior.Reason != reason) {
            if(prior.Connected != peer.Connected)prior.Since = now;
            log($"PeerHealth slot={peer.Slot} connected={peer.Connected} reason={reason} receiveAgeMs={peer.Liveness?.ReceiveAgeMs?.ToString()??"Unknown"} roundTripAgeMs={peer.Liveness?.RoundTripAgeMs?.ToString()??"Unknown"} sentBytes={peer.SentBytes} receivedBytes={peer.ReceivedBytes} droppedPackets={peer.DroppedPackets}");
            prior.Connected = peer.Connected; prior.Reason = reason;
        }
        if(peer.Connected) {
            prior.EverConnected = true;
            return peer with { Connection = new("Connected","已通过双向验证，可使用此设备的虚拟 IP 串流。",now-prior.Since) };
        }
        attempt ??= new("WaitingEntry",peer.Detail,CanRetry:true);
        string failure = reason switch {
            "ReturnPathTimedOut" => "仍能收到对端数据，但同路径往返验证已超时，正在恢复。",
            "ReceiveTimedOut" when prior.EverConnected => "超过 12 秒未收到有效数据，正在恢复直连。",
            "TransportExited" => "传输组件已退出，正在重新建立直连。",
            _ => ""
        };
        if(!freshRemote && !prior.EverConnected)attempt=new("WaitingPeer","尚未收到对端的有效上线信息。请确认另一台设备已启动并连接同一网络。",CanRetry:true);
        return peer with { Connection = attempt with {
            Phase = prior.EverConnected && attempt.Phase != "Retrying" ? "Recovering" : attempt.Phase,
            Detail = failure.Length > 0 ? failure + " " + attempt.Detail : attempt.Detail, ElapsedMs = now-prior.Since } };
    }
    public void Retain(IEnumerable<int> slots)
    {
        var current=slots.ToHashSet();foreach(int slot in peers.Keys.Where(s=>!current.Contains(s)).ToArray())peers.Remove(slot);
    }
}
