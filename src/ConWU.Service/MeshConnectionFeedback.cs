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
            "ReturnPathTimedOut" => "仍能收到对端数据，但同路径往返验证已超时。",
            "ReceiveTimedOut" when prior.EverConnected => "超过 12 秒未收到有效数据。",
            "TransportExited" => "传输组件已退出。",
            _ => ""
        };
        // No fresh announcement and no timed attempt is an idle member, not
        // an unbounded connection attempt. Preserve owned work, retry budgets
        // and failed cleanup even if the remote announcement has expired.
        if(!freshRemote && attempt.RemainingSeconds == null && attempt.Phase is "WaitingEntry" or "WaitingPeer" or "Connecting")
            return peer with { Connection = new("Offline","尚未收到此设备的有效上线信息；上线后会自动连接。") { ReasonCode="NoFreshAnnouncement" } };
        return peer with { Connection = attempt with {
            Phase = prior.EverConnected && attempt.Phase is not ("Offline" or "Retrying" or "Queued" or "Releasing" or "Blocked") ? "Recovering" : attempt.Phase,
            Detail = failure.Length > 0 ? failure + " " + attempt.Detail : attempt.Detail, ElapsedMs = now-prior.Since } };
    }
    public static (string State, ConnectionProgress Connection) Summarize(MeshPeerStatus[] statuses, long elapsedMs)
    {
        int count = statuses.Count(p => p.Connected), offline = statuses.Count(p => !p.Connected && p.Connection?.Phase == "Offline");
        var pending = statuses.Where(p => !p.Connected && p.Connection?.Phase != "Offline").ToArray();
        if(pending.Length == 0) {
            if(count == 0) return ("网络已就绪", new("Idle",statuses.Length == 0
                ? "当前没有其他设备；需要时可在“添加设备”中邀请电脑。"
                : "已配对设备暂未在线，上线后会自动连接。") { ReasonCode=statuses.Length == 0 ? "NoPairedPeers" : "NoOnlinePeers" });
            string detail = offline == 0 ? "直连已通过双向验证，可复制设备 IP 开始串流。"
                : $"已直连 {count} 台设备，可开始使用；另有 {offline} 台设备未在线，上线后会自动连接。";
            long connectedMs = statuses.Where(p => p.Connected).Min(p => p.Connection?.ElapsedMs ?? elapsedMs);
            return (statuses.Any(p => p.Connected && p.Degraded) ? "已直连（含 UDP）" : "已直连", new("Connected",detail,connectedMs));
        }
        var waitingPeer = pending.OrderBy(p => p.Connection?.Phase switch {
            "Blocked"=>0,"Releasing"=>1,"Retrying"=>2,"Queued"=>3,_=>4 }).First();
        var waiting = waitingPeer.Connection ?? new("Connecting",waitingPeer.Detail,elapsedMs);
        var connection = waiting with {
            CanRetry=pending.Any(p => p.Connection?.CanRetry == true),
            Detail=statuses.Length > 1 ? (string.IsNullOrWhiteSpace(waitingPeer.Name) ? "设备 "+waitingPeer.Slot : waitingPeer.Name)+"："+waiting.Detail : waiting.Detail };
        string state = count > 0 ? "部分设备已直连" : connection.Phase switch {
            "Blocked"=>"有设备需要处理","Releasing"=>"正在回收连接资源","Retrying"=>"等待重试",
            "Queued"=>"等待连接名额","WaitingPeer"=>"等待设备响应",_=>"正在连接" };
        return (state,connection);
    }
    public void Retain(IEnumerable<int> slots)
    {
        var current=slots.ToHashSet();foreach(int slot in peers.Keys.Where(s=>!current.Contains(s)).ToArray())peers.Remove(slot);
    }
}
