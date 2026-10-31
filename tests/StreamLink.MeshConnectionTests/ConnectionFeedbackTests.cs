using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    static void ConnectionFeedback()
    {
        var feedback = new MeshConnectionFeedback(_ => { });
        var peer = new MeshPeerStatus(2,"10.81.7.2","Akane",false,null,"暂无入口");
        var offline = feedback.Observe(peer,null,false,100);
        Check(offline.Connection is { Phase:"Offline",CanRetry:false,ElapsedMs:0 },"an unannounced member is idle with no endless attempt timer");
        var empty = MeshConnectionFeedback.Summarize([],60000);
        Check(empty is { State:"网络已就绪",Connection.Phase:"Idle",Connection.CanRetry:false },"an empty network is ready without waiting for unused member slots");
        var idle = MeshConnectionFeedback.Summarize([offline],60000);
        Check(idle is { State:"网络已就绪",Connection.Phase:"Idle" },"offline members do not create an active connection summary");
        var connected = feedback.Observe(peer with { Connected=true,Liveness=new("Healthy",1,2) },null,false,200);
        Check(connected.Connection?.Phase == "Connected","authenticated health remains connected despite stale coordination metadata");
        connected = feedback.Observe(peer with { Connected=true,Liveness=new("Healthy",1,2) },null,false,800);
        var mixed = MeshConnectionFeedback.Summarize([connected,offline with { Slot=3 }],90000);
        Check(mixed is { State:"已直连",Connection.Phase:"Connected",Connection.ElapsedMs:600 } && mixed.Connection.Detail.Contains("1 台设备未在线"),
            "connected plus offline members stays connected, accurately lists offline peers and uses verified connection age");
        var lost = feedback.Observe(peer with { Liveness=new("ReceiveTimedOut",13000,13000) },null,false,900);
        Check(lost.Connection?.Phase == "Offline","a previously connected member with no current announcement or attempt settles to offline");
        var online = feedback.Observe(peer,new("Connecting","正在连接",RemainingSeconds:10,CanRetry:true),true,1000);
        Check(online.Connection?.Phase == "Recovering","an online returning member retains active recovery feedback");
        var first = new MeshConnectionFeedback(_ => { });
        var activeWait = first.Observe(peer,new("WaitingPeer","等待实际申请响应",RemainingSeconds:5,CanRetry:true),false,100);
        Check(activeWait.Connection is { Phase:"WaitingPeer",RemainingSeconds:5 },"stale metadata cannot hide an owned bounded handshake");
        foreach(string phase in new[]{"Preparing","Verifying","Releasing","Blocked","Retrying","Queued"}) {
            var work = first.Observe(peer,new(phase,"实际工作或错误",CanRetry:phase=="Retrying"),false,100);
            Check(work.Connection?.Phase == phase,"stale metadata preserves real work: "+phase);
        }
        var blocked = first.Observe(peer,new("Blocked","资源未能回收",CanRetry:false),false,100);
        var mixedError = MeshConnectionFeedback.Summarize([connected,blocked with { Slot=3 }],1000);
        Check(mixedError is { State:"部分设备已直连",Connection.Phase:"Blocked" },"a healthy peer cannot hide another peer's resource error");
        Check(MeshConnectionFeedback.Summarize([online,offline with { Slot=3 }],1000).Connection.Phase == "Recovering",
            "an idle peer does not replace an online peer's recovery progress");
    }
}
