using System.Net;
using StreamLink.Core;
using System.Text.Json;

static partial class Program
{
    static async Task PreparedEvidence(string output){
        if(File.Exists(output))throw new IOException("Fresh evidence required");
        using var limit=new CancellationTokenSource(12000);var t=limit.Token;
        var a=MeshIdentity.Create("https://example.com/","","udp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));
        var ga=Guid.NewGuid();var gb=Guid.NewGuid();var attempt=Guid.NewGuid();var key=Key();
        await using var left=new UdpTraversal(new TraversalSocket(new(IPAddress.Loopback,0)),ga,attempt,1,2,key,new());
        await using var right=new UdpTraversal(new TraversalSocket(new(IPAddress.Loopback,0)),gb,attempt,2,1,key,new());
        var context=new TraversalAttemptContext(a.Pair.Network,a.Self.Device,Guid.NewGuid(),b.Self.Device,Guid.NewGuid(),attempt,Guid.NewGuid(),1,Guid.NewGuid(),1,TraversalProfile.UdpDirect,true,true,Guid.NewGuid());
        var reverse=context with{LocalNodeId=context.RemoteNodeId,RemoteNodeId=context.LocalNodeId,LocalBootId=context.RemoteBootId,RemoteBootId=context.LocalBootId,
            LocalCandidateId=context.RemoteCandidateId,RemoteCandidateId=context.LocalCandidateId,ProtocolClient=false,Nominator=false};
        await using var pa=left.PreparePath(context,ga,right.Local);await using var pb=right.PreparePath(reverse,gb,left.Local);
        var ea=(ITraversalCheckEvidence)pa;var eb=(ITraversalCheckEvidence)pb;
        Check(!ea.CheckEvidence.Executed&&!eb.CheckEvidence.Executed,"UDP Armed is not execution evidence");
        var paths=await Task.WhenAll(pa.Activate(t),pb.Activate(t));
        try{
            Check(ea.CheckEvidence.Executed&&eb.CheckEvidence.Executed,"same-socket UDP records completed actual sends after activation");
            Check(ea.CheckEvidence.SendsCompleted<=ea.CheckEvidence.SendAttempts&&eb.CheckEvidence.SendsCompleted<=eb.CheckEvidence.SendAttempts,"successful-send evidence never exceeds attempted control packets");
            await pa.DisposeAsync();await pb.DisposeAsync();
            byte[] payload=new byte[1344];Random.Shared.NextBytes(payload);Check(paths[0].TrySend(payload),"full payload admitted on retained path");
            var received=await paths[1].Receive(t);
            Check(received.Span.SequenceEqual(payload),"ending preparation preserves the winning socket and full payload");
            File.WriteAllText(output,JsonSerializer.Serialize(new{status="Pass",checks=5,left=ea.CheckEvidence,right=eb.CheckEvidence,socketA=left.SocketId,socketB=right.SocketId,
                scope="Real unconnected loopback UDP sockets, same-resource activation and retained full payload; no Wintun or public NAT claim"},new JsonSerializerOptions{WriteIndented=true}));
        }finally{foreach(var p in paths)await p.DisposeAsync();}
    }
}
