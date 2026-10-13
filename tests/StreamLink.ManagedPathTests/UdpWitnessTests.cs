using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

static class UdpWitnessTests
{
    internal static async Task<object> Run(Action<bool,string> check)
    {
        byte[] key=RandomNumberGenerator.GetBytes(32);Guid generation=Guid.NewGuid(),attempt=Guid.NewGuid();var aResources=new TraversalResources();var bResources=new TraversalResources();
        await using var a=UdpTraversal.Create(new(IPAddress.Loopback,0),generation,attempt,1,2,key,aResources);
        await using var b=UdpTraversal.Create(new(IPAddress.Loopback,0),Guid.NewGuid(),attempt,2,1,key,bResources);
        await using var c=UdpTraversal.Create(new(IPAddress.Loopback,0),Guid.NewGuid(),attempt,2,1,key,bResources);
        b.AuthorizePeerWitness(IPAddress.Loopback);c.AuthorizePeerWitness(IPAddress.Loopback);Guid held=a.SocketId;
        using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var first=await a.ObservePeerPort(b.Local,limit.Token);var second=await a.ObservePeerPort(c.Local,limit.Token);
        check(first.Mapped.Equals(a.Local)&&second.Mapped.Equals(a.Local)&&first.SocketId==held&&second.SocketId==held,"two actual authenticated peer ports witness the same held sender socket before data nomination");
        int[] ports=[b.Local.Port,c.Local.Port];var strong=UdpStableSourceEvidence.PeerPorts(a,generation,IPAddress.Loopback,ports,[first,second]);strong.Require(a,generation,a.Local,IPAddress.Loopback,ports);
        check(strong.Kind=="peer-ports"&&strong.Description.PeerScope=="127.0.0.1","production strong evidence factory accepts only the measured full peer-port scope");
        bool rejected=false;try{UdpStableSourceEvidence.PeerPorts(a,generation,IPAddress.Loopback,[b.Local.Port],[first,second]);}catch(IOException){rejected=true;}check(rejected,"extra/missing target scope cannot reuse the strong proof");
        await using var wrong=UdpTraversal.Create(new(IPAddress.Loopback,0),Guid.NewGuid(),attempt,2,1,RandomNumberGenerator.GetBytes(32),bResources);wrong.AuthorizePeerWitness(IPAddress.Loopback);
        rejected=false;try{await a.ObservePeerPort(wrong.Local,limit.Token);}catch(IOException ex){rejected=ex.Message.Contains("PeerPortWitnessUnavailable");}
        check(rejected&&a.ReceiveReady&&a.SocketId==held,"wrong peer key yields explicit unavailability without killing the shared receive loop or rebinding");
        await using var unready=UdpTraversal.Create(new(IPAddress.Loopback,0),Guid.NewGuid(),attempt,2,1,key,bResources);
        rejected=false;try{await a.ObservePeerPort(unready.Local,limit.Token);}catch(IOException ex){rejected=ex.Message.Contains("PeerPortWitnessUnavailable");}
        check(rejected,"a private peer without an authorized reachable witness is not assigned stable status");
        var initial=new[]{first,second,first with{Target=new(IPAddress.Parse("192.0.2.1"),3478)},second with{Target=new(IPAddress.Parse("198.51.100.1"),3478)}};
        var later=new[]{first with{ProbeStartedAt=initial.Max(i=>i.ProbeStartedAt)+1},second with{ProbeStartedAt=initial.Max(i=>i.ProbeStartedAt)+2}};
        var weak=UdpEmpiricalEvidenceProvider.Evaluate(a,generation,initial,later,false);
        check(weak.MappingStable&&!weak.ExperimentalAdmission&&!weak.IsStrongPeerPortProof,"empirical mapping stability remains disabled and cannot become a peer-port proof");
        var changed=UdpEmpiricalEvidenceProvider.Evaluate(a,generation,initial,[later[0],later[1] with{Mapped=new(IPAddress.Loopback,a.Local.Port==65535?65534:a.Local.Port+1)}],true);
        check(!changed.ExperimentalAdmission&&changed.Reason=="MappingChanged","independent changed holdout rejects the experimental mapping hypothesis");
        var stale=UdpEmpiricalEvidenceProvider.Evaluate(a,generation,initial,later.Select(i=>i with{NetworkGeneration=Guid.NewGuid()}).ToArray(),true);
        check(!stale.ExperimentalAdmission,"old or mixed generation cannot admit empirical exploration");
        check(aResources.Usage().OpenUdpResources==1&&bResources.Usage().OpenUdpResources==4,"all actual witness sockets remain accounted in the existing per-device resource pools");
        object Describe(NatObservation o)=>new{o.SocketId,o.NetworkGeneration,o.Protocol,local=o.Local.ToString(),target=o.Target.ToString(),mapped=o.Mapped.ToString(),o.ObservedAt};
        return new{socketResourceId=held,scope="Real Windows exclusive UDP sockets/authenticated witness responses and same-owner proof; STUN holdout evaluation uses explicit fixtures. No NAT4 WAN, no full probability strategy negotiation, no data throughput claim.",first=Describe(first),second=Describe(second),strong=strong.Description,empirical=weak};
    }
}
