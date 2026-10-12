using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class DiagnosticNegotiationTests
{
    public static async Task Run(Action<bool,string> check)
    {
        var a=MeshIdentity.Create("https://localhost/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var mine=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo],StandbyPaths:1,PathDiagnostics:1,DiagnosticMbps:50);
        var theirs=mine with{BootId=Guid.NewGuid()};long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),sequence=0;
        var candidate=new MeshTraversalCandidate(Guid.NewGuid(),1,"127.0.0.1:40001",null,now,now+120,CandidatePurpose.SimultaneousOpen,Standby:true);
        foreach(string mode in new[]{"both","old-peer","old-server","goal-mismatch","ordinary"}){
            var remote=mode=="old-peer"?theirs with{PathDiagnostics=0,DiagnosticMbps=0}:mode=="goal-mismatch"?theirs with{DiagnosticMbps=40}:theirs;
            var c=candidate with{Standby=mode!="ordinary"};
            await using var offer=MeshTraversalAttempt.Offer(a,b.Self,mine,remote,TraversalProfile.FakeTcpHttpSo,c,1,()=>++sequence,coordinatorStandby:true,coordinatorDiagnostics:mode!="old-server");
            await using var answer=MeshTraversalAttempt.Answer(b,a.Self,remote,mine,offer.Outbound!,c with{Id=Guid.NewGuid(),Endpoint="127.0.0.1:40002"},()=>++sequence,coordinatorStandby:true,coordinatorDiagnostics:mode!="old-server");
            check(offer.DiagnosticMbpsNegotiated==(mode=="both"?50:0)&&answer.DiagnosticMbpsNegotiated==(mode=="both"?50:0),
                mode+": diagnostic permission independently captures matching bilateral target and server grant only for standby");
        }
        bool rejected=false;try{MeshTraversal.ValidateCapabilities(mine with{PathDiagnostics=0});}catch(FormatException){rejected=true;}
        check(rejected,"target cannot be advertised without diagnostic version permission");
        rejected=false;try{MeshTraversal.ValidateCapabilities(mine with{StandbyPaths=0});}catch(FormatException){rejected=true;}
        check(rejected,"diagnostic capability cannot omit the authenticated standby lifecycle it depends on");
        check(!JsonSerializer.Serialize(mine with{PathDiagnostics=0,DiagnosticMbps=0}).Contains("PathDiagnostics")&&!new DeviceProfile().PathDiagnostics,
            "old profile and ordinary metadata do not enable high-rate probes");
        rejected=false;try{new DeviceProfile{TraversalMode="tcp",StandbyPaths=true,PathDiagnostics=true,ManagedEgressMbps=50}.Validate();}catch(FormatException){rejected=true;}
        check(rejected,"50Mbps target cannot silently overbook a 50Mbps whole-IP shared egress budget");
        new DeviceProfile{TraversalMode="tcp",StandbyPaths=true,PathDiagnostics=true,ManagedEgressMbps=70}.Validate();check(true,"validated opt-in has explicit shared wire headroom");
    }
}
