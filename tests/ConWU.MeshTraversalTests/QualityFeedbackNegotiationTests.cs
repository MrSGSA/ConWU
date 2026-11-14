using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class QualityFeedbackNegotiationTests
{
    public static async Task Run(Action<bool,string> check)
    {
        var a=MeshIdentity.Create("https://example.com/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var mine=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo],QualityFeedback:1);
        var theirs=mine with{BootId=Guid.NewGuid()};long seq=0,now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var candidate=new MeshTraversalCandidate(Guid.NewGuid(),1,"192.0.2.1:43000","192.0.2.9:3478",now,now+120,CandidatePurpose.SimultaneousOpen);
        foreach(string mode in new[]{"both","old-peer","old-local","old-server"}){
            var local=mode=="old-local"?mine with{QualityFeedback=0}:mine;
            var remote=mode=="old-peer"?theirs with{QualityFeedback=0}:theirs;
            await using var offer=MeshTraversalAttempt.Offer(a,b.Self,local,remote,TraversalProfile.FakeTcpHttpSo,candidate,1,()=>++seq,coordinatorQuality:mode!="old-server");
            await using var answer=MeshTraversalAttempt.Answer(b,a.Self,remote,local,offer.Outbound!,candidate with{Id=Guid.NewGuid(),Endpoint="192.0.2.2:43001"},()=>++seq,coordinatorQuality:mode!="old-server");
            check(offer.QualityFeedbackNegotiated==(mode=="both")&&answer.QualityFeedbackNegotiated==(mode=="both"),
                "authenticated attempt captures bilateral/server delivery permission: "+mode);
        }
        bool rejected=false;try{MeshTraversal.ValidateCapabilities(mine with{QualityFeedback=2});}catch(FormatException){rejected=true;}
        check(rejected,"unknown receipt capability version is not interpreted as permission");
        check(!JsonSerializer.Serialize(mine with{QualityFeedback=0}).Contains("QualityFeedback"),"ordinary capability serialization omits the new field and preserves its old signing shape");
        var announcement=new MeshAnnouncement(a.Self.Slot,a.Self.Device,1,now+120,"192.0.2.1:43000","test",mine);
        var sealedMessage=MeshMetadata.Seal(a,announcement);
        check(MeshMetadata.Open(b,a.Self,sealedMessage).Traversal!.QualityFeedback==1,"encrypted member-signed announcement authenticates the independent delivery capability");
        rejected=false;try{MeshMetadata.Open(b,a.Self,sealedMessage with{Data=sealedMessage.Data[..^1]+(sealedMessage.Data[^1]=='A'?'B':'A')});}catch(Exception ex)when(ex is CryptographicException or FormatException){rejected=true;}
        check(rejected,"modified receipt capability ciphertext cannot replace a signed announcement");
        check(!new DeviceProfile().QualityFeedback&&new ControlReply(true,"",null,null,"",[]).QualityFeedbackVersion==0,"old profile/IPC defaults are off rather than silently approving control overhead");
        rejected=false;try{new DeviceProfile{QualityFeedback=true,TraversalMode="legacy"}.Validate();}catch(FormatException){rejected=true;}
        check(rejected,"compatible unmanaged mode cannot hold an invisible receipt experiment");
        var timed=mine with{StandbyPaths=1,PathDiagnostics=1,DiagnosticMbps=50,DiagnosticTiming=1};
        var timedRemote=timed with{BootId=theirs.BootId};var standby=candidate with{Standby=true};
        foreach(string mode in new[]{"both","old-peer","old-local","old-server"}){
            var local=mode=="old-local"?timed with{DiagnosticTiming=0}:timed;
            var remote=mode=="old-peer"?timedRemote with{DiagnosticTiming=0}:timedRemote;
            await using var offer=MeshTraversalAttempt.Offer(a,b.Self,local,remote,TraversalProfile.FakeTcpHttpSo,standby,2,()=>++seq,
                coordinatorStandby:true,coordinatorDiagnostics:true,coordinatorTiming:mode!="old-server");
            await using var answer=MeshTraversalAttempt.Answer(b,a.Self,remote,local,offer.Outbound!,standby with{Id=Guid.NewGuid(),Endpoint="192.0.2.2:43001"},()=>++seq,
                coordinatorStandby:true,coordinatorDiagnostics:true,coordinatorTiming:mode!="old-server");
            check(offer.DiagnosticTimingNegotiated==(mode=="both"?1:0)&&answer.DiagnosticTimingNegotiated==offer.DiagnosticTimingNegotiated,
                "authenticated bilateral/coordinator baseline timing permission: "+mode);
        }
        var timedEnvelope=MeshMetadata.Seal(a,announcement with{Traversal=timed});
        check(MeshMetadata.Open(b,a.Self,timedEnvelope).Traversal!.DiagnosticTiming==1,"baseline timing permission is encrypted and signed in the member announcement");
        rejected=false;try{MeshTraversal.ValidateCapabilities(timed with{PathDiagnostics=0,DiagnosticMbps=0});}catch(FormatException){rejected=true;}
        check(rejected,"baseline permission cannot exist without the separately authorized diagnostic profile");
        check(!JsonSerializer.Serialize(timed with{DiagnosticTiming=0}).Contains("DiagnosticTiming"),"absent timing capability preserves legacy metadata canonical shape");
    }
}
