using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class StandbyNegotiationTests
{
    public static async Task Run(Action<bool,string> check)
    {
        var a=MeshIdentity.Create("https://localhost/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var mine=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo],StandbyPaths:1);var theirs=mine with{BootId=Guid.NewGuid()};
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),sequence=0;
        var c=new MeshTraversalCandidate(Guid.NewGuid(),1,"127.0.0.1:40001",null,now,now+120,CandidatePurpose.SimultaneousOpen,Standby:true);
        void Reject(Action action,string why){bool rejected=false;try{action();}catch(Exception ex)when(ex is CryptographicException or FormatException){rejected=true;}check(rejected,why);}
        await using var offer=MeshTraversalAttempt.Offer(a,b.Self,mine,theirs,TraversalProfile.FakeTcpHttpSo,c,1,()=>++sequence,coordinatorStandby:true);
        await using var answer=MeshTraversalAttempt.Answer(b,a.Self,theirs,mine,offer.Outbound!,c with{Id=Guid.NewGuid(),Endpoint="127.0.0.1:40002"},()=>++sequence,coordinatorStandby:true);
        check(offer.StandbyNegotiated&&answer.StandbyNegotiated&&answer.Context.Standby,"authenticated responder preserves standby resource purpose in the actual path context");
        Reject(()=>MeshTraversalAttempt.ValidateOffer(b,a.Self,theirs,mine,offer.Outbound!),"server permission is required before standby responder allocation");
        Reject(()=>MeshTraversalAttempt.ValidateOffer(b,a.Self,theirs with{StandbyPaths=0},mine,offer.Outbound!,true),"old peer cannot authorize standby from the ordinary traversal version");
        Reject(()=>MeshTraversalAttempt.Answer(b,a.Self,theirs,mine,offer.Outbound!,c with{Id=Guid.NewGuid(),Standby=false},()=>++sequence,coordinatorStandby:true),"standby Offer cannot be answered with an automatically selected candidate");
        Reject(()=>MeshTraversal.ValidateCapabilities(mine with{StandbyPaths=2}),"unknown standby capability versions are rejected");
        check(!JsonSerializer.Serialize(mine with{StandbyPaths=0}).Contains("StandbyPaths")&&!JsonSerializer.Serialize(c with{Standby=false}).Contains("Standby"),"ordinary signed shapes omit standby defaults for old-peer compatibility");
        check(!new DeviceProfile().StandbyPaths&&new ControlReply(true,"",null,null,"",[]).StandbyPathsVersion==0,"old profile and backend reply never opt into retained resources");
        Reject(()=>new DeviceProfile{StandbyPaths=true}.Validate(),"legacy ownership cannot silently enable retained managed standby");
        var message=offer.Outbound! with{Stage=MeshTraversalStage.Standby,PeerCandidate=c with{Id=Guid.NewGuid()}};
        MeshTraversal.ValidateShape(message);
        check(MeshTraversal.Context(a.Pair.Network,message,true).Standby,"standby reconciliation binds candidate purpose into the path authentication digest");
        Reject(()=>MeshTraversal.ValidateShape(message with{PeerCandidate=message.PeerCandidate! with{Standby=false}}),"a signed standby candidate pair must have the same purpose");
        Reject(()=>MeshTraversal.ValidateShape(message with{Candidate=c with{Standby=false},PeerCandidate=message.PeerCandidate! with{Standby=false}}),"ordinary candidates cannot report standby status");
    }
}
