using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

static class UdpExplorationTests
{
    public static async Task Run(Action<bool,string> check)
    {
        void Reject(Action run,string why){bool failed=false;try{run();}catch(Exception e)when(e is FormatException or CryptographicException or ArgumentException){failed=true;}check(failed,why);}
        var a=MeshIdentity.Create("https://example.com/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
        var ca=new MeshTraversalCapabilities(1,0,Guid.NewGuid(),[TraversalProfile.UdpDirect],UdpExploration:1);var cb=ca with{BootId=Guid.NewGuid()};
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),sequence=0;
        var stable=new MeshTraversalCandidate(Guid.NewGuid(),1,"192.0.2.1:42000","192.0.2.9:3478",now,now+12,CandidatePurpose.UdpDirect,
            Exploration:new(true,Guid.NewGuid(),"peer-ports",now,"43000,43001","192.0.2.2"));
        var hard=stable with{Id=Guid.NewGuid(),Endpoint="192.0.2.2:44000",Exploration=new(false,Guid.Empty,"",0,"43000,43001","")};
        await using var leader=MeshTraversalAttempt.Offer(a,b.Self,ca,cb,TraversalProfile.UdpDirect,stable,1,()=>++sequence);
        var offer=leader.Outbound!;MeshTraversalAttempt.ValidateOffer(b,a.Self,cb,ca,offer);
        check(true,"signed UDP exploration Offer requires bilateral independent capability");
        Reject(()=>MeshTraversalAttempt.ValidateOffer(b,a.Self,cb with{UdpExploration=0},ca,offer),"missing local UDP enhancement capability rejects Offer before resource collection");
        Reject(()=>MeshTraversalAttempt.ValidateOffer(b,a.Self,cb,ca with{UdpExploration=0},offer),"missing peer UDP enhancement capability rejects Offer");
        Reject(()=>MeshTraversal.Verify(a.Pair.Network,a.Self,b.Self,offer with{Candidate=stable with{Exploration=null}}),"signature binds exploration role and proof rather than only endpoint");
        await using var answer=MeshTraversalAttempt.Answer(b,a.Self,cb,ca,offer,hard,()=>++sequence);
        check(answer.Context.UdpExploration&&leader.Exploring,"complete signed pair creates the distinct exploration authentication context");
        var ordinary=answer.Context with{UdpExploration=false};
        check(!PathNomination.ContextDigest(ordinary).SequenceEqual(PathNomination.ContextDigest(answer.Context)),"exploration and ordinary UDP contexts cannot reuse authentication digests");
        _=new PathNomination(answer.Context,Guid.NewGuid(),1,TimeSpan.FromSeconds(11),true);
        check(true,"negotiated exploration admits only the remaining portion of its twelve-second nomination window");
        Reject(()=>new PathNomination(ordinary,Guid.NewGuid(),1,TimeSpan.FromSeconds(11),true),"ordinary UDP still rejects an eleven-second replacement window");
        Reject(()=>PathNomination.ContextDigest(answer.Context with{Profile=TraversalProfile.FakeTcpHttpSo}),"TCP cannot claim UDP exploration context semantics");
        foreach(string invalid in new[]{"43001,43000","43000,43000","043000","80","43000,","65536"})
            Reject(()=>MeshUdpExploration.Ports(invalid),"noncanonical or unbounded exploration target set rejected");
        Reject(()=>MeshUdpExploration.Pair(stable,stable with{Id=Guid.NewGuid()}),"two stable roles cannot select unrelated winning sockets");
        Reject(()=>MeshUdpExploration.Pair(hard,hard with{Id=Guid.NewGuid()}),"two unqualified strict roles do not activate a probability round");
        Reject(()=>MeshUdpExploration.Pair(stable,hard with{Exploration=hard.Exploration! with{Targets="43000,43002"}}),"peer-port proof must cover exactly the signed guess set");
        Reject(()=>MeshUdpExploration.Pair(stable,hard with{Endpoint="192.0.2.3:44000"}),"peer-specific source proof cannot authorize another public IP");
        Reject(()=>MeshUdpExploration.Validate(stable,TraversalProfile.FakeTcpHttpSo),"UDP probability permission cannot be interpreted as TCP prediction");
        Reject(()=>MeshUdpExploration.Validate(stable with{Endpoint="[2001:db8::1]:42000"},TraversalProfile.UdpDirect),"IPv6 does not use the IPv4 single-stable-endpoint model");
        check(!JsonSerializer.Serialize(ca with{UdpExploration=0}).Contains("UdpExploration")&&!JsonSerializer.Serialize(stable with{Exploration=null}).Contains("Exploration"),"inactive extensions do not alter legacy signing metadata");
        var profile=new DeviceProfile{UdpExploration=true,TraversalMode="legacy",AllowUdpFallback=false};Reject(profile.Validate,"explicit legacy mode cannot silently accept exploration configuration");
        profile.TraversalMode="tcp-udp";Reject(profile.Validate,"UDP exploration requires explicit fallback permission");profile.AllowUdpFallback=true;profile.Validate();check(true,"opt-in TCP/UDP fallback mode accepts configuration");
        profile.PathSelection="faketcp-only";Reject(profile.Validate,"FakeTcpOnly cannot activate UDP multi-source exploration");
        check(!new DeviceProfile().UdpExploration,"existing and new profiles keep UDP exploration disabled");
    }
}
