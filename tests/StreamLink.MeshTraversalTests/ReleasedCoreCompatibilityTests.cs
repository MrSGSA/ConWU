using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

// Loads the exact retained release library in a separate context. This checks
// real old parsing/crypto code, not a new DTO with a capability set to zero.
static class ReleasedCoreCompatibilityTests
{
    public static object Run(string file,Action<bool,string> check)
    {
        file=Path.GetFullPath(file);var context=new AssemblyLoadContext("streamlink-released-core-"+Guid.NewGuid(),true);
        try{
            var old=context.LoadFromAssemblyPath(file);
            Type Type(string name)=>old.GetType("StreamLink.Core."+name,true)!;
            object Convert(object value,string name)=>JsonSerializer.Deserialize(JsonSerializer.Serialize(value),Type(name))!;
            object Call(string type,string method,params object[] args)=>Type(type).GetMethod(method,BindingFlags.Public|BindingFlags.Static)!.Invoke(null,args)!;
            check(Type("MeshTraversalCapabilities").GetProperty("StandbyPaths")==null&&Type("MeshTraversalCapabilities").GetProperty("QualityFeedback")==null,
                "retained released Core actually predates the new standby and delivery capability fields");
            var a=MeshIdentity.Create("https://localhost/","","faketcp");var b=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(a)));b.Directory=a.Directory;
            var caps=new MeshTraversalCapabilities(1,1,Guid.NewGuid(),[TraversalProfile.FakeTcpHttpSo],QualityFeedback:1,StandbyPaths:1);
            long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var node=new MeshAnnouncement(a.Self.Slot,a.Self.Device,1,now+120,"192.0.2.1:40001","new",caps);
            var envelope=MeshMetadata.Seal(a,node);
            object parsed=Call("MeshMetadata","Open",Convert(b,"MeshProfile"),Convert(a.Self,"MeshMember"),Convert(envelope,"MeshEnvelope"));
            check((string)Type("MeshAnnouncement").GetProperty("Endpoint")!.GetValue(parsed)! == node.Endpoint,
                "actual old Core authenticates the opaque signed ciphertext and reads ordinary endpoint despite unknown encrypted capabilities");
            var oldCaps=Type("MeshAnnouncement").GetProperty("Traversal")!.GetValue(parsed)!;
            var observedOldCaps=JsonSerializer.Deserialize<MeshTraversalCapabilities>(JsonSerializer.Serialize(oldCaps,oldCaps.GetType()))!;
            check(observedOldCaps.StandbyPaths==0&&observedOldCaps.QualityFeedback==0,"old parser ignores extensions without accidentally granting their capabilities");
            var oldNode=Convert(node,"MeshAnnouncement");
            object oldEnvelope=Call("MeshMetadata","Seal",Convert(a,"MeshProfile"),oldNode);
            var decoded=MeshMetadata.Open(b,a.Self,JsonSerializer.Deserialize<MeshEnvelope>(JsonSerializer.Serialize(oldEnvelope,oldEnvelope.GetType()))!);
            check(decoded.Endpoint==node.Endpoint&&decoded.Traversal is{StandbyPaths:0,QualityFeedback:0},
                "new Core verifies and decrypts an announcement actually produced by the released signing implementation");
            long sequence=0;var other=caps with{BootId=Guid.NewGuid()};
            var candidate=new MeshTraversalCandidate(Guid.NewGuid(),1,"192.0.2.1:40001",null,now,now+120,CandidatePurpose.SimultaneousOpen);
            using var unused=new IDisposableAttempt(MeshTraversalAttempt.Offer(a,b.Self,caps,other,TraversalProfile.FakeTcpHttpSo,candidate,1,()=>++sequence));
            Call("MeshTraversal","Verify",a.Pair.Network,Convert(a.Self,"MeshMember"),Convert(b.Self,"MeshMember"),Convert(unused.Actor.Outbound!,"MeshTraversalMessage"));
            check(true,"actual released verifier accepts ordinary new Offer whose optional standby fields are absent");
            bool refused=false;try{MeshTraversalAttempt.Offer(a,b.Self,caps,observedOldCaps with{BootId=Guid.NewGuid()},TraversalProfile.FakeTcpHttpSo,candidate with{Standby=true},2,()=>++sequence,coordinatorStandby:true);}
            catch(CryptographicException){refused=true;}check(refused,"new standby Offer is rejected before endpoint allocation when actual old serialization supplies no standby capability");
            return new{sha256=System.Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(file))),oldAssemblyVersion=old.GetName().Version?.ToString(),
                scope="actual retained old Core metadata encryption/signing/parser and ordinary traversal verifier; no old service process, sockets, Wintun or network"};
        }finally{context.Unload();}
    }
    sealed class IDisposableAttempt(MeshTraversalAttempt actor):IDisposable
    {public MeshTraversalAttempt Actor=>actor;public void Dispose()=>actor.DisposeAsync().AsTask().GetAwaiter().GetResult();}
}
