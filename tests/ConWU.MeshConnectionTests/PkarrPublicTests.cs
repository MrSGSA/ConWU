using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task PkarrPublicDuplex(string output)
    {
        var host=MeshIdentity.Create("","","faketcp",direct:true);var guest=Guest(host);
        string hostSeed=PkarrPacket.NewSeed(),guestSeed=PkarrRendezvous.MemberSeed(guest),hostSource=PkarrPacket.Source(hostSeed),guestSource=PkarrPacket.Source(guestSeed);
        var timer=System.Diagnostics.Stopwatch.StartNew();bool initial=false,changed=false,acknowledged=false;int acceptedHost=0,acceptedGuest=0;string error="";
        try{
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(110));using var client=new PkarrClient(checkpoints:new());
            long Sequence()=>DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
            var announcement=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),["203.0.113.44:44680"]);
            var state=new PkarrPeerState(Guid.NewGuid(),Guid.Empty,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds(),"Public test");
            announcement=announcement with{State=PkarrRendezvous.Seal(host,guest.Self,hostSource,announcement,state)};
            acceptedHost=await client.Publish(hostSeed,PkarrPacket.Create(hostSeed,Sequence(),announcement),stop.Token);
            async Task<PkarrRecord> Lookup(string source,Func<PkarrRecord,bool> accept){
                for(int i=0;i<10;i++){
                    try{var record=await client.ResolveRecord(source,"faketcp",stop.Token);if(accept(record))return record;}catch(IOException){}
                    await Task.Delay(1000,stop.Token);
                }
                throw new IOException("公开 PKARR 网关尚未返回本次更新的有效公告");
            }
            var first=await Lookup(hostSource,r=>r.Announcement.Endpoints.SequenceEqual(announcement.Endpoints));
            initial=PkarrRendezvous.Open(guest,host.Self,hostSource,first.Announcement).Boot==state.Boot;
            Check(initial,"public PKARR gateways carry the encrypted peer state inside a verified standard signed DNS record");
            var next=announcement with{Endpoints=["203.0.113.45:44681"],State=null};
            next=next with{State=PkarrRendezvous.Seal(host,guest.Self,hostSource,next,state with{ObservedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),Expires=DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds()})};
            acceptedHost=await client.Publish(hostSeed,PkarrPacket.Create(hostSeed,Sequence(),next),stop.Token);
            var found=await Lookup(hostSource,r=>r.Announcement.Endpoints.SequenceEqual(next.Endpoints));var hostState=PkarrRendezvous.Open(guest,host.Self,hostSource,found.Announcement);changed=hostState.Entry==PkarrRendezvous.EntryId(hostSource,next,state.Boot);
            Check(changed,"an updated address and its exact encrypted entry version are retrieved through the same public key");
            var reply=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),["203.0.113.46:44682"]);
            var response=new PkarrPeerState(Guid.NewGuid(),hostState.Boot,DateTimeOffset.UtcNow.ToUnixTimeSeconds(),DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds(),"Public test peer"){AcknowledgedEntry=hostState.Entry};
            reply=reply with{State=PkarrRendezvous.Seal(guest,host.Self,guestSource,reply,response)};
            acceptedGuest=await client.Publish(guestSeed,PkarrPacket.Create(guestSeed,Sequence(),reply),stop.Token);
            var returned=await Lookup(guestSource,r=>r.Announcement.State!=null);var ack=PkarrRendezvous.Open(host,guest.Self,guestSource,returned.Announcement);
            acknowledged=ack.AcknowledgedBoot==state.Boot&&ack.AcknowledgedEntry==hostState.Entry;
            Check(acknowledged,"the independent peer record returns an authenticated acknowledgement of the host's new address");
        }catch(Exception ex){error=ex.Message;throw;}
        finally{
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status=initial&&changed&&acknowledged?"Pass":"Fail",checkedAt=DateTimeOffset.UtcNow,elapsedMs=timer.ElapsedMilliseconds,gateways=PkarrClient.DefaultGateways,acceptedHost,acceptedGuest,initial,changed,acknowledged,error,
                scope="Ephemeral identities, documentation-only addresses; public HTTPS gateway publication, signature verification and encrypted two-way discovery. No installed profile, physical peer NAT, Moonlight or traffic load test."},new JsonSerializerOptions{WriteIndented=true}));
        }
    }
    // Explicit, optional live test. Uses an ephemeral key and documentation-only
    // candidate addresses, never an installed identity or the user's endpoints.
    static async Task PkarrPublicTests(string output)
    {
        string seed=PkarrPacket.NewSeed(),source=PkarrPacket.Source(seed);var watch=System.Diagnostics.Stopwatch.StartNew();
        int accepted=0,updated=0;bool first=false,changed=false;string error="";
        try{
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(90));using var client=new PkarrClient();
            long sequence=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
            var announcement=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds(),["203.0.113.44:44680"]);
            accepted=await client.Publish(seed,PkarrPacket.Create(seed,sequence,announcement),deadline.Token);
            for(int attempt=0;attempt<4;attempt++){
                try{first=(await client.Resolve(source,"faketcp",deadline.Token)).SequenceEqual(announcement.Endpoints);}catch(IOException){}
                if(first)break;await Task.Delay(1000,deadline.Token);
            }
            Check(first,"public PKARR HTTPS gateways accept and return a verified standard signed record");
            var next=announcement with{Endpoints=["203.0.113.45:44681"]};
            updated=await client.Publish(seed,PkarrPacket.Create(seed,Math.Max(sequence+1,DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000),next),deadline.Token);
            for(int attempt=0;attempt<4;attempt++){
                try{changed=(await client.Resolve(source,"faketcp",deadline.Token)).SequenceEqual(next.Endpoints);}catch(IOException){}
                if(changed)break;await Task.Delay(1000,deadline.Token);
            }
            Check(changed,"the same public discovery key returns the changed address after a new publication");
        }catch(Exception ex){error=ex.Message;throw;}
        finally{
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status=first&&changed?"Pass":"Fail",checkedAt=DateTimeOffset.UtcNow,elapsedMs=watch.ElapsedMilliseconds,
                source,gateways=PkarrClient.DefaultGateways,firstAccepted=accepted,updateAccepted=updated,firstResolved=first,changedAddressResolved=changed,error,
                scope="Public HTTPS PKARR publication and signed address-change lookup only. Documentation addresses and ephemeral key; no installed profile, peer NAT traversal or streaming tested."},new JsonSerializerOptions{WriteIndented=true}));
        }
    }
}
