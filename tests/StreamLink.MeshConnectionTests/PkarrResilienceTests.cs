using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class PkarrRaceGateway(byte[] current,byte[]? stale=null):HttpMessageHandler
    {
        public bool StallSecond,StallAll;public int Pending,Cancelled;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            Interlocked.Increment(ref Pending);
            try{
                bool second=request.RequestUri!.Host.StartsWith("two.",StringComparison.Ordinal);
                if(StallAll||second&&StallSecond)try{await Task.Delay(Timeout.Infinite,token);}catch(OperationCanceledException){Interlocked.Increment(ref Cancelled);throw;}
                if(second&&stale!=null)await Task.Delay(400,token);
                return new(HttpStatusCode.OK){Content=new ByteArrayContent(second||stale==null?current:stale)};
            }finally{Interlocked.Decrement(ref Pending);}
        }
    }
    static async Task PkarrResilience()
    {
        string seed=PkarrPacket.NewSeed(),source=PkarrPacket.Source(seed),key=PkarrPacket.KeyFromSource(source);long sequence=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
        var address=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),["203.0.113.8:44680"]);
        byte[] old=PkarrPacket.Create(seed,sequence,address),current=PkarrPacket.Create(seed,sequence+1,address with{Endpoints=["203.0.113.9:44680"]});
        using(var gateway=new PkarrRaceGateway(current){StallSecond=true})using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test","https://two.test"],TimeSpan.FromSeconds(3),new())){
            var clock=System.Diagnostics.Stopwatch.StartNew();var found=await client.ResolveRecord(source,"faketcp",default);
            Check(found.Sequence==sequence+1&&clock.Elapsed<TimeSpan.FromSeconds(1.5),"a responsive signed gateway is not held for the stalled gateway's entire deadline");
            Check(gateway.Pending==0&&gateway.Cancelled==1,"losing gateway requests are cancelled and joined before returning success");
        }
        var records=Array.Empty<PkarrCheckpoint>();int writes=0;
        var reconciliation=new PkarrCheckpoints();reconciliation.Remember(key,PkarrPacket.Read(key,old,DateTimeOffset.UtcNow));
        using(var gateway=new PkarrRaceGateway(current,old))using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test","https://two.test"],TimeSpan.FromSeconds(2),reconciliation)){
            var first=await client.ResolveRecord(source,"faketcp",default);var second=await client.ResolveRecord(source,"faketcp",default);var third=await client.ResolveRecord(source,"faketcp",default);
            Check(first.Sequence==sequence&&second.Sequence==sequence&&third.Sequence==sequence+1,"periodic reconciliation prevents a fast unchanged cache from starving a slower gateway with a new address");
        }
        var durable=new PkarrCheckpoints(()=>records,items=>{records=items;writes++;});
        durable.Remember(key,PkarrPacket.Read(key,current,DateTimeOffset.UtcNow));
        using(var gateway=new PkarrRaceGateway(current,old))using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test","https://two.test"],TimeSpan.FromSeconds(2),new(()=>records,items=>records=items))){
            var clock=System.Diagnostics.Stopwatch.StartNew();var found=await client.ResolveRecord(source,"faketcp",default);
            Check(found.Sequence==sequence+1&&clock.Elapsed>=TimeSpan.FromMilliseconds(350),"a fast rollback response cannot suppress a slower gateway with the persisted latest record");
        }
        using(var gateway=new PkarrRaceGateway(old))using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test"],checkpoints:new(()=>records))){
            bool rejected=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){rejected=true;}
            Check(rejected&&writes==1,"a fresh client restores the persisted high-water mark and rejects a formerly valid address");
        }
        var conflicting=PkarrPacket.Create(seed,sequence+1,address with{Endpoints=["203.0.113.99:44680"]});
        using(var gateway=new SplitGateway(current,conflicting))using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test","https://two.test"],checkpoints:new())){
            bool rejected=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){rejected=true;}
            Check(rejected,"same-sequence conflicts are rejected inside the bounded gateway collection window");
        }
        bool fail=true;var transactional=new PkarrCheckpoints(write:_=>{if(fail)throw new IOException("fixture disk unavailable");});
        bool failed=false;try{transactional.Remember(key,PkarrPacket.Read(key,current,DateTimeOffset.UtcNow));}catch(IOException){failed=true;}
        Check(failed&&transactional.Accepts(key,PkarrPacket.Read(key,old,DateTimeOffset.UtcNow)),"a failed checkpoint commit does not mutate the in-memory accepted state");
        fail=false;transactional.Remember(key,PkarrPacket.Read(key,current,DateTimeOffset.UtcNow));
        Check(!transactional.Accepts(key,PkarrPacket.Read(key,old,DateTimeOffset.UtcNow)),"a successful checkpoint commit protects the subsequent query");
        using(var gateway=new PkarrRaceGateway(current){StallAll=true})using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test","https://two.test"],checkpoints:new()))using(var cancelled=new CancellationTokenSource(50)){
            bool wasCancelled=false;try{await client.Resolve(source,"faketcp",cancelled.Token);}catch(OperationCanceledException){wasCancelled=true;}
            Check(wasCancelled&&gateway.Pending==0&&gateway.Cancelled==2,"explicit cancellation stops and joins every gateway without returning an old success");
        }
        var wrongProtocol=PkarrPacket.Create(seed,sequence+2,address with{Mode="udp"});
        var unpoisoned=new PkarrCheckpoints();
        using(var gateway=new PkarrRaceGateway(wrongProtocol))using(var http=new HttpClient(gateway))using(var client=new PkarrClient(http,["https://one.test"],checkpoints:unpoisoned)){
            bool rejected=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){rejected=true;}
            Check(rejected&&unpoisoned.Accepts(key,PkarrPacket.Read(key,current,DateTimeOffset.UtcNow)),"a rejected protocol cannot advance a different protocol's accepted checkpoint");
        }
        PkarrStateCryptography();
        var owner=MeshIdentity.Create("","","faketcp",direct:true);var peer=Guest(owner);
        var live=new DeviceProfile{Device=owner.Self.Device,Mesh=owner,PkarrSeed=seed,PkarrSequence=10,PkarrPeers=[new(owner.Pair.Network,peer.Self.Slot,peer.Self.Device,peer.Self.SigningKey,source)],PkarrStateVersion=1};
        var draft=ProfileChanges.Copy(live);draft.DeviceName="Saved name";draft.PkarrSeed="";draft.PkarrSequence=0;draft.PkarrPeers=[];draft.PkarrStateVersion=0;live.PkarrSequence=20;
        ProfileChanges.PreserveLatestDirectory(live,draft);
        Check(draft.DeviceName=="Saved name"&&draft.PkarrSeed==live.PkarrSeed&&draft.PkarrSequence==20&&draft.PkarrPeers.SequenceEqual(live.PkarrPeers)&&draft.PkarrStateVersion==1,"a settings draft cannot overwrite discovery identity, peer binding or sequence completed after the draft was opened");
        var restored=PairSettingsTransaction.SettingsOnly(live,new DeviceProfile());
        Check(restored.PkarrSeed==live.PkarrSeed&&restored.PkarrPeers.SequenceEqual(live.PkarrPeers)&&restored.PkarrStateVersion==1,"settings rollback keeps current discovery observations independently of the rolled-back preferences");
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));var store=new ProfileStore(Path.Combine(ProfileStore.Root,"checkpoint"));
        var protectedStore=new PkarrCheckpoints(()=>store.ReadPrivate<PkarrCheckpoint[]>("pkarr-checkpoints.protected")??[],items=>store.WritePrivate("pkarr-checkpoints.protected",items));
        protectedStore.Remember(key,PkarrPacket.Read(key,current,DateTimeOffset.UtcNow));
        var reopened=new PkarrCheckpoints(()=>store.ReadPrivate<PkarrCheckpoint[]>("pkarr-checkpoints.protected")??[]);
        Check(!reopened.Accepts(key,PkarrPacket.Read(key,old,DateTimeOffset.UtcNow)),"protected on-disk checkpoint survives reopening the actual profile store");
        Console.WriteLine($"PASS {checks} PKARR resilience checks; local gateways and protected validation store only");
    }
    static void PkarrStateCryptography()
    {
        var host=MeshIdentity.Create("","","faketcp",direct:true);var guest=Guest(host);string hostSource=PkarrPacket.Source(PkarrPacket.NewSeed()),guestSource=PkarrPacket.Source(PkarrRendezvous.MemberSeed(guest));
        long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();var first=new PkarrAnnouncement(1,"faketcp",now+3600,["203.0.113.8:44680"]);
        var hostState=new PkarrPeerState(Guid.NewGuid(),Guid.Empty,now,now+180,"主机");
        var sealedHost=first with{State=PkarrRendezvous.Seal(host,guest.Self,hostSource,first,hostState)};
        var opened=PkarrRendezvous.Open(guest,host.Self,hostSource,sealedHost);
        Check(opened.Boot==hostState.Boot&&opened.Entry==PkarrRendezvous.EntryId(hostSource,first,hostState.Boot),"approved pair derives an encrypted state channel bound to its current endpoint version");
        var second=first with{Endpoints=["203.0.113.9:44681"]};
        var guestState=new PkarrPeerState(Guid.NewGuid(),opened.Boot,now,now+180,"从机"){AcknowledgedEntry=opened.Entry};
        var sealedGuest=second with{State=PkarrRendezvous.Seal(guest,host.Self,guestSource,second,guestState)};
        var acknowledged=PkarrRendezvous.Open(host,guest.Self,guestSource,sealedGuest);
        Check(acknowledged.AcknowledgedBoot==hostState.Boot&&acknowledged.AcknowledgedEntry==opened.Entry,"peer acknowledgement identifies the exact boot and endpoint content, independently of heartbeat sequence");
        Check(guestSource==PkarrPacket.Source(PkarrRendezvous.MemberSeed(guest))&&guestSource!=hostSource,"the guest's independent discovery identity is stable across reconstruction and distinct from its host");
        foreach(var changed in new[]{sealedHost with{Mode="udp"},sealedHost with{Expires=first.Expires+1},sealedHost with{Endpoints=second.Endpoints}}){
            bool rejected=false;try{PkarrRendezvous.Open(guest,host.Self,hostSource,changed);}catch(CryptographicException){rejected=true;}Check(rejected,"authenticated state cannot be transplanted to another protocol, expiry or endpoint list");
        }
        bool wrongSource=false;try{PkarrRendezvous.Open(guest,host.Self,guestSource,sealedHost);}catch(CryptographicException){wrongSource=true;}Check(wrongSource,"state cannot be transplanted to another PKARR public key");
        var other=MeshIdentity.Create("","","faketcp",direct:true);var otherGuest=Guest(other);bool wrongNetwork=false;
        try{PkarrRendezvous.Open(otherGuest,other.Self,hostSource,sealedHost);}catch(CryptographicException){wrongNetwork=true;}Check(wrongNetwork,"state from a different approved pair cannot authenticate in this network");
        string seed=PkarrPacket.NewSeed(),source=PkarrPacket.Source(seed);var maximum=first with{Endpoints=Enumerable.Range(1,8).Select(i=>$"203.0.113.{i}:65535").ToArray()};
        maximum=maximum with{State=PkarrRendezvous.Seal(host,guest.Self,source,maximum,hostState with{Name=new string('机',64)})};
        byte[] wire=PkarrPacket.Create(seed,DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000,maximum);
        Check(wire.Length<=1072&&PkarrRendezvous.Open(guest,host.Self,source,PkarrPacket.Read(PkarrPacket.KeyFromSource(source),wire,DateTimeOffset.UtcNow).Announcement).Name.Length==64,"maximum names and eight candidates fit a real signed PKARR packet without oversized public records");
    }
}
