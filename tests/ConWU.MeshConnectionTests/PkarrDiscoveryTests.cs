using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class PkarrGateway:HttpMessageHandler
    {
        public byte[]? Packet;public bool Offline;public int Publications;public string LastKey="";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            token.ThrowIfCancellationRequested();LastKey=request.RequestUri!.AbsolutePath[1..];
            if(Offline)return new(HttpStatusCode.ServiceUnavailable);
            if(request.Method==HttpMethod.Put){Packet=await request.Content!.ReadAsByteArrayAsync(token);Publications++;return new(HttpStatusCode.NoContent);}
            return Packet==null?new(HttpStatusCode.NotFound):new(HttpStatusCode.OK){Content=new ByteArrayContent(Packet)};
        }
    }
    static async Task PkarrDiscoveryTests()
    {
        DiscoveryPolicyTests();
        // RFC 8032's public test seed, never an actual application identity.
        string seed=Convert.ToBase64String(Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        string key=PkarrPacket.PublicKey(seed),source="pkarr://"+key;
        Check(Convert.ToHexString(PkarrPacket.DecodeKey(key)).Equals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",StringComparison.OrdinalIgnoreCase),"PKARR Ed25519 public key matches RFC 8032 independently published vector");
        ExistingEntryResolver.Validate([new(ExistingEntry.NetworkOwner,source)]);
        var full=new UiNetworkSettings{ConnectionSource="existing",DirectMode=true,ExistingEntries=Enumerable.Range(1,12).Select(i=>new ExistingEntry(0,$"203.0.113.{i}:8436")).ToArray()};
        Check(ConnectionSettings.Normalize(full).ExistingEntries.Length==12,"existing twelve-source configurations remain valid when PKARR is disabled");
        bool capacity=false;try{ConnectionSettings.Normalize(full with{PkarrPublish=true});}catch(FormatException ex){capacity=ex.Message.Contains("11 项本机入口");}
        Check(capacity,"PKARR source capacity is checked before saving rather than failing during approval");
        Check(ConnectionSettings.Normalize(full with{PkarrPublish=true,ExistingEntries=full.ExistingEntries.Take(11).ToArray()}).PkarrPublish,"eleven sources leave room for the signed discovery hint");
        long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;var announcement=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),["203.0.113.1:8436"]);
        byte[] packet=PkarrPacket.Create(seed,now,announcement);
        Check(PkarrPacket.Read(key,packet,DateTimeOffset.UtcNow).Announcement.Endpoints.Single()=="203.0.113.1:8436","real signed PKARR DNS TXT payload round-trips");
        var corrupted=packet.ToArray();corrupted[^1]^=1;bool bad=false;try{PkarrPacket.Read(key,corrupted,DateTimeOffset.UtcNow);}catch(CryptographicException){bad=true;}Check(bad,"tampered discovery metadata is rejected before DNS content is trusted");
        bad=false;try{PkarrPacket.Read(PkarrPacket.PublicKey(PkarrPacket.NewSeed()),packet,DateTimeOffset.UtcNow);}catch(CryptographicException){bad=true;}Check(bad,"another host's key cannot verify the record");
        bad=false;try{PkarrPacket.Read(key,packet,DateTimeOffset.UtcNow.AddHours(3));}catch(FormatException){bad=true;}Check(bad,"expired address records are rejected");
        using var gateway=new PkarrGateway();using var http=new HttpClient(gateway);using var client=new PkarrClient(http,["https://fixture.invalid"]);
        int sent=await client.Publish(seed,packet,default);Check(sent==1&&gateway.Publications==1&&gateway.LastKey==key,"gateway PUT uses the standard z-base32 key path and signed wire payload");
        Check((await client.Resolve(source,"faketcp",default)).Single()=="203.0.113.1:8436","an unpaired resolver needs only the public PKARR source, no account or DNS credentials");
        gateway.Offline=true;bad=false;try{await client.Publish(seed,packet,default);}catch(IOException){bad=true;}Check(bad,"gateway outage cannot be reported as a successful publication");
        bad=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){bad=true;}Check(bad,"gateway outage does not return a stale successful lookup");gateway.Offline=false;
        byte[] newer=PkarrPacket.Create(seed,now+1000,announcement with{Endpoints=["203.0.113.2:9123"]});await client.Publish(seed,newer,default);
        Check((await client.Resolve(source,"faketcp",default)).Single()=="203.0.113.2:9123","same persistent public key discovers the changed address");
        gateway.Packet=packet;bad=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){bad=true;}Check(bad,"a previously observed newer version cannot be rolled back by a gateway");
        gateway.Packet=newer;bad=false;try{await client.Resolve(source,"udp",default);}catch(IOException){bad=true;}Check(bad,"lookup never silently switches the selected data protocol");
        gateway.Packet=corrupted;bad=false;try{await client.Resolve(source,"faketcp",default);}catch(IOException){bad=true;}Check(bad,"invalid gateway responses do not become usable candidate addresses");
        gateway.Packet=newer;
        using var resolver=new ExistingEntryResolver(()=>new(http,["https://fixture.invalid"]));
        var resolution=(await resolver.Resolve([new(ExistingEntry.NetworkOwner,source)],"faketcp",default)).Single();
        Check(resolution.ExpiresAt==announcement.Expires&&!resolution.AllowCached&&resolution.Endpoints.Single()=="203.0.113.2:9123","signed expiry reaches the runtime entry plan and failed PKARR queries cannot reuse stale cached endpoints");
        gateway.Offline=true;var unavailable=(await resolver.Resolve([new(ExistingEntry.NetworkOwner,source)],"faketcp",default)).Single();
        Check(unavailable.Error.Length>0&&!unavailable.AllowCached,"gateway failure explicitly invalidates lookup cache without declaring a healthy data path failed");gateway.Offline=false;
        await PkarrGatewayBudgets(seed,now,announcement);
        using var canceled=new CancellationTokenSource();canceled.Cancel();bad=false;try{await client.Resolve(source,"faketcp",canceled.Token);}catch(OperationCanceledException){bad=true;}Check(bad,"lookup cancellation remains cancellation instead of stale success");
        Console.WriteLine($"PASS {checks} PKARR protocol checks; injected gateway only, no public announcement");
    }
    static void DiscoveryPolicyTests()
    {
        var original=new UiNetworkSettings("https://coord.example.com/"){ConnectionSource="existing",DirectMode=true,ExistingEntries=[new(0,"203.0.113.1:8436")],CoordinatorBackup=true,PkarrPublish=true};
        var existing=ConnectionSettings.Normalize(original with{DiscoveryMode="existing"});
        Check(!existing.CoordinatorBackup&&!existing.PkarrPublish&&existing.Service==original.Service,"explicit existing-entry policy disables hidden fallback and publication while retaining inactive inputs");
        var autonomous=ConnectionSettings.Normalize(original with{ConnectionSource="custom",DiscoveryMode="pkarr",PkarrPublish=false});
        Check(autonomous.PkarrPublish&&!autonomous.CoordinatorBackup,"PKARR mode is mandatory publication for its host and cannot silently enable coordination");
        var profile=new DeviceProfile();ConnectionSettings.Apply(profile,autonomous);
        Check(profile.CoordinationService.Length==0&&profile.SavedNetworkSettings!.Service==original.Service,"inactive coordinator address is stored only as a preference, never as an active discovery target");
        var inactive=ConnectionSettings.Normalize(autonomous with{Service="unfinished://",CertificatePin="unfinished",ExistingEntries=[new(0,"unfinished://")]});
        ConnectionSettings.Apply(profile,inactive);profile.Validate();
        Check(profile.ExistingEntries.Length==0&&profile.SavedNetworkSettings!.ExistingEntries.Single().Source=="unfinished://","inactive input drafts are retained without being parsed as active endpoints or preventing another valid mode from saving");
        var inactiveStun=ConnectionSettings.Normalize(existing with{TcpStun=["unfinished://"],UdpStun=["unfinished://"]});ConnectionSettings.Apply(profile,inactiveStun);profile.Validate();
        Check(profile.SavedNetworkSettings!.TcpStun!.Single()=="unfinished://"&&!profile.TcpStun.Contains("unfinished://"),"dormant STUN inputs remain preferences and are not applied in existing-entry mode");
        var owner=MeshIdentity.Create("","","faketcp",direct:true);var guest=Guest(owner);
        string source=PkarrPacket.Source(PkarrPacket.NewSeed());
        var approved=ApprovedNetworkSettings.Create(owner,autonomous with{ExistingEntries=[new(0,source)]});
        var received=approved.ForGuest(guest,new());
        Check(received.DiscoveryMode=="pkarr"&&!received.PkarrPublish&&received.ExistingEntries.Single().PeerSlot==ExistingEntry.NetworkOwner,"approved PKARR guests inherit lookup mode and public key, never host publishing authority");
        profile.Mesh=guest;profile.ConnectionSource="custom";profile.ExistingEntries=received.ExistingEntries.Concat([new ExistingEntry(0,"203.0.113.99:9999")]).ToArray();
        Check(MeshRunner.EntrySources(profile,guest).Single().Source==source,"autonomous guest resolves the approved PKARR host hint but ignores dormant local existing entries");
        bool rejected=false;try{ConnectionSettings.Normalize(autonomous with{DirectMode=false});}catch(FormatException){rejected=true;}
        Check(rejected,"backend rejects a forged combination of PKARR and coordinated discovery");
    }
    sealed class SplitGateway(byte[] first,byte[] second):HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(request.RequestUri!.Host.StartsWith("one.")?first:second)});
    }
    sealed class SlowContent:HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context)=>throw new NotSupportedException();
        protected override bool TryComputeLength(out long length){length=0;return false;}
        protected override Task<Stream> CreateContentReadStreamAsync()=>Task.FromResult<Stream>(new SlowStream());
        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken token)=>CreateContentReadStreamAsync();
    }
    sealed class SlowStream:MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default){await Task.Delay(Timeout.Infinite,token);return 0;}
    }
    sealed class SlowGateway:HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new SlowContent()});
    }
    static async Task PkarrGatewayBudgets(string seed,long sequence,PkarrAnnouncement announcement)
    {
        byte[] a=PkarrPacket.Create(seed,sequence+2000,announcement),b=PkarrPacket.Create(seed,sequence+2000,announcement with{Endpoints=["203.0.113.77:8844"]});
        using var split=new SplitGateway(a,b);using var splitHttp=new HttpClient(split);using var splitClient=new PkarrClient(splitHttp,["https://one.invalid","https://two.invalid"]);
        bool conflict=false;try{await splitClient.Resolve(PkarrPacket.Source(seed),"faketcp",default);}catch(IOException ex){conflict=ex.Message.Contains("冲突");}
        Check(conflict,"simultaneous gateway responses with equal sequence and different signed payloads are rejected");
        using var slow=new SlowGateway();using var slowHttp=new HttpClient(slow){Timeout=Timeout.InfiniteTimeSpan};using var slowClient=new PkarrClient(slowHttp,["https://slow.invalid"],TimeSpan.FromMilliseconds(100));
        bool timedOut=false;var timer=System.Diagnostics.Stopwatch.StartNew();try{await slowClient.Resolve(PkarrPacket.Source(seed),"faketcp",default);}catch(IOException){timedOut=true;}
        Check(timedOut&&timer.Elapsed<TimeSpan.FromSeconds(3),"gateway deadline covers a stalled response body, including clients using ResponseHeadersRead");
    }
}
