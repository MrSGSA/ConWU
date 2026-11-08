using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

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
        // RFC 8032's public test seed, never an actual application identity.
        string seed=Convert.ToBase64String(Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        string key=PkarrPacket.PublicKey(seed),source="pkarr://"+key;
        Check(Convert.ToHexString(PkarrPacket.DecodeKey(key)).Equals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",StringComparison.OrdinalIgnoreCase),"PKARR Ed25519 public key matches RFC 8032 independently published vector");
        ExistingEntryResolver.Validate([new(ExistingEntry.NetworkOwner,source)]);
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
        using var canceled=new CancellationTokenSource();canceled.Cancel();bad=false;try{await client.Resolve(source,"faketcp",canceled.Token);}catch(OperationCanceledException){bad=true;}Check(bad,"lookup cancellation remains cancellation instead of stale success");
        Console.WriteLine($"PASS {checks} PKARR protocol checks; injected gateway only, no public announcement");
    }
}
