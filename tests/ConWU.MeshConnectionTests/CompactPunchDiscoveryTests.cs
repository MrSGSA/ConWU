using System.Net;
using StreamLink.Core;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task CompactPunchDiscoveryTests()
    {
        CompactCodeTests();
        var code=CompactDirectCode.Import(CompactDirectCode.Issue("8.8.8.8:49197","mimic","000123",true));
        var handler=new PunchGateway();using var http=new HttpClient(handler);using var client=new PkarrClient(http,requestTimeout:TimeSpan.FromSeconds(1),checkpoints:new());
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var peer=new IPEndPoint(IPAddress.Parse("8.8.4.4"),49201);
        await CompactPunchDiscovery.Publish(client,code,peer,stop.Token);
        Check(handler.Writes==2,"temporary candidate is published as an ordinary signed PKARR record to both configured gateways");
        var record=PkarrPacket.Read(PkarrPacket.PublicKey(CompactPunchDiscovery.Seed(code)),handler.Packet!,DateTimeOffset.UtcNow);
        Check(record.Announcement.Endpoints.SequenceEqual([peer.ToString()])&&record.Announcement.Expires<=DateTimeOffset.UtcNow.AddSeconds(91).ToUnixTimeSeconds(),
            "bootstrap publication contains a bounded short-lived candidate and no network membership");
        int probes=0;IPEndPoint? observed=null;
        try{await CompactPunchDiscovery.Listen(client,code,DateTimeOffset.UtcNow.AddSeconds(10).ToUnixTimeSeconds(),endpoint=>{probes++;observed=endpoint;stop.Cancel();},_=>{},stop.Token);}catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        Check(probes==1&&Equals(observed,peer),"the host learns the exact public guest candidate and requests one probe without granting membership");
        int before=handler.Writes;
        try{await CompactPunchDiscovery.Publish(client,code,new(IPAddress.Parse("10.0.0.1"),49201),CancellationToken.None);throw new Exception("private candidate accepted");}catch(IOException){}
        Check(handler.Writes==before,"a private guest address cannot trigger publication or arbitrary LAN probing");
        try{CompactPunchDiscovery.Seed(code with{PunchDiscovery=false});throw new Exception("ordinary invitation activated discovery");}catch(ArgumentException){}
        Check(true,"an ordinary direct invitation cannot be treated as a candidate mailbox");
        using var expired=new CancellationTokenSource(300);
        probes=0;
        await CompactPunchDiscovery.Listen(client,code,DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds(),_=>probes++,_=>{},expired.Token);
        Check(probes==0,"expired host invitations perform no lookup or peer probe");
        Console.WriteLine($"PASS {checks} compact bootstrap checks; hints remain untrusted until real pairing approval");
    }
    sealed class PunchGateway:HttpMessageHandler
    {
        public int Writes;public byte[]? Packet;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if(request.Method==HttpMethod.Put){Interlocked.Increment(ref Writes);Packet=await request.Content!.ReadAsByteArrayAsync(token);return new(HttpStatusCode.NoContent);}
            return Packet==null?new(HttpStatusCode.NotFound):new(HttpStatusCode.OK){Content=new ByteArrayContent(Packet)};
        }
    }
}
