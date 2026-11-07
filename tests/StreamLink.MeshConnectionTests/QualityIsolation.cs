using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task QualityIsolation(string? output=null)
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] secret=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(2,1,secret);CryptographicOperations.ZeroMemory(secret);
        await using var peer=new PeerEndpoint(link);
        using var conflict=new UdpClient(new IPEndPoint(IPAddress.Loopback,Quality.Port));
        var adapter=new MemoryAdapter();int adapters=0,diagnostics=0;
        var discovery=new Discovery(owner,guest,peer.Endpoint.ToString());var transports=new ConcurrentBag<ForwardingTransport>();var receivers=new ConcurrentBag<StubTransport>();
        var logs=new ConcurrentQueue<string>();SessionStatus? status=null;
        var services=new MeshRuntimeServices(_=>discovery,_=>{adapters++;return Task.FromResult<IPacketAdapter>(adapter);},
            async(_,_,ct)=>{await Task.Delay(Timeout.Infinite,ct);throw new InvalidOperationException();},
            r=>{if(r.Server){var receiver=new StubTransport(null);receivers.Add(receiver);return receiver;}var transport=new ForwardingTransport(r.Target);transports.Add(transport);return transport;},
            (_,key,ct)=>{diagnostics++;return Quality.Serve("127.0.0.1",key,ct);},(_,_,_)=>{},(_,_)=>{},Path.Combine(Path.GetTempPath(),"StreamLink-quality-isolation-"+Guid.NewGuid().ToString("N")));
        var profile=new DeviceProfile{Mesh=owner};var runner=new MeshRunner(profile,logs.Enqueue,s=>status=s,_=>{},_=>{},services);
        using var cancellation=new CancellationTokenSource();var running=runner.Run(cancellation.Token);
        try{
            await Until(()=>logs.Any(l=>l.StartsWith("测速服务不可用")),"actual diagnostic port conflict is reported without network restart");
            await Until(()=>status?.Connected==true,"peer authentication connects despite unavailable diagnostic port");
            int before=peer.DataPackets;adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));
            await Until(()=>peer.DataPackets>before,"complete authenticated IP datagram reaches peer after diagnostic fault");
            Check(adapters==1&&diagnostics==1&&!running.IsCompleted&&transports.Count==1&&!transports.Single().Disposed&&receivers.Count==1&&!receivers.Single().Disposed&&!adapter.Disposed,"diagnostic failure must preserve the healthy outbound transport, default receiver and adapter");
            if(output!=null){Directory.CreateDirectory(Path.GetDirectoryName(output)!);await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status="Pass",checks,adapterCreations=adapters,diagnosticStarts=diagnostics,authenticatedIpPackets=peer.DataPackets,scope="formal MeshRunner and actual loopback UDP port fault + MeshLink IP data; memory adapter, not native FakeTCP/WAN",relay=false},new JsonSerializerOptions{WriteIndented=true}));}
        }finally{await Stop(running,cancellation);}
    }
}
