using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task StrictExistingOnly()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var good=new PeerEndpoint(link);using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));string dead=sink.Client.LocalEndPoint!.ToString()!;
        var discovery=new Discovery(owner,guest,good.Endpoint.ToString());var adapter=new MemoryAdapter();
        string supplied=dead;int probes=0,factories=0,listeners=0;var targets=new ConcurrentQueue<string>();SessionStatus? status=null;
        string folder=Path.Combine(Path.GetTempPath(),"streamlink-entry-only-"+Guid.NewGuid().ToString("N"));
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{Interlocked.Increment(ref probes);throw new Exception("strict mode must not probe");},request=>{if(request.Server)Interlocked.Increment(ref listeners);else targets.Enqueue(request.Target.ToString());return new ForwardingTransport(request.Target);},(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            NetworkWake=()=>new MeshNetworkWake(false),Candidates=(_,_,_,_)=>{Interlocked.Increment(ref factories);throw new Exception("strict mode must not create a candidate factory");},
            ResolveEntries=(_,_,_)=>Task.FromResult(new[]{new EntryResolution(guest.Self.Slot,0,"地址",[supplied],"")})
        };
        var profile=new DeviceProfile{Mesh=owner,EntryRefreshSeconds=1,ConnectionSource="existing",ExistingEntries=[new(guest.Self.Slot,"203.0.113.1:44680")],TransportMode="faketcp",PathSelection="faketcp-only"};
        var runner=new MeshRunner(profile,_=>{},s=>status=s,_=>{},_=>{},services);using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try{
            await Until(()=>status?.Peers?.Single().Connection?.Phase=="EntryUnavailable","failed supplied entry reports manual switch guidance instead of autonomous fallback",20000);
            Check(probes==0&&factories==0&&targets.All(t=>t==dead)&&good.Received==0&&listeners==1,"real runner owns one default receiver and never calls STUN/mapping/factory or a discovered outbound alternative");
            Check(discovery.Published.Any(n=>n.ExistingEntryOnly&&n.Traversal==null),"signed announcement tells peer not to initiate autonomous traversal for this device");
            supplied=good.Endpoint.ToString();runner.UpdateEntries(profile);
            await Until(()=>status?.Connected==true,"corrected subscribed entry connects using the same selected mode",7000);
            adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));await Until(()=>good.DataPackets==1,"strict supplied path delivers real authenticated full-size application data");
            Check(probes==0&&factories==0&&!adapter.Disposed,"subscription correction preserves Wintun and does not enable autonomous work");
        }finally{await Stop(running,stop);if(Directory.Exists(folder))Directory.Delete(folder,true);}
        var custom=ProfileChanges.Copy(profile);custom.ConnectionSource="custom";
        Check(ProfileChanges.Impact(profile,custom)==ProfileChangeImpact.RestartNetwork&&ProfileChanges.Impact(custom,profile)==ProfileChangeImpact.RestartNetwork,"switching between supplied-only and autonomous mode explicitly rebuilds connection policy");
        var changed=ProfileChanges.Copy(profile);changed.ExistingEntries=[new(guest.Self.Slot,"203.0.113.9:44680")];
        Check(ProfileChanges.Impact(profile,changed)==ProfileChangeImpact.NextAttempt,"editing supplied addresses within the same mode remains a live update");
        var plan=new ExistingEntryPlan();
        Check(plan.Select([dead],good.Endpoint.ToString(),false,false,1000,true)==dead&&plan.Select([dead],good.Endpoint.ToString(),false,false,100000,true)==dead&&!plan.FellBack,"supplied-only plan never returns an autonomous fallback even after its old priority deadline");
        Check(plan.Select([],good.Endpoint.ToString(),false,false,100001,true)=="","empty supplied entry list does not use a discovered alternative");
    }
}
