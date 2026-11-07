using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task ThirdPartyDdnsDiscovery()
    {
        var mesh=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(mesh);guest.Directory=mesh.Directory;
        var config=new CloudflareDdnsSettings(true,"conwu.example.test",RefreshSeconds:30);
        long utc=1000;int reads=0;bool failed=false;string address="203.0.113.5:44680";
        ExistingEntry[] captured=[];
        Task<EntryResolution[]> Resolve(ExistingEntry[] entries,string mode,CancellationToken token){
            reads++;captured=entries;Check(mode=="faketcp","third-party DNS retains the fixed user protocol");
            return Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"TXT",failed?[]:[address],failed?"DNS fixture unavailable":"")).ToArray());
        }
        await using(var dns=new MeshThirdPartyDdns(Resolve,default,()=>utc)){
            dns.Tick(config,mesh,"faketcp",true,1000);dns.Tick(config,mesh,"faketcp",true,1001);
            Check(captured.Length==2&&captured.Select(e=>e.Source).Distinct().Count()==2&&captured.All(e=>e.Source.Contains("txt://e-")&&e.Source.EndsWith("#streamlink")),"one shared domain yields independent third-party records for each trusted member");
            Check(!captured.Any(e=>e.Source.Contains("txt://"+DdnsAddressRecords.Name(config.Domain,mesh.Pair.Network,mesh.Self.Device))),"third parties cannot overwrite ConWU's separately named signed discovery record");
            Check(dns.ForMember(mesh.Self).Single()==address&&dns.ForMember(guest.Self).Single()==address,"both local ingress publication and known-member reconnect consume third-party results without a ConWU Cloudflare token");
            utc+=30;address="203.0.113.8:45000";dns.Tick(config,mesh,"faketcp",true,31001);dns.Tick(config,mesh,"faketcp",true,31002);
            Check(reads==2&&dns.ForMember(guest.Self).Single()==address,"a DNS update replaces the candidate IP and external port on the next bounded poll");
            failed=true;utc+=30;dns.Tick(config,mesh,"faketcp",true,61002);dns.Tick(config,mesh,"faketcp",true,61003);
            Check(dns.ForMember(guest.Self).Length==1,"temporary DNS failure retains only the unexpired candidate");
            utc+=31;dns.Tick(config,mesh,"faketcp",true,92003);dns.Tick(config,mesh,"faketcp",true,92004);
            Check(dns.ForMember(guest.Self).Length==0,"repeated query failure cannot renew or indefinitely retain an unsigned address");
            failed=false;address="127.0.0.1:44680";dns.Tick(config,mesh,"faketcp",true,122004);dns.Tick(config,mesh,"faketcp",true,122005);
            Check(dns.ForMember(guest.Self).Length==0,"external records cannot inject loopback/private targets into automatic discovery");
            address="203.0.113.5:44680";dns.Tick(config,mesh,"faketcp",false,122006);dns.Tick(config,mesh,"faketcp",false,122007);
            Check(captured.Length==1&&captured[0].PeerSlot==guest.Self.Slot&&dns.ForMember(mesh.Self).Length==0,"autonomous mode does not consume its own third-party ingress record");
            dns.Tick(config with{Enabled=false},mesh,"faketcp",false,122008);
            Check(dns.ForMember(guest.Self).Length==0,"disabling DDNS immediately removes external hints");
        }
        var delayed=new TaskCompletionSource<EntryResolution[]>(TaskCreationOptions.RunContinuationsAsynchronously);ExistingEntry[] old=[];
        await using(var dns=new MeshThirdPartyDdns((entries,_,_)=>{old=entries;return delayed.Task;},default,()=>utc)){
            dns.Tick(config,mesh,"faketcp",true,1000);
            dns.Tick(config with{Domain="other.example.test"},mesh,"faketcp",true,1001);
            dns.Tick(config,mesh,"faketcp",true,1002);
            delayed.SetResult(old.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"TXT",["203.0.113.5:44680"],"")).ToArray());
            dns.Tick(config,mesh,"faketcp",true,1003);
            Check(dns.ForMember(guest.Self).Length==0,"a late pre-change DNS reply is discarded even after switching back to the same domain");
        }
        bool queryEnded=false;
        var closing=new MeshThirdPartyDdns(async(_,_,ct)=>{try{await Task.Delay(Timeout.Infinite,ct);return [];}finally{queryEnded=true;}},default);
        closing.Tick(config,mesh,"faketcp",true,1000);
        await closing.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));await closing.DisposeAsync();
        Check(queryEnded,"shutdown cancels and joins an outstanding third-party DNS query without waiting for its network deadline");
    }
    static async Task ThirdPartyDdnsRunner()
    {
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var guest=Guest(owner);guest.Directory=owner.Directory;
        byte[] key=MeshIdentity.SharedKey(guest,owner.Self);using var link=new MeshLink(guest.Self.Slot,owner.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var peer=new PeerEndpoint(link);var adapter=new MemoryAdapter();
        var discovery=new Discovery(owner,guest,""){ExpiresOverride=1};int probes=0,factories=0,active=0,maximum=0;SessionStatus? status=null;
        const string target="203.0.113.5:44680";
        string folder=Path.Combine(Path.GetTempPath(),"conwu-thirdparty-"+Guid.NewGuid().ToString("N"));
        var targets=new ConcurrentQueue<string>();var transports=new ConcurrentBag<TrackedThirdPartyTransport>();
        var services=new MeshRuntimeServices(_=>discovery,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{probes++;throw new Exception("no autonomous probe allowed");},
            r=>{if(r.Server)return new StubTransport(null);targets.Enqueue(r.Target.ToString());int current=Interlocked.Increment(ref active);maximum=Math.Max(maximum,current);var t=new TrackedThirdPartyTransport(new ForwardingTransport(peer.Endpoint),()=>Interlocked.Decrement(ref active));transports.Add(t);return t;},
            (_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            Candidates=(_,_,_,_)=>{factories++;throw new Exception("no autonomous candidate factory allowed");},NetworkWake=()=>new MeshNetworkWake(false),
            Ddns=ct=>new(ct,read:(_,_,_,_,_)=>Task.FromResult<DdnsAddressRecord?>(null)),
            ResolveEntries=(entries,_,_)=>Task.FromResult(entries.Select((e,i)=>new EntryResolution(e.PeerSlot,i,"TXT",e.PeerSlot==guest.Self.Slot||e.PeerSlot==ExistingEntry.Network?[target]:[],"")).ToArray())
        };
        var profile=new DeviceProfile{Mesh=owner,ConnectionSource="existing",Ddns=new(true,"conwu.example.test"),ExistingEntries=[new(ExistingEntry.Network,target)]};
        var runner=new MeshRunner(profile,_=>{},s=>status=s,_=>{},_=>{},services);using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try{
            await Until(()=>status?.Connected==true,"third-party DDNS reconnects a trusted member while coordinator presence is stale",12000);
            adapter.Outgoing.Add(Packet(owner.LocalIp,guest.LocalIp));await Until(()=>peer.DataPackets==1,"third-party discovered entry carries a real authenticated full-size IP packet");
            Check(probes==0&&factories==0&&targets.All(t=>t==target)&&maximum==1&&active==1,"DDNS plus a duplicate manual network seed use one outbound owner and never start autonomous punching");
            int created=transports.Count;var healthy=transports.Single(t=>!t.Disposed);
            runner.UpdateEntries(profile);await Task.Delay(500);
            Check(active==1&&transports.Count==created&&!healthy.Disposed&&!adapter.Disposed,"saving unchanged discovery settings preserves the same healthy transport and adapter");
        }finally{await Stop(running,stop);if(Directory.Exists(folder))Directory.Delete(folder,true);}
        Check(active==0&&transports.All(t=>t.Disposed)&&adapter.Disposed,"third-party DNS shutdown releases every owned transport and adapter");
    }
    sealed class TrackedThirdPartyTransport(IMeshTransport inner,Action closed):IMeshTransport
    {
        public IPEndPoint? ClientEndpoint=>inner.ClientEndpoint;public bool Exited=>inner.Exited;public bool Disposed;
        public void Dispose(){if(Disposed)return;Disposed=true;try{inner.Dispose();}finally{closed();}}
    }
}
