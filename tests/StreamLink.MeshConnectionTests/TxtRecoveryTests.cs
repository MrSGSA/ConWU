using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;

static partial class Program
{
    const string RecoverySource="txt://entries.example.com#streamlink1";
    const string StaleEntry="203.0.113.6:8504",FreshEntry="203.0.113.6:8414";
    static Task<IPAddress[]> NoAddresses(string _,CancellationToken token)=>Task.FromResult(Array.Empty<IPAddress>());
    static Task<string[]> StaleTxt(string _,CancellationToken token)=>Task.FromResult(new[]{"streamlink1="+StaleEntry});
    static Task<TxtRecoveryAnswer[]> FreshTxt(string _,CancellationToken token)=>Task.FromResult(new[]{new TxtRecoveryAnswer("fixture",["streamlink1="+FreshEntry])});

    static byte[] DnsReply(byte[] request,string value)
    {
        byte[] text=Encoding.UTF8.GetBytes(value),reply=new byte[request.Length+13+text.Length];
        request.CopyTo(reply,0);reply[2]=0x81;reply[3]=0x80;reply[7]=1;
        int at=request.Length;reply[at++]=0xc0;reply[at++]=0x0c;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(at),16);at+=2;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(at),1);at+=2;
        BinaryPrimitives.WriteUInt32BigEndian(reply.AsSpan(at),60);at+=4;
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(at),(ushort)(text.Length+1));at+=2;
        reply[at++]=(byte)text.Length;text.CopyTo(reply,at);return reply;
    }
    static HttpResponseMessage DnsResponse(byte[] wire)=>new(HttpStatusCode.OK){Content=new ByteArrayContent(wire){Headers={ContentType=new MediaTypeHeaderValue("application/dns-message")}}};

    static async Task TxtRecovery()
    {
        int backupCalls=0;
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(host,ct)=>{Interlocked.Increment(ref backupCalls);return FreshTxt(host,ct);})){
            var ordinary=(await resolver.Resolve([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(ordinary.Endpoints.SequenceEqual([StaleEntry])&&backupCalls==0,"ordinary TXT lookup preserves system DNS and never invokes recovery providers");
            var recovered=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(recovered.Endpoints.SequenceEqual([FreshEntry,StaleEntry])&&backupCalls==1&&recovered.LookupDetail.Contains("HTTPS DNS"),"valid but stale system TXT cannot hide a fresh recovery candidate; old candidates remain available for authentication");
            await resolver.ResolveRecovering([new(1,"txt://private.internal#streamlink1")],"faketcp",default);
            Check(backupCalls==1,"private DNS namespaces are never sent to public recovery providers");
        }
        foreach(var primary in new Func<string,CancellationToken,Task<string[]>>[]{
            (_,_)=>Task.FromException<string[]>(new IOException("token=must-not-leak")),
            (_,_)=>Task.FromResult(new[]{"other=203.0.113.1:1"}),
            (_,_)=>Task.FromResult(new[]{"streamlink1=udp://203.0.113.6:9"})}){
            using var resolver=new ExistingEntryResolver(NoAddresses,primary,recoverTxt:FreshTxt);
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Error.Length==0&&result.Endpoints.SequenceEqual([FreshEntry])&&!result.LookupDetail.Contains("must-not-leak"),"a failing, wrong-tag or wrong-protocol system answer cannot poison a valid recovery result");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(_,_)=>Task.FromResult(new[]{
            new TxtRecoveryAnswer("bad",["streamlink1=udp://203.0.113.1:2"]),
            new TxtRecoveryAnswer("foreign",["streamlink2=203.0.113.1:3"]),
            new TxtRecoveryAnswer("good",["other=203.0.113.1:4 streamlink1="+FreshEntry])}))) {
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([FreshEntry,StaleEntry])&&!result.LookupDetail.Contains("foreign"),"each recovery backend is tag- and protocol-checked independently before candidate merging");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(_,_)=>Task.FromException<TxtRecoveryAnswer[]>(new HttpRequestException("secret")))){
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([StaleEntry])&&result.Error.Length==0&&!result.LookupDetail.Contains("secret"),"recovery provider failure preserves a valid system answer without leaking provider errors");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(_,_)=>Task.FromResult(new[]{
            new TxtRecoveryAnswer("stale",["streamlink1="+StaleEntry]),new TxtRecoveryAnswer("fresh",["streamlink1="+FreshEntry])}))){
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([FreshEntry,StaleEntry]),"a new alternate candidate is tried before the already-unreachable system answer even when the first encrypted provider is also stale");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(_,_)=>Task.FromResult(new[]{
            new TxtRecoveryAnswer("many",Enumerable.Range(0,8).Select(i=>"streamlink1=203.0.113.9:"+(9000+i)).ToArray()),
            new TxtRecoveryAnswer("fresh",["streamlink1="+FreshEntry])}))){
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.Length==8&&result.Endpoints.Contains(FreshEntry)&&result.Endpoints.Contains(StaleEntry),"a full stale backend cannot crowd out fresh-provider or system candidates within the eight-entry limit");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,async(_,ct)=>{await Task.Delay(Timeout.Infinite,ct);return [];},recoverTxt:FreshTxt)){
            var watch=System.Diagnostics.Stopwatch.StartNew();
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([FreshEntry])&&watch.ElapsedMilliseconds<5000,"a stuck system DNS lookup cannot hide an available HTTPS DNS result behind the full resolver timeout");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:async(_,ct)=>{await Task.Delay(Timeout.Infinite,ct);return [];})){
            var watch=System.Diagnostics.Stopwatch.StartNew();
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([StaleEntry])&&watch.ElapsedMilliseconds<5000,"unreachable HTTPS DNS cannot suppress a usable system answer or leave unbounded work");
        }
        using(var resolver=new ExistingEntryResolver(NoAddresses,async(_,ct)=>{await Task.Delay(3700,ct);return ["streamlink1="+StaleEntry];},recoverTxt:(_,_)=>Task.FromException<TxtRecoveryAnswer[]>(new IOException("unavailable")))){
            var result=(await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",default)).Single();
            Check(result.Endpoints.SequenceEqual([StaleEntry])&&result.Error.Length==0,"unavailable alternates do not shorten the original timeout of a slow but functioning system resolver");
        }
        using(var stop=new CancellationTokenSource(50))
        using(var resolver=new ExistingEntryResolver(NoAddresses,async(_,ct)=>{await Task.Delay(Timeout.Infinite,ct);return [];},recoverTxt:async(_,ct)=>{await Task.Delay(Timeout.Infinite,ct);return [];})){
            bool cancelled=false;try{await resolver.ResolveRecovering([new(1,RecoverySource)],"faketcp",stop.Token);}catch(OperationCanceledException){cancelled=true;}
            Check(cancelled,"caller cancellation stops both TXT recovery legs");
        }
        using(var handler=new ScriptedEntryHttp(async(_,request,ct)=>{
            Check(request.Method==HttpMethod.Post&&request.RequestUri!.Scheme=="https"&&request.Content!.Headers.ContentType!.MediaType=="application/dns-message","recovery uses bounded HTTPS DNS wire requests");
            byte[] question=await request.Content!.ReadAsByteArrayAsync(ct);
            return DnsResponse(DnsReply(question,"streamlink1="+(request.RequestUri!.Host=="dns.alidns.com"?FreshEntry:StaleEntry)));
        }))
        using(var doh=new DnsOverHttpsTextLookup(handler)){
            var answers=await doh.Query("entries.example.com",default);
            Check(handler.Calls==3&&answers.Length==3&&answers.SelectMany(a=>a.Documents).Distinct().Count()==2,"independent encrypted providers contribute candidates when their caches disagree");
            await doh.Query("private.local",default);Check(handler.Calls==3,"private names cannot reach the HTTPS DNS transport");
        }
        foreach(string bad in new[]{"transaction","question","oversize","redirect","type"}){
            using var handler=new ScriptedEntryHttp(async(_,request,ct)=>{
                if(bad=="redirect")return new(HttpStatusCode.Redirect){Headers={Location=new("https://private.example/token=must-not-leak")}};
                byte[] query=await request.Content!.ReadAsByteArrayAsync(ct),wire=DnsReply(query,"streamlink1="+FreshEntry);
                if(bad=="transaction")wire[0]^=1;
                if(bad=="question")wire[13]^=1;
                if(bad=="oversize")wire=new byte[ExistingEntryResolver.MaximumBody+1];
                var response=DnsResponse(wire);if(bad=="type")response.Content.Headers.ContentType=new("text/html");return response;
            });
            using var doh=new DnsOverHttpsTextLookup(handler);
            Check((await doh.Query("entries.example.com",default)).Length==0&&handler.Calls==3,"HTTPS DNS rejects "+bad+" responses without following URLs or admitting candidates");
        }
        await SharedRecoveryLookup();
        ReconnectRecoveryBounds();
        await TxtRecoveryRunner();
        Console.WriteLine($"PASS {checks} TXT recovery checks; isolated DNS fixtures and authenticated loopback traffic; installed services unchanged");
    }

    static async Task SharedRecoveryLookup()
    {
        int calls=0;var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:async(host,ct)=>{Interlocked.Increment(ref calls);entered.TrySetResult();await release.Task.WaitAsync(ct);return await FreshTxt(host,ct);});
        using var shared=new SharedEntryResolver(resolver);
        await shared.Resolve([new(1,RecoverySource)],"faketcp",default);
        using var stop=new CancellationTokenSource();
        var first=shared.ResolveRecovering([new(1,RecoverySource)],"faketcp",stop.Token);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(2));
        var second=shared.ResolveRecovering([new(2,RecoverySource)],"faketcp",default);
        stop.Cancel();release.TrySetResult();
        bool cancelled=false;try{await first;}catch(OperationCanceledException){cancelled=true;}
        var answer=(await second).Single();
        Check(cancelled&&calls==1&&answer.PeerSlot==2&&answer.Endpoints[0]==FreshEntry,"recovery bypasses ordinary coalesced answers, coalesces concurrent recovery and isolates caller cancellation and peer ownership");
    }

    static void ReconnectRecoveryBounds()
    {
        var policy=new PeerReconnectPolicy();string[] hints=[StaleEntry];long last=1000,maxGap=0;int allowed=0;
        for(long now=1000;now<600000;now+=1000)if(policy.Allow(true,false,false,hints,now)){maxGap=Math.Max(maxGap,now-last);last=now;allowed++;}
        Check(maxGap<=31000&&allowed<400,"unchanged offline entry retains idle backoff but cannot become dormant for four minutes");
        Check(policy.Allow(true,false,false,[FreshEntry],600001),"a changed entry immediately wakes the offline retry policy");
        Check(!policy.Allow(false,false,false,hints,600002),"faster serverless recovery does not bypass coordinated presence requirements");
    }

    static async Task TxtRecoveryRunner()
    {
        var host=MeshIdentity.Create("","","faketcp",direct:true);var guest=Guest(host);guest.Directory=host.Directory;
        byte[] key=MeshIdentity.SharedKey(host,guest.Self);using var link=new MeshLink(host.Self.Slot,guest.Self.Slot,key);CryptographicOperations.ZeroMemory(key);
        await using var peer=new PeerEndpoint(link);using var sink=new UdpClient(new IPEndPoint(IPAddress.Loopback,0));
        var adapter=new MemoryAdapter();SessionStatus? status=null;int recoveries=0,ordinary=0,probes=0;
        var transports=new ConcurrentBag<ForwardingTransport>();var targets=new ConcurrentQueue<string>();
        using var resolver=new ExistingEntryResolver(NoAddresses,StaleTxt,recoverTxt:(_,_)=>Task.FromResult(new[]{
            new TxtRecoveryAnswer("stale",["streamlink1="+StaleEntry]),new TxtRecoveryAnswer("fresh",["streamlink1="+FreshEntry])}));
        string folder=Path.Combine(Path.GetTempPath(),"conwu-txt-recovery-"+Guid.NewGuid().ToString("N"));
        var profile=new DeviceProfile{Mesh=guest,ConnectionSource="existing",EntryRefreshSeconds=1,ExistingEntries=[new(ExistingEntry.Network,StaleEntry),new(ExistingEntry.NetworkOwner,RecoverySource)]};
        string saved=JsonSerializer.Serialize(profile);
        var services=new MeshRuntimeServices(mesh=>new DirectMeshDiscovery(mesh),_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>{probes++;throw new Exception("no STUN in existing-entry mode");},r=>{
            if(r.Server)return new StubTransport(null);
            string target=r.Target.ToString();targets.Enqueue(target);
            var transport=new ForwardingTransport(target==FreshEntry?peer.Endpoint:(IPEndPoint)sink.Client.LocalEndPoint!,toleratePeerOffline:true);transports.Add(transport);return transport;
        },(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){
            ResolveEntries=(e,m,ct)=>{Interlocked.Increment(ref ordinary);return resolver.Resolve(e,m,ct);},
            ResolveEntriesForRecovery=(e,m,ct)=>{Interlocked.Increment(ref recoveries);return resolver.ResolveRecovering(e,m,ct);},
            NetworkWake=()=>new MeshNetworkWake(false),Candidates=(_,_,_,_)=>throw new Exception("no autonomous fallback")
        };
        var runner=new MeshRunner(profile,_=>{},s=>Volatile.Write(ref status,s),_=>{},_=>{},services);
        using var stop=new CancellationTokenSource();var running=runner.Run(stop.Token);
        try{
            await Until(()=>Volatile.Read(ref status)?.Peers?.SingleOrDefault() is {Connected:true,OuterTarget:FreshEntry},"fresh HTTPS DNS candidate restores saved membership despite stale system DNS and a stale fixed seed",9000);
            int recoveryCount=recoveries;
            await Until(()=>Volatile.Read(ref ordinary)>0,"healthy connections return to ordinary system DNS refresh",4000);
            Check(recoveries==recoveryCount,"healthy state does not repeatedly query public recovery services");
            int packets=peer.DataPackets;adapter.Outgoing.Add(Packet(guest.LocalIp,host.LocalIp));
            await Until(()=>peer.DataPackets>packets,"recovered path delivers authenticated encrypted IP traffic");
            Check(JsonSerializer.Serialize(profile)==saved&&probes==0&&targets.All(t=>t is StaleEntry or FreshEntry),"recovery preserves settings, identities and protocol and dials only supplied candidates");
        }finally{
            await Stop(running,stop);
            if(Directory.Exists(folder)){
                string resolved=Path.GetFullPath(folder),temp=Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
                if(!string.Equals(Path.GetDirectoryName(resolved),temp,StringComparison.OrdinalIgnoreCase)||
                    (File.GetAttributes(resolved)&FileAttributes.ReparsePoint)!=0)throw new IOException("fixture cleanup escaped its temporary directory");
                Directory.Delete(resolved,true);
            }
        }
        Check(runner.CleanupComplete&&adapter.Disposed&&transports.All(t=>t.Disposed),"recovery runner releases adapters and candidate transports on cancellation");
    }
}
