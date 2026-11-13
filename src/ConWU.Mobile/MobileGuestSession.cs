using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace ConWU.Mobile;

public sealed record MobileConnectionStatus(string NetworkId,string State,string Detail,bool Connected=false,double? RttMs=null,long SentBytes=0,long ReceivedBytes=0,long ConnectedAt=0);

public sealed class MobileGuestSession(MobileNetwork network,IPacketAdapter adapter,string deviceName,Action<MobileConnectionStatus> report)
{
    public async Task Run(CancellationToken token,
        Func<ExistingEntry[],string,CancellationToken,Task<EntryResolution[]>>? resolveOverride=null,
        Func<MeshProfile,IPEndPoint,IMeshTransport>? transportOverride=null,
        Func<long>? networkGeneration=null)
    {
        MobileEnrollment.RequireProtocol(network.Mesh.Pair.Mode);
        var mesh=network.Mesh;int host=mesh.IntroducerSlot;
        await using var router=new MeshRouter(mesh,adapter);
        using var sync=new MeshPeerSynchronization(mesh);sync.Attach(router);
        using var coordinator=ConnectionSettings.Discovery(network.Settings)=="coordinator"?new MeshDiscoveryClient(mesh):null;
        using var resolver=new ExistingEntryResolver(()=>new PkarrClient(gateways:network.Settings.PkarrGateways));
        IMeshTransport? transport=null;
        string[] endpoints=[];string activeTarget="";string lookupError="";
        long nextLookup=0,nextAttempt=0,nextPublish=0,connectedAt=0,revision=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();int attempt=0;
        bool wasHealthy=false;
        long observedNetwork=networkGeneration?.Invoke()??0;
        void Status(string state,string detail){var peer=router.Status().FirstOrDefault(p=>p.Slot==host);report(new(network.Id,state,detail,peer?.Connected==true,peer?.RttMs,peer?.SentBytes??0,peer?.ReceivedBytes??0,connectedAt));}
        async Task CloseTransport()
        {
            if(transport==null)return;
            router.FailLegacyTransport(host,transport.ClientEndpoint);
            if(transport is IAsyncDisposable asyncTransport)await asyncTransport.DisposeAsync();else transport.Dispose();
            transport=null;activeTarget="";
        }
        try{
            while(!token.IsCancellationRequested){
                long now=Environment.TickCount64;
                long currentNetwork=networkGeneration?.Invoke()??observedNetwork;
                if(currentNetwork!=observedNetwork){
                    observedNetwork=currentNetwork;
                    await CloseTransport();nextLookup=0;nextAttempt=0;
                }
                if(router.Completion.IsCompleted){await router.Completion;throw new IOException("连接数据通道已停止");}
                sync.Tick(now);
                var signed=sync.Read()?.Directory;
                if(signed!=null&&signed.Revision>(mesh.Directory?.Revision??0)){
                    if(signed.Closed||!signed.Members.Contains(mesh.Self)){Status("Revoked","主机已删除网络或移除本设备");return;}
                    router.ApplyDirectory(signed);
                }
                bool healthy=router.HasHealthyPath(host);
                if(healthy&&!wasHealthy)connectedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if(!healthy&&wasHealthy){nextLookup=0;nextAttempt=0;connectedAt=0;}
                wasHealthy=healthy;
                if(now>=nextPublish){
                    var announcement=new MeshAnnouncement(mesh.Self.Slot,mesh.Self.Device,++revision,DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"",deviceName);
                    sync.Publish(announcement);nextPublish=now+30000;
                    if(coordinator!=null)try{await coordinator.Publish(announcement,token);}catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or HttpRequestException or OperationCanceledException){}
                }
                if(now>=nextLookup){
                    nextLookup=now+Math.Min(healthy?86400:30,Math.Max(1,network.Settings.EntryRefreshSeconds))*1000L;
                    try{
                        if(coordinator!=null){
                            var snapshot=await coordinator.Read(token);
                            if(snapshot!=null){
                                sync.Merge(snapshot,fromCoordinator:true);
                                if(snapshot.Directory.Closed||!snapshot.Directory.Members.Contains(mesh.Self)){Status("Revoked","主机已删除网络或移除本设备");return;}
                                var member=snapshot.Directory.Members.Single(m=>m.Slot==host);
                                var announcement=snapshot.Nodes.Where(n=>n.Slot==host).Select(n=>MeshMetadata.Open(mesh,member,n)).OrderByDescending(n=>n.Revision).FirstOrDefault();
                                if(announcement!=null)endpoints=(announcement.ExistingEndpoints??[]).Concat(announcement.Endpoint.Length>0?[announcement.Endpoint]:[]).Distinct().ToArray();
                            }
                        }else{
                            var sources=Sources(network);
                            var values=resolveOverride==null?healthy?await resolver.Resolve(sources,mesh.Pair.Mode,token):await resolver.ResolveRecovering(sources,mesh.Pair.Mode,token):await resolveOverride(sources,mesh.Pair.Mode,token);
                            endpoints=values.SelectMany(v=>v.Endpoints).Distinct().Take(ExistingEntryResolver.MaximumEndpoints).ToArray();
                        }
                        lookupError=endpoints.Length==0?"主机入口暂不可用，正在自动重试":"";
                    }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or HttpRequestException or FormatException or CryptographicException or OperationCanceledException){lookupError="暂未获取到主机的当前入口，正在自动重试";}
                    // Only manual discovery and the very first coordinated
                    // connection need the compact-code endpoint. Existing-entry
                    // and PKARR configuration never fall back to a stale code.
                    if(coordinator!=null&&endpoints.Length==0&&activeTarget.Length==0&&attempt==0)endpoints=[network.BootstrapEndpoint];
                }
                if(!healthy&&now>=nextAttempt){
                    await CloseTransport();
                    nextAttempt=now+10000;
                    if(endpoints.Length>0){
                        try{
                            string selected=endpoints[attempt++%endpoints.Length];var parsed=ExistingEntryResolver.ParseEndpoint(selected);
                            IPAddress address=IPAddress.TryParse(parsed.Host,out var ip)?ip:(await Dns.GetHostAddressesAsync(parsed.Host,token)).FirstOrDefault(a=>a.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork)??throw new IOException("主机域名暂未解析到 IPv4 入口");
                            transport=transportOverride?.Invoke(mesh,new(address,parsed.Port))??new StreamMeshTransport(mesh,new(address,parsed.Port),false,0,flowLanes:network.Settings.StreamFlowLanes);
                            router.SetCandidate(host,transport.ClientEndpoint,network.HostName,"手机主动连接主机");activeTarget=selected;
                        }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or System.Net.Sockets.SocketException or HttpRequestException or FormatException or OperationCanceledException){
                            await CloseTransport();lookupError="主机入口暂不可达，正在自动重试";
                        }
                    }
                }
                if(transport?.Exited==true){await CloseTransport();nextAttempt=now+1000;}
                healthy=router.HasHealthyPath(host);
                Status(healthy?"Connected":endpoints.Length>0?"Connecting":"Waiting",healthy?"已直连 "+network.HostName:lookupError.Length>0?lookupError:"正在验证与主机的双向连接");
                await Task.Delay(500,token);
            }
        }catch(OperationCanceledException)when(token.IsCancellationRequested){}
        finally{await CloseTransport();}
    }
    public static ExistingEntry[] Sources(MobileNetwork network)
    {
        var sources=network.Settings.ExistingEntries.Where(e=>e.PeerSlot==ExistingEntry.NetworkOwner).Select(e=>e with{PeerSlot=network.Mesh.IntroducerSlot}).ToArray();
        if(network.Settings.ConnectionSource=="existing")return sources.Length>0?sources:[new(network.Mesh.IntroducerSlot,network.BootstrapEndpoint)];
        if(ConnectionSettings.Discovery(network.Settings)=="pkarr")return sources.Where(e=>ExistingEntryResolver.Kind(e.Source)=="PKARR").ToArray();
        return [new(network.Mesh.IntroducerSlot,network.BootstrapEndpoint)];
    }
}
