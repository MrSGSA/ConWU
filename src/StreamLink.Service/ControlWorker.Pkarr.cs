using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    readonly Lazy<PkarrCheckpoints> pkarrCheckpoints;
    PkarrStatus pkarrStatus=new(false,"未启用");
    Task? publishingPkarr;CancellationTokenSource? pkarrStop;int pkarrRefreshRequested;
    static string[] PkarrGateways(DeviceProfile value)=>value.SavedNetworkSettings is {} saved&&ConnectionSettings.Discovery(saved)=="pkarr"?saved.PkarrGateways:PkarrClient.DefaultGateways;
    string[] CurrentPkarrGateways(){lock(sync)return PkarrGateways(profile).ToArray();}
    PkarrClient CreatePkarrClient(){var client=meshRuntime?.PkarrClientFactory?.Invoke()??new PkarrClient(gateways:CurrentPkarrGateways(),gatewayProvider:CurrentPkarrGateways);client.UseCheckpoints(pkarrCheckpoints.Value);return client;}
    static bool PkarrSelected(DeviceProfile value)=>value.Mesh is {} mesh&&(value.PkarrPublish&&mesh.IsOwner||PkarrRendezvous.Uses(value)&&value.PkarrStateVersion==1);
    bool CurrentPkarrPublication(DeviceProfile value,MeshRunner active)
    {
        lock(sync)return profile.Enabled&&!Volatile.Read(ref stoppingNetwork)&&PkarrSelected(profile)&&
            profile.Mesh?.Pair.Network==value.Mesh?.Pair.Network&&profile.PkarrSeed==value.PkarrSeed&&profile.TransportMode==value.TransportMode&&PkarrGateways(profile).SequenceEqual(PkarrGateways(value))&&
            ReferenceEquals(meshRunner,active)&&active.ReceiverReady;
    }
    static ExistingEntry[] PkarrHints(DeviceProfile p)=>p.PkarrPublish&&p.PkarrSeed.Length>0?[new(0,PkarrPacket.Source(p.PkarrSeed))]:[];
    void EnsurePkarrIdentity()
    {
        lock(sync){if(profile.Mesh is {} mesh&&profile.PkarrSeed.Length==0&&(profile.PkarrPublish&&mesh.IsOwner||PkarrRendezvous.Uses(profile))){
            var next=ProfileChanges.Copy(profile);next.PkarrSeed=mesh.IsOwner?PkarrPacket.NewSeed():PkarrRendezvous.MemberSeed(mesh);next.PkarrSequence=0;store.Save(next);profile=next;meshRunner?.UpdateEntries(next);
        }}
    }
    void RememberPkarrPeer(PkarrPeerBinding binding)
    {
        lock(sync){
            if(profile.Mesh is not {} mesh||!PkarrRendezvous.Uses(profile)||!PkarrRendezvous.Matches(binding,mesh))return;
            var prior=profile.PkarrPeers.FirstOrDefault(p=>p.Network==binding.Network&&p.Slot==binding.Slot);
            if(prior==binding&&profile.PkarrStateVersion==1)return;
            if(prior!=null&&prior.Source!=binding.Source&&prior.Device==binding.Device&&prior.SigningKey==binding.SigningKey)throw new IOException("对端 PKARR 发现身份已改变，请重新配对以更新绑定");
            var next=ProfileChanges.Copy(profile);next.PkarrStateVersion=1;next.PkarrPeers=next.PkarrPeers.Where(p=>PkarrRendezvous.Matches(p,mesh)&&p.Slot!=binding.Slot).Append(binding).ToArray();
            next.ExistingEntries=RuntimeEntries(next);store.Save(next);profile=next;meshRunner?.UpdateEntries(next);
        }
    }
    void StartPkarr()
    {
        if(!networkContext||publishingPkarr is {IsCompleted:false})return;
        pkarrStop?.Dispose();pkarrStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        publishingPkarr=Task.Run(()=>RunPkarr(pkarrStop.Token),CancellationToken.None);
    }
    async Task RunPkarr(CancellationToken token)
    {
        using var client=CreatePkarrClient();using var resolver=new ExistingEntryResolver(CreatePkarrClient);
        long began=Environment.TickCount64,nextPublish=0,lastResolved=0,lastPublished=0,publishedAt=0,lastAttempt=0;Guid publishedEntry=Guid.Empty;int failures=0,accepted=0;
        string fingerprint="",observedPayload="",lastError="";string[] cached=[],published=[];
        void Observe(bool enabled,string state,string source=""){
            var active=meshRunner;var peer=active?.PkarrPeer;long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();bool fresh=peer?.State.Expires>now;
            Volatile.Write(ref pkarrStatus,new(enabled,state,source,publishedAt,lastError){Endpoints=published,AcceptedGateways=accepted,TotalGateways=client.GatewayCount,
                PeerSeenAt=peer?.State.ObservedAt??0,PeerExpires=peer?.State.Expires??0,PeerAcknowledged=enabled&&fresh&&peer!.State.AcknowledgedBoot==active!.PkarrBootId&&publishedEntry!=Guid.Empty&&peer.State.AcknowledgedEntry==publishedEntry,QueryError=active?.PkarrQueryError??""});
        }
        try{while(!token.IsCancellationRequested){
            try{
            DeviceProfile current;lock(sync)current=ProfileChanges.Copy(profile);
            if(PkarrRendezvous.Uses(current)){EnsurePkarrIdentity();lock(sync)current=ProfileChanges.Copy(profile);}
            bool selected=PkarrSelected(current);
            if(!selected&&current.Enabled&&PkarrRendezvous.Uses(current)){Observe(true,"仅查询主机地址，等待对端协商双向发现",PkarrPacket.Source(current.PkarrSeed));await Task.Delay(1000,token);continue;}
            if(!selected||!current.Enabled){lastError="";accepted=0;Observe(selected,selected?"等待本机网络启动":"未启用");nextPublish=0;observedPayload="";}
            else{
                EnsurePkarrIdentity();lock(sync)current=ProfileChanges.Copy(profile);
                string source=PkarrPacket.Source(current.PkarrSeed);var active=meshRunner;
                var sources=current.UsesExistingEntriesOnly?current.ExistingEntries.Where(e=>e.PeerSlot==0&&ExistingEntryResolver.Kind(e.Source)!="PKARR").ToArray():[];
                if(sources.Length==0)sources=(active?.PreparedInvitationEntries??[]).Where(e=>ExistingEntryResolver.Kind(e.Source)!="PKARR").ToArray();
                if(Interlocked.Exchange(ref pkarrRefreshRequested,0)!=0)nextPublish=Math.Min(nextPublish,Math.Max(Environment.TickCount64,lastAttempt+5000));
                var remote=active?.PkarrPeer;long utc=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                string observed=current.Mesh!.Pair.Network+"/"+current.PkarrSeed+"/"+current.TransportMode+"/"+string.Join("\n",PkarrGateways(current))+"/"+string.Join("\n",sources.Select(e=>e.Source));
                if(observed!=fingerprint){fingerprint=observed;cached=[];nextPublish=0;}
                string payload=observed+"/"+current.Mesh.Directory!.Revision+"/"+current.DeviceName+"/"+active?.PkarrBootId+"/"+(remote?.State.Expires>utc?remote.State.Boot:Guid.Empty)+"/"+(remote?.State.Expires>utc?remote.State.Entry:Guid.Empty);
                // React once to a change, independently of whether its PUT has
                // succeeded. Re-scheduling the same pending payload every tick
                // would defeat exponential backoff throughout an outage.
                if(payload!=observedPayload){observedPayload=payload;if(nextPublish>Environment.TickCount64)nextPublish=Math.Min(nextPublish,Math.Max(Environment.TickCount64,lastAttempt+5000));}
                if(active?.ReceiverReady!=true||sources.Length==0){Observe(true,"等待本机接收器与入口准备",source);nextPublish=0;}
                else if(Environment.TickCount64>=nextPublish){
                    lastAttempt=Environment.TickCount64;
                    try{
                        if(cached.Length==0||Environment.TickCount64>=lastResolved+Math.Max(5000,(long)current.EntryRefreshSeconds*1000)){
                            var resolved=await resolver.Resolve(sources,current.TransportMode,token);cached=resolved.SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray();lastResolved=Environment.TickCount64;
                        }
                        if(cached.Length==0)throw new IOException("尚无可发布的入口；PKARR 不负责保证入站可达");
                        long sequence=0;
                        lock(sync){
                            // Resolver work may finish after a policy save or a
                            // receiver replacement. Never publish for that old
                            // owner, and never restore its state after a late PUT.
                            if(CurrentPkarrPublication(current,active)){
                                long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;sequence=Math.Max(now,profile.PkarrSequence+1);
                                if(sequence>now+300_000_000)throw new IOException("系统时间明显回退，暂缓 PKARR 发布");
                                var updated=ProfileChanges.Copy(profile);updated.PkarrSequence=sequence;store.Save(updated);profile=updated;
                            }
                        }
                        if(sequence==0){await Task.Delay(1000,token);continue;}
                        var announcement=new PkarrAnnouncement(1,current.TransportMode,DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),cached);
                        var peer=current.Mesh.Directory!.Members.FirstOrDefault(p=>p.Slot!=current.Mesh.Self.Slot);
                        if(PkarrRendezvous.Uses(current)&&current.PkarrStateVersion==1&&peer!=null){
                            long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();var state=new PkarrPeerState(active.PkarrBootId,remote?.State.Expires>now?remote.State.Boot:Guid.Empty,now,now+180,current.DeviceName){AcknowledgedEntry=remote?.State.Expires>now?remote.State.Entry:Guid.Empty};
                            announcement=announcement with{State=PkarrRendezvous.Seal(current.Mesh,peer,source,announcement,state)};
                        }
                        byte[] packet=PkarrPacket.Create(current.PkarrSeed,sequence,announcement);
                        int received=await client.Publish(current.PkarrSeed,packet,token);
                        if(!CurrentPkarrPublication(current,active)){nextPublish=0;await Task.Delay(1000,token);continue;}
                        accepted=received;publishedEntry=announcement.State==null?Guid.Empty:PkarrRendezvous.EntryId(source,announcement,active.PkarrBootId);if(publishedEntry!=Guid.Empty)active.ObservePkarrPublication(publishedEntry);failures=0;lastError="";lastPublished=Environment.TickCount64;publishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();published=cached;
                        bool connected=active.HasHealthyPeers;int interval=peer==null?300000:connected||lastPublished-began>=120000?60000:20000;
                        if(accepted<client.GatewayCount)interval=Math.Min(interval,30000);
                        nextPublish=lastPublished+interval;
                        Observe(true,accepted<client.GatewayCount?$"已发布 · {accepted}/{client.GatewayCount} 个网关，稍后补发":announcement.State!=null?"已发布 · 双向发现运行中":"已发布 · 地址发现",source);
                    }catch(OperationCanceledException)when(token.IsCancellationRequested){throw;}
                    catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or FormatException or CryptographicException or System.Text.Json.JsonException or ArgumentException){
                        accepted=0;lastError=ex.Message;nextPublish=Environment.TickCount64+Math.Min(30000,2000L<<Math.Min(failures++,4))+Random.Shared.Next(250);Observe(true,"发布未完成，正在自动重试",source);
                    }
                }else{
                    var status=Volatile.Read(ref pkarrStatus);Observe(true,status.State,source);
                }
            }
            }catch(OperationCanceledException)when(token.IsCancellationRequested){throw;}
            catch(Exception ex)when(ex is IOException or UnauthorizedAccessException or FormatException or CryptographicException or System.Text.Json.JsonException or ArgumentException){
                // Identity/checkpoint persistence can fail before the actual
                // publication block. A transient storage error must not silently
                // terminate discovery or prevent the network from shutting down.
                accepted=0;lastError=ex.Message;Observe(true,"发现状态暂未保存，正在自动重试");
                await Task.Delay((int)Math.Min(30000,2000L<<Math.Min(failures++,4))+Random.Shared.Next(250),token);
            }
            await Task.Delay(1000,token);
        }}catch(OperationCanceledException)when(token.IsCancellationRequested){}
    }
    async Task StopPkarr(){pkarrStop?.Cancel();try{if(publishingPkarr!=null)await publishingPkarr;}finally{publishingPkarr=null;pkarrStop?.Dispose();pkarrStop=null;}}
}
