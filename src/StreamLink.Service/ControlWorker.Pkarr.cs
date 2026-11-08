using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    PkarrStatus pkarrStatus=new(false,"未启用");
    Task? publishingPkarr;CancellationTokenSource? pkarrStop;
    static ExistingEntry[] PkarrHints(DeviceProfile p)=>p.PkarrPublish&&p.PkarrSeed.Length>0?[new(0,PkarrPacket.Source(p.PkarrSeed))]:[];
    void EnsurePkarrIdentity()
    {
        lock(sync){if(profile.PkarrPublish&&profile.Mesh?.IsOwner==true&&profile.PkarrSeed.Length==0){var next=ProfileChanges.Copy(profile);next.PkarrSeed=PkarrPacket.NewSeed();next.PkarrSequence=0;store.Save(next);profile=next;}}
    }
    void StartPkarr()
    {
        if(!networkContext||publishingPkarr is {IsCompleted:false})return;
        pkarrStop?.Dispose();pkarrStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        publishingPkarr=Task.Run(()=>RunPkarr(pkarrStop.Token),CancellationToken.None);
    }
    async Task RunPkarr(CancellationToken token)
    {
        using var client=meshRuntime?.PkarrClientFactory?.Invoke()??new PkarrClient();using var resolver=new ExistingEntryResolver();long nextPublish=0,lastResolved=0,lastPublished=0,publishedAt=0;string fingerprint="",lastPayload="";string[] cached=[],published=[];
        try{while(!token.IsCancellationRequested){
            DeviceProfile current;lock(sync)current=ProfileChanges.Copy(profile);
            if(!current.PkarrPublish||current.Mesh?.IsOwner!=true||!current.Enabled){Volatile.Write(ref pkarrStatus,new(current.PkarrPublish,current.PkarrPublish?"等待主机网络启动":"未启用"));nextPublish=0;}
            else{
                var sources=current.ExistingEntries.Where(e=>e.PeerSlot==0&&ExistingEntryResolver.Kind(e.Source)!="PKARR").ToArray();
                if(sources.Length==0)sources=(meshRunner?.PreparedInvitationEntries??[]).Where(e=>ExistingEntryResolver.Kind(e.Source)!="PKARR").ToArray();
                string observed=current.Mesh.Pair.Network+"/"+current.TransportMode+"/"+current.EntryRefreshSeconds+"/"+string.Join("\n",sources.Select(e=>e.Source));
                if(observed!=fingerprint){fingerprint=observed;cached=[];nextPublish=0;}
                if(Environment.TickCount64>=nextPublish){
                try{
                    if(!await requests.WaitAsync(0,token)){await Task.Delay(1000,token);continue;}
                    try{EnsurePkarrIdentity();lock(sync)current=ProfileChanges.Copy(profile);}finally{requests.Release();}
                    string source=PkarrPacket.Source(current.PkarrSeed);
                    Volatile.Write(ref pkarrStatus,new(true,"正在检查入口公告",source,publishedAt){Endpoints=published});
                    long interval=Math.Max(5000,(long)current.EntryRefreshSeconds*1000);
                    if(cached.Length==0||Environment.TickCount64>=lastResolved+interval){
                        var resolved=sources.Length>0?await resolver.Resolve(sources,current.TransportMode,token):[];
                        cached=resolved.SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray();lastResolved=Environment.TickCount64;
                    }
                    var endpoints=cached;
                    if(endpoints.Length==0)throw new IOException("尚无可发布的入口；PKARR 不负责打洞");
                    string payload=current.TransportMode+"/"+string.Join(",",endpoints);
                    if(payload==lastPayload&&Environment.TickCount64<lastPublished+300000){
                        Volatile.Write(ref pkarrStatus,new(true,"已发布 · 地址未变",source,publishedAt){Endpoints=published});
                        nextPublish=Math.Min(lastResolved+interval,lastPublished+300000);continue;
                    }
                    long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000,sequence;
                    if(!await requests.WaitAsync(0,token)){nextPublish=Environment.TickCount64+1000;continue;}
                    try{lock(sync){if(!profile.PkarrPublish||profile.Mesh?.Pair.Network!=current.Mesh!.Pair.Network||profile.PkarrSeed!=current.PkarrSeed)continue;sequence=Math.Max(now,profile.PkarrSequence+1);if(sequence>now+300_000_000)throw new IOException("系统时间明显回退，暂缓 PKARR 发布");var updated=ProfileChanges.Copy(profile);updated.PkarrSequence=sequence;store.Save(updated);profile=updated;}}finally{requests.Release();}
                    byte[] packet=PkarrPacket.Create(current.PkarrSeed,sequence,new(1,current.TransportMode,DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),endpoints));
                    int gateways=await client.Publish(current.PkarrSeed,packet,token);
                    lastPublished=Environment.TickCount64;publishedAt=DateTimeOffset.UtcNow.ToUnixTimeSeconds();published=endpoints;lastPayload=payload;
                    Volatile.Write(ref pkarrStatus,new(true,$"已发布 · {gateways} 个网关接受公告",source,publishedAt){Endpoints=endpoints});nextPublish=Math.Min(lastResolved+interval,lastPublished+300000);
                }catch(OperationCanceledException)when(token.IsCancellationRequested){throw;}
                catch(Exception ex)when(ex is IOException or FormatException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or ArgumentException){Volatile.Write(ref pkarrStatus,new(true,"发布未完成",current.PkarrSeed.Length>0?PkarrPacket.Source(current.PkarrSeed):"",publishedAt,ex.Message){Endpoints=published});nextPublish=Environment.TickCount64+30_000;}
                }
            }
            await Task.Delay(5000,token);
        }}catch(OperationCanceledException)when(token.IsCancellationRequested){}
    }
    async Task StopPkarr(){pkarrStop?.Cancel();try{if(publishingPkarr!=null)await publishingPkarr;}finally{publishingPkarr=null;pkarrStop?.Dispose();pkarrStop=null;}}
}
