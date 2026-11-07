using StreamLink.Core;

namespace StreamLink.Service;

// One bounded resolver batch, polled without blocking packet forwarding. These
// DNS values have no signature and cannot approve, revoke or authenticate peers.
internal sealed class MeshThirdPartyDdns(
    Func<ExistingEntry[],string,CancellationToken,Task<EntryResolution[]>> resolve,
    CancellationToken stop,Func<long>? utcNow=null):IAsyncDisposable
{
    sealed record Hint(string Device,string Key,string[] Endpoints,long Expires);
    readonly Dictionary<int,Hint> cache=[];
    readonly Func<long> utc=utcNow??(()=>DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    Task<EntryResolution[]>? reading;
    CancellationTokenSource? request;
    string identity="",readingIdentity="";
    int generation,readGeneration;
    ExistingEntry[] sources=[];
    long next;
    bool disposed;
    public string ReadState=>identity.Length==0?"":cache.Count>0?$"已取得 {cache.Count} 台设备的第三方地址候选，仍需通过直连认证":reading!=null?"正在查询第三方入口":"尚未取得第三方入口，将按设置间隔重试；手动备用地址仍可使用";
    public void Tick(CloudflareDdnsSettings settings,MeshProfile mesh,string mode,bool readLocal,long now)
    {
        ObjectDisposedException.ThrowIf(disposed,this);
        var members=settings.Enabled?(mesh.Directory?.Members??[]).Where(m=>readLocal||m.Slot!=mesh.Self.Slot).ToArray():[];
        string desired=settings.Enabled?settings.Domain.ToLowerInvariant()+"/"+mesh.Pair.Network+"/"+mode+"/"+readLocal+"/"+settings.RefreshSeconds+"/"+
            string.Join('|',members.Select(m=>$"{m.Slot}:{m.Device}:{m.SigningKey}")):"";
        if(identity!=desired){identity=desired;generation++;request?.Cancel();cache.Clear();next=0;}
        long current=utc();
        foreach(int slot in cache.Keys.ToArray())if(cache[slot].Expires<=current)cache.Remove(slot);
        if(reading?.IsCompleted==true){
            try{
                var results=reading.GetAwaiter().GetResult();
                if(readGeneration==generation&&readingIdentity==identity)foreach(var result in results){
                    if(result.Index<0||result.Index>=sources.Length||sources[result.Index].PeerSlot!=result.PeerSlot)continue;
                    int slot=result.PeerSlot==0?mesh.Self.Slot:result.PeerSlot;
                    var member=members.FirstOrDefault(m=>m.Slot==slot);
                    if(member==null||result.Error.Length>0)continue;
                    // Never resolve returned URLs, infer another device identity,
                    // accept private targets or extend a failed query's lease.
                    var endpoints=result.Endpoints.Where(DdnsAddressRecords.PublicEndpoint).Distinct().Take(4).ToArray();
                    if(endpoints.Length==0)cache.Remove(slot);
                    else cache[slot]=new(member.Device,member.SigningKey,endpoints,current+Math.Clamp(settings.RefreshSeconds*2,60,1200));
                }
            }catch(Exception)when(!stop.IsCancellationRequested){}
            finally{reading=null;request?.Dispose();request=null;}
        }
        if(settings.Enabled&&members.Length>0&&reading==null&&now>=next){
            sources=members.Select(m=>new ExistingEntry(m.Slot==mesh.Self.Slot?0:m.Slot,ThirdPartyDdns.Source(settings.Domain,mesh.Pair.Network,m.Device))).ToArray();
            request=CancellationTokenSource.CreateLinkedTokenSource(stop);request.CancelAfter(25000);
            readingIdentity=identity;readGeneration=generation;reading=Read(sources,mode,request.Token);
            next=now+settings.RefreshSeconds*1000L;
        }
    }
    async Task<EntryResolution[]> Read(ExistingEntry[] entries,string mode,CancellationToken token)=>await resolve(entries,mode,token);
    public string[] ForMember(MeshMember member)=>cache.TryGetValue(member.Slot,out var hint)&&hint.Device==member.Device&&hint.Key==member.SigningKey&&hint.Expires>utc()?hint.Endpoints.ToArray():[];
    public async ValueTask DisposeAsync(){if(disposed)return;disposed=true;request?.Cancel();try{if(reading!=null)try{await reading;}catch{}}finally{request?.Dispose();request=null;reading=null;cache.Clear();}}
}
