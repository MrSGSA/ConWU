using StreamLink.Core;

namespace StreamLink.Service;
internal sealed class EntryBackupPublisher:IDisposable
{
    readonly CancellationTokenSource stop;
    public Task Completion {get;}
    public EntryBackupPublisher(MeshProfile mesh,PairRoomTicket room,UiNetworkSettings settings,string mode,Action<string> log,CancellationToken lifetime)
    {
        stop=CancellationTokenSource.CreateLinkedTokenSource(lifetime);
        Completion=Task.Run(async()=>{
            using var resolver=new ExistingEntryResolver();using var client=new EntryLookupClient(settings.Service,settings.CertificatePin);
            var sources=settings.ExistingEntries.Where(e=>e.PeerSlot==0).ToArray();
            string published="";
            try{
                if(sources.Length==0){log("配对协调未发布入口：请主机填写本机的可达地址或订阅");return;}
                while(!stop.IsCancellationRequested&&room.Expires>DateTimeOffset.UtcNow.ToUnixTimeSeconds()){
                    try{
                        var resolved=await resolver.Resolve(sources,mode,stop.Token);
                        var endpoints=resolved.SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray();
                        if(endpoints.Length>0){await client.Publish(mesh,EntryLookup.Sign(mesh,room,endpoints),stop.Token);string current=string.Join('|',endpoints);if(current!=published){published=current;log("已向配对协调发布主机入口，配对码仍由本机审批");}}
                        else log("配对协调暂未取得可发布入口，原直连配对仍可使用");
                    }catch(Exception ex)when(!stop.IsCancellationRequested&&ex is IOException or HttpRequestException or OperationCanceledException){log("配对入口登记暂未完成，原直连配对继续可用："+ex.GetType().Name);}
                    await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(settings.EntryRefreshSeconds,5,30)),stop.Token);
                }
            }catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        });
    }
    public void Dispose(){stop.Cancel();_=Completion.ContinueWith(t=>{_=t.Exception;stop.Dispose();},CancellationToken.None,TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);}
}
