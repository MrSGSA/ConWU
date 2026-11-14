using StreamLink.Core;

namespace StreamLink.Service;

// Coalesce concurrent reads without sharing identity, credentials or cached
// candidate ownership. A selector and the complete URL are part of the key.
internal sealed class SharedEntryResolver : IDisposable
{
    readonly ExistingEntryResolver resolver;
    readonly CancellationTokenSource stopping=new();
    readonly object gate=new();
    readonly Dictionary<(string Source,string Mode,bool Recovery),(long Started,Task<EntryResolution[]> Task)> reads=[];
    bool disposed;
    internal SharedEntryResolver(ExistingEntryResolver? resolver=null)=>this.resolver=resolver??new();
    public Task<EntryResolution[]> Resolve(ExistingEntry[] sources,string mode,CancellationToken token)=>Resolve(sources,mode,false,token);
    public Task<EntryResolution[]> ResolveRecovering(ExistingEntry[] sources,string mode,CancellationToken token)=>Resolve(sources,mode,true,token);
    async Task<EntryResolution[]> Resolve(ExistingEntry[] sources,string mode,bool recovery,CancellationToken token)
    {
        ExistingEntryResolver.Validate(sources);
        return await Task.WhenAll(sources.Select(async(source,index)=>{
            Task<EntryResolution[]> task;long now=Environment.TickCount64;var key=(source.Source,mode,recovery);
            lock(gate){
                ObjectDisposedException.ThrowIf(disposed,this);
                if(reads.TryGetValue(key,out var prior)&&(!prior.Task.IsCompleted||now-prior.Started<1000))task=prior.Task;
                else{
                    foreach(var old in reads.Where(p=>p.Value.Task.IsCompleted&&now-p.Value.Started>=1000).Select(p=>p.Key).ToArray())reads.Remove(old);
                    if(reads.Count>=512)throw new IOException("入口查询队列已满，请稍后重试");
                    task=recovery?resolver.ResolveRecovering([new(0,source.Source)],mode,stopping.Token):resolver.Resolve([new(0,source.Source)],mode,stopping.Token);reads[key]=(now,task);
                    _=task.ContinueWith(t=>{_=t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
                }
            }
            var result=await task.WaitAsync(token);return result.Single() with{PeerSlot=source.PeerSlot,Index=index};
        }));
    }
    public void Dispose(){lock(gate){if(disposed)return;disposed=true;stopping.Cancel();resolver.Dispose();stopping.Dispose();}}
}
