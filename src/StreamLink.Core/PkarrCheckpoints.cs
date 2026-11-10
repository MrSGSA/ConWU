using System.Security.Cryptography;

namespace StreamLink.Core;

public sealed record PkarrCheckpoint(string Key,long Sequence,string Digest);

// The store belongs to a protected device/network directory. No locator is
// accepted until its high-water mark has been committed. Settings transactions
// never restore this independent record.
public sealed class PkarrCheckpoints(Func<PkarrCheckpoint[]>? read=null,Action<PkarrCheckpoint[]>? write=null,bool allowVolatileEviction=false)
{
    public const int Maximum=256;
    readonly object gate=new();
    Dictionary<string,PkarrCheckpoint>? entries;
    readonly Dictionary<string,int> unchangedQueries=new(StringComparer.Ordinal);
    readonly Dictionary<string,long> touched=new(StringComparer.Ordinal);long access;
    Dictionary<string,PkarrCheckpoint> Load()
    {
        if(entries!=null)return entries;
        var saved=read?.Invoke()??[];
        if(saved.Length>Maximum)throw new IOException("PKARR 防回退记录超过上限");
        var loaded=new Dictionary<string,PkarrCheckpoint>(StringComparer.Ordinal);
        foreach(var item in saved){
            PkarrPacket.DecodeKey(item.Key);
            if(item.Sequence<=0||item.Digest is not {Length:64}||!item.Digest.All(char.IsAsciiHexDigit)||!loaded.TryAdd(item.Key,item))throw new IOException("PKARR 防回退记录无效，请检查本机存储");
        }
        return entries=loaded;
    }
    static string Digest(PkarrRecord record)=>Convert.ToHexString(SHA256.HashData(record.Packet));
    public bool Accepts(string key,PkarrRecord record)
    {
        lock(gate){var all=Load();if(all.ContainsKey(key))touched[key]=++access;return !all.TryGetValue(key,out var prior)||record.Sequence>prior.Sequence||record.Sequence==prior.Sequence&&prior.Digest==Digest(record);}
    }
    public bool Reconcile(string key)
    {
        lock(gate){if(!Load().ContainsKey(key))return false;int count=unchangedQueries.GetValueOrDefault(key)+1;unchangedQueries[key]=count>=3?0:count;return count>=3;}
    }
    public bool Advances(string key,PkarrRecord record){lock(gate)return !Load().TryGetValue(key,out var prior)||record.Sequence>prior.Sequence;}
    public void Remember(string key,PkarrRecord record)
    {
        lock(gate){
            var all=Load();string digest=Digest(record);
            if(all.TryGetValue(key,out var prior)){
                if(record.Sequence<prior.Sequence||record.Sequence==prior.Sequence&&digest!=prior.Digest)throw new IOException("PKARR 网关返回了旧公告或冲突公告");
                if(record.Sequence==prior.Sequence)return;
            }
            var next=new Dictionary<string,PkarrCheckpoint>(all,StringComparer.Ordinal);
            if(!all.ContainsKey(key)&&all.Count>=Maximum){
                if(!allowVolatileEviction||read!=null||write!=null)throw new IOException("PKARR 防回退记录已满，未遗忘已有网络的记录");
                string oldest=all.Keys.MinBy(k=>touched.GetValueOrDefault(k))!;next.Remove(oldest);touched.Remove(oldest);unchangedQueries.Remove(oldest);
            }
            next[key]=new(key,record.Sequence,digest);
            write?.Invoke(next.Values.OrderBy(p=>p.Key,StringComparer.Ordinal).ToArray());entries=next;unchangedQueries.Remove(key);
            touched[key]=++access;
        }
    }
}
