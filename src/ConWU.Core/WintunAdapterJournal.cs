using System.Text.Json;
using System.Runtime.Versioning;

namespace StreamLink.Core;

// The protected local device identity remains the exclusive ownership scope
// across network deletion and approved member-slot rotation. The actual
// Windows adapter gets a fresh generation: reusing a removed GUID can leave
// Windows at CM_PROB_NEED_CLASS_CONFIG even after official Close completed.
// This protected, bounded intent journal survives process exits and lets the
// installer identify every adapter it may clean. It contains no credentials.
[SupportedOSPlatform("windows")]
internal static class WintunAdapterJournal
{
    const int Maximum=512;
    internal sealed record LegacyScope(string Network,int Slot);
    sealed record Journal(int Schema,Guid Scope,Guid[] Generations,LegacyScope[]? Legacy=null,long LastClosedAt=0,bool FailedCreate=false);
    internal sealed record Preparation(WintunIdentity Identity,HashSet<string> VerifiedOrphans);
    static string PathFor(WintunIdentity scope)=>Path.Combine(WintunIdentity.StorageRoot,scope.Guid.ToString("N")+"-adapters.json");
    static Journal Load(WintunIdentity scope)
    {
        string path=PathFor(scope);
        if(!File.Exists(path))return new(1,scope.Guid,[]);
        if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0||new FileInfo(path).Length>131072)throw new IOException("Wintun 实例记录无效，未操作其他网卡");
        var state=JsonSerializer.Deserialize<Journal>(File.ReadAllText(path))??throw new IOException("Wintun 实例记录为空");
        if(state.Schema!=1||state.Scope!=scope.Guid||state.Generations is not {Length:<=Maximum}||state.Generations.Any(g=>g==Guid.Empty||g==scope.Guid)||state.Generations.Distinct().Count()!=state.Generations.Length)
            throw new IOException("Wintun 实例记录身份不符，未操作其他网卡");
        if(state.Legacy is {Length:>Maximum})throw new IOException("Wintun 旧版实例记录过多");
        foreach(var old in state.Legacy??[])_ = WintunIdentity.For(old.Network,old.Slot);
        return state;
    }
    internal static WintunIdentity[] Read(WintunIdentity scope,LegacyScope? legacy=null)
    {
        var state=Load(scope);
        return state.Generations.Select(scope.Generation).Concat((state.Legacy??[]).Concat(legacy==null?[]:[legacy]).Select(l=>WintunIdentity.For(l.Network,l.Slot))).Append(scope).Distinct().ToArray();
    }
    internal static void RememberLegacy(WintunIdentity scope,LegacyScope? legacy)
    {
        var state=Load(scope);var rows=WindowsInterfaceInventory.Read().Select(r=>r.Guid).ToHashSet();
        Save(scope,state.Generations.Where(rows.Contains).Select(scope.Generation),
            (state.Legacy??[]).Concat(legacy==null?[]:[legacy]).Distinct().Where(l=>rows.Contains(WintunIdentity.For(l.Network,l.Slot).Guid)).ToArray(),state.LastClosedAt,state.FailedCreate);
    }
    internal static void MarkClosed(WintunIdentity scope,bool failedCreate=false)
    {
        var state=Load(scope);Save(scope,state.Generations.Select(scope.Generation),state.Legacy??[],DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),failedCreate);
    }
    static void Save(WintunIdentity scope,IEnumerable<WintunIdentity> generations,LegacyScope[] legacy,long closedAt,bool failedCreate=false)
    {
        var ids=generations.Select(g=>g.Guid).Distinct().ToArray();
        if(ids.Length>Maximum||legacy.Length>Maximum)throw new IOException("本实例的 Wintun 残留记录已达上限，请保留日志并修复安装");
        string path=PathFor(scope),temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Wintun 实例记录不能是链接");
        try{
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){
                JsonSerializer.Serialize(stream,new Journal(1,scope.Guid,ids,legacy,closedAt,failedCreate));stream.Flush(true);
            }
            File.Move(temporary,path,true);
        }finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    internal static Preparation Prepare(WintunIdentity scope,CancellationToken token,Action<string> trace,LegacyScope? legacy=null)
    {
        var state=Load(scope);var known=Read(scope,legacy);
        long deadline=Environment.TickCount64+3000;
        while(known.Any(WintunMaintenance.DevicePresent)){
            token.ThrowIfCancellationRequested();
            if(Environment.TickCount64>=deadline)throw new IOException("旧 Wintun 设备仍在退出，未创建第二个网卡实例，请稍后重试");
            trace("previous-device-wait");if(token.WaitHandle.WaitOne(100))token.ThrowIfCancellationRequested();
        }
        var rows=WindowsInterfaceInventory.Read(token);var verified=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void VerifyRows(){
            verified.Clear();
            foreach(var identity in known){
                token.ThrowIfCancellationRequested();
                if(rows.Any(r=>r.Name.Equals(identity.Name,StringComparison.OrdinalIgnoreCase)&&r.Guid!=identity.Guid))throw new IOException("同名网卡不属于本实例，未创建新网卡");
                var row=rows.SingleOrDefault(r=>r.Guid==identity.Guid);if(row==null)continue;
                WintunMaintenance.RequireOrphanIdentity(identity,row.Name,row.Description);
                if(WintunMaintenance.DevicePresent(identity))throw new IOException("旧 Wintun 设备在复核期间重新出现，未接管或卸载");
                verified.Add(identity.Guid.ToString("B"));verified.Add(identity.Guid.ToString("D"));
                verified.Add("WindowsInterface:"+row.Luid.ToString("X16"));
            }
        }
        VerifyRows();
        long closedAt=state.LastClosedAt;
        if(verified.Count>0||state.FailedCreate){
            // Actual official-API A/B on this Windows build: immediate fresh
            // GUID recreation still fails CM_PROB_NEED_CLASS_CONFIG (0x38),
            // while a 30-second post-close settling interval succeeds. Pending
            // install events already report idle, so that API is insufficient.
            // Normal hosts with no orphan row incur no delay. Persisted close
            // time includes service restart/upgrade and cancellation is prompt.
            long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if(closedAt<=0||closedAt>now)closedAt=now;
            long until=Environment.TickCount64+Math.Max(0,30000-Math.Clamp(now-closedAt,0,30000));
            while(Environment.TickCount64<until){
                token.ThrowIfCancellationRequested();trace("previous-adapter-settle-wait/"+((until-Environment.TickCount64+999)/1000));
                if(token.WaitHandle.WaitOne(100))token.ThrowIfCancellationRequested();
            }
            // Recheck the exact PnP identities after the cooperative wait.
            if(known.Any(WintunMaintenance.DevicePresent))throw new IOException("旧 Wintun 设备在等待期间重新出现；未接管或卸载");
        }
        rows=WindowsInterfaceInventory.Read(token);VerifyRows();
        var next=scope.Generation(Guid.NewGuid());
        var surviving=rows.Select(r=>r.Guid).ToHashSet();
        Save(scope,state.Generations.Where(surviving.Contains).Select(scope.Generation).Append(next),
            (state.Legacy??[]).Concat(legacy==null?[]:[legacy]).Distinct().Where(l=>surviving.Contains(WintunIdentity.For(l.Network,l.Slot).Guid)).ToArray(),closedAt);
        trace("adapter-generation-recorded");return new(next,verified);
    }
}
