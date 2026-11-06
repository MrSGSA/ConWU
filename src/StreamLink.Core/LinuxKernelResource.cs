using System.Text.Json;

namespace StreamLink.Core;

// A locked, private journal survives abrupt daemon exit. Recovery is restricted
// to this profile and this network namespace, and skips every live owner.
internal sealed class LinuxKernelResource : IDisposable
{
    sealed record Entry(string Namespace,string Table,string[]? Rule);
    static string Root=>Path.Combine(Path.GetDirectoryName(UnixControlProtocol.SocketPath)!,"kernel-resources");
    static string Namespace=>new FileInfo("/proc/self/ns/net").LinkTarget??throw new IOException("无法确认网络命名空间");
    readonly string path;readonly FileStream lease;readonly Entry entry;bool disposed;
    public string Table=>entry.Table;
    public LinuxKernelResource(string[]? rule=null) {
        LinuxPlatform.PrivateDirectory(Root);
        path=Path.Combine(Root,Guid.NewGuid().ToString("N")+".json");
        entry=new(Namespace,rule==null?"sl_"+Guid.NewGuid().ToString("N")[..16]:"",rule);
        lease=new(path,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.ReadWrite,Share=FileShare.None,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite});
        try{JsonSerializer.Serialize(lease,entry);lease.Flush(true);}catch{lease.Dispose();File.Delete(path);throw;}
    }
    static void Cleanup(Entry value) {
        if(value.Rule is {} rule) {
            if(rule.Length!=10||rule[0]!="-s"||rule[2]!="-d"||rule[4]!="-m"||rule[5]!="comment"||rule[6]!="--comment"||!rule[7].StartsWith("StreamLink-")||rule[8]!="-j"||rule[9]!="ACCEPT")throw new IOException("无效的防火墙回收记录");
            // Only remove the exact tuple and random ownership comment.
            var listing=LinuxPlatform.Run("iptables","-w","3","-S","INPUT");
            if(listing.Contains(rule[7],StringComparison.Ordinal))LinuxPlatform.Run("iptables",new[]{"-w","3","-D","INPUT"}.Concat(rule).ToArray());
        }else {
            if(value.Table.Length!=19||!value.Table.StartsWith("sl_")||!value.Table[3..].All(char.IsAsciiHexDigit))throw new IOException("无效的原生规则回收记录");
            if(LinuxPlatform.Run("nft","list","tables").Split('\n').Any(l=>l.Trim()=="table inet "+value.Table))LinuxPlatform.Run("nft","delete","table","inet",value.Table);
        }
    }
    public static void Recover() {
        if(!Directory.Exists(Root))return;LinuxPlatform.PrivateDirectory(Root);
        foreach(string file in Directory.EnumerateFiles(Root,"*.json")) {
            if((File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0)throw new IOException("资源记录不能为符号链接");
            FileStream held;try{held=new(file,FileMode.Open,FileAccess.ReadWrite,FileShare.None);}catch(IOException){continue;}
            bool removed=false;
            using(held){if(held.Length>4096)throw new IOException("资源回收记录过大");var value=JsonSerializer.Deserialize<Entry>(held)??throw new IOException("资源回收记录为空");if(value.Namespace!=Namespace)continue;Cleanup(value);removed=true;}
            if(removed)File.Delete(file);
        }
    }
    public void Dispose(){if(disposed)return;try{Cleanup(entry);File.Delete(path);disposed=true;}finally{lease.Dispose();}}
}
