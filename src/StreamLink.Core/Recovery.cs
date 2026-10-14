using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;

namespace StreamLink.Core;

[SupportedOSPlatform("windows")]
public static class Recovery
{
    sealed record Owner(int Pid,long StartTicks,string Rule);
    public static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),PersonalFeature.InstanceName,"sessions");
    public static void Record(string folder,string rule)
    {
        using var process=Process.GetCurrentProcess();
        File.WriteAllText(Path.Combine(folder,"owner.json"),JsonSerializer.Serialize(new Owner(process.Id,process.StartTime.ToUniversalTime().Ticks,rule)));
    }
    public static void Recover(Action<string> log, string? sessionsRoot = null)
    {
        string root = sessionsRoot ?? Root;
        if(!Directory.Exists(root)) return;
        foreach(string folder in Directory.EnumerateDirectories(root))
        {
            if(!Guid.TryParseExact(Path.GetFileName(folder),"N",out _)) continue;
            string ownerFile=Path.Combine(folder,"owner.json");
            if(!File.Exists(ownerFile)) continue;
            try
            {
                var owner=JsonSerializer.Deserialize<Owner>(File.ReadAllText(ownerFile));
                if(owner==null || !owner.Rule.StartsWith("StreamLink-",StringComparison.Ordinal) || !Guid.TryParseExact(owner.Rule[11..],"N",out _)) continue;
                bool alive=false;
                try {using var p=Process.GetProcessById(owner.Pid); alive=p.StartTime.ToUniversalTime().Ticks==owner.StartTicks;} catch(ArgumentException) { }
                if(alive) continue;
                WindowsHost.RemoveFirewall(owner.Rule);
                foreach(string name in new[]{"network.toml","transport.conf","owner.json","owned-rule.txt"}) File.Delete(Path.Combine(folder,name));
                foreach (string path in Directory.EnumerateFiles(folder, "raw-*.conf"))
                    if (Guid.TryParseExact(Path.GetFileNameWithoutExtension(path)[4..], "N", out _)) File.Delete(path);
                log("已恢复清理上次异常退出留下的本软件规则与临时密钥");
            }
            catch(Exception ex) { log("旧会话清理未确认："+ex.Message); }
        }
    }
}
