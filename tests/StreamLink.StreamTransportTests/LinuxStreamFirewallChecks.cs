using StreamLink.Core;

static class LinuxStreamFirewallChecks
{
    public static void Run()
    {
        if(!OperatingSystem.IsLinux()||LinuxPlatform.geteuid()!=0||new FileInfo("/proc/self/ns/net").LinkTarget==new FileInfo("/proc/1/ns/net").LinkTarget)
            throw new IOException("Firewall verification requires root in an isolated network namespace");
        string folder=Path.Combine(Path.GetTempPath(),"conwu-stream-firewall-"+Guid.NewGuid().ToString("N"));
        string? previous=Environment.GetEnvironmentVariable("STREAMLINK_PROFILE_ROOT");Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",folder);
        try{
            string baseline=LinuxPlatform.Run("iptables","-S","INPUT");
            using(var access=LinuxFirewall.AllowStreamListener(48443)){
                string rule=LinuxPlatform.Run("iptables","-S","INPUT");
                if(!rule.Contains("--dport 48443")||LinuxFirewall.RemainingResources().Length!=1)throw new IOException("stream listener was not recorded precisely");
                LinuxFirewall.Recover();
                if(LinuxPlatform.Run("iptables","-S","INPUT")!=rule)throw new IOException("recovery removed a live owner");
            }
            if(LinuxPlatform.Run("iptables","-S","INPUT")!=baseline||LinuxFirewall.RemainingResources().Length!=0)throw new IOException("owned stream firewall rule was not released");
            Console.WriteLine("PASS Linux stream firewall allows only the selected TCP port, retains live owners, and removes its own journal/rule on release");
        }finally{Environment.SetEnvironmentVariable("STREAMLINK_PROFILE_ROOT",previous);if(Directory.Exists(folder))Directory.Delete(folder,true);}
    }
}
