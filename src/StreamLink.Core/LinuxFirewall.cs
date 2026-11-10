using System.Net;

namespace StreamLink.Core;

public static class LinuxFirewall
{
    public static IDisposable AllowStreamListener(int port)
    {
        if(port is <1024 or >65535)throw new ArgumentOutOfRangeException(nameof(port));
        string name="StreamLink-"+Guid.NewGuid().ToString("N");
        string[] spec=["-p","tcp","--dport",port.ToString(System.Globalization.CultureInfo.InvariantCulture),"-m","comment","--comment",name,"-j","ACCEPT"];
        var resource=new LinuxKernelResource(spec);
        try{LinuxPlatform.Run("iptables",new[]{"-w","3","-I","INPUT"}.Concat(spec).ToArray());return resource;}
        catch{resource.Dispose();throw;}
    }
    static readonly object gate=new();
    static readonly Dictionary<string,LinuxKernelResource> owned=[];
    public static void Recover()=>LinuxKernelResource.Recover();
    public static object[] RemainingResources()=>LinuxKernelResource.Remaining();
    public static void Update(string rule,string local,string remote) {
        if(!rule.StartsWith("StreamLink-")||!Guid.TryParseExact(rule[11..],"N",out _))throw new ArgumentException("防火墙规则不属于本实例");
        lock(gate){
            if(owned.TryGetValue(rule,out var prior)){prior.Dispose();owned.Remove(rule);}
            if(remote.Length==0)return;
            if(!IPAddress.TryParse(local,out var ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork||remote.Split(',').Any(r=>!IPAddress.TryParse(r,out _)))throw new ArgumentException("虚拟防火墙地址无效");
            string[] spec=["-s",remote,"-d",local,"-m","comment","--comment",rule,"-j","ACCEPT"];
            var resource=new LinuxKernelResource(spec);
            try{LinuxPlatform.Run("iptables",new[]{"-w","3","-I","INPUT"}.Concat(spec).ToArray());owned[rule]=resource;}
            catch{resource.Dispose();throw;}
        }
    }
}
