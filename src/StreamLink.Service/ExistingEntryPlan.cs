namespace StreamLink.Service;

// One bounded foreground window per peer. Resolver refreshes do not reset the
// deadline or replace healthy transports; recovery/user retry starts a new window.
internal sealed class ExistingEntryPlan
{
    long began;
    bool wasHealthy,admitted;
    string sources="";
    public bool Priority {get;private set;}
    public bool FellBack {get;private set;}
    public string Detail {get;private set;}="";
    public void Retry(){began=0;admitted=false;Priority=false;FellBack=false;}
    public bool Admit(Func<bool> admit){if(admitted)return true;return admitted=admit();}
    public string Select(string[] endpoints,string fallback,bool localEntry,bool healthy,long now,bool existingOnly=false)
    {
        string current=string.Join('|',endpoints);
        if(current!=sources){sources=current;Retry();}
        if(healthy){wasHealthy=true;Priority=false;return "";}
        if(wasHealthy){Retry();wasHealthy=false;}
        if(existingOnly){
            FellBack=false;Priority=endpoints.Length>0||localEntry;
            if(began==0)began=now;
            if(endpoints.Length==0){Detail=localEntry?"等待对端通过本机已有入口连接；不执行自主打洞":"没有可用的已有入口；请检查地址或订阅，或手动切换到自选服务器模式";return "";}
            int index=(int)((now-began)/15000%endpoints.Length);
            Detail=$"仅验证已有入口 {index+1}/{endpoints.Length}：{endpoints[index]}；不执行自主打洞";
            return endpoints[index];
        }
        if(endpoints.Length==0&&!localEntry){Priority=false;return fallback;}
        if(began==0)began=now;
        int count=Math.Clamp(endpoints.Length,1,8);
        Priority=now-began<(endpoints.Length==0&&localEntry?15000:count*4000L);
        Detail=endpoints.Length==0?"本机已有入口已提供给对端，等待对端验证连接":$"正在优先验证已有入口 {Math.Min(count,(int)((now-began)/4000)+1)}/{count}：{endpoints[Math.Min(endpoints.Length-1,(int)((now-began)/4000))]}";
        if(!Priority){FellBack=true;return fallback;}
        return endpoints.Length==0?"":endpoints[Math.Min(endpoints.Length-1,(int)((now-began)/4000))];
    }
}
