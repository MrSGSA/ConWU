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
    public string Select(string[] endpoints,string fallback,bool localEntry,bool healthy,long now)
    {
        string current=string.Join('|',endpoints);
        if(current!=sources){sources=current;Retry();}
        if(healthy){wasHealthy=true;Priority=false;return "";}
        if(wasHealthy){Retry();wasHealthy=false;}
        if(endpoints.Length==0&&!localEntry){Priority=false;return fallback;}
        if(began==0)began=now;
        int count=Math.Clamp(endpoints.Length,1,8);
        Priority=now-began<(endpoints.Length==0&&localEntry?15000:count*4000L);
        Detail=endpoints.Length==0?"本机已有入口已提供给对端，等待对端验证连接":$"正在优先验证已有入口 {Math.Min(count,(int)((now-began)/4000)+1)}/{count}";
        if(!Priority){FellBack=true;return fallback;}
        return endpoints.Length==0?"":endpoints[Math.Min(endpoints.Length-1,(int)((now-began)/4000))];
    }
}
