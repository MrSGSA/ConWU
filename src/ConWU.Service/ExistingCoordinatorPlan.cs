namespace StreamLink.Service;

// Address-source priority only. This never admits a traversal/punch attempt.
internal sealed class ExistingCoordinatorPlan
{
    long started;
    string fingerprint="";
    public bool UsingBackup {get;private set;}
    public string Select(string[] primary,string[] secondary,bool healthy,long now)
    {
        string current=string.Join('|',primary);
        if(fingerprint!=current||started==0){fingerprint=current;started=now;UsingBackup=false;}
        if(healthy)return "";
        var extra=secondary.Except(primary).Distinct().ToArray();
        UsingBackup=now-started>=12000&&extra.Length>0;
        var choices=UsingBackup?extra.Concat(primary).ToArray():primary;
        return choices.Length==0?"":choices[(int)((now-started-(UsingBackup?12000:0))/(UsingBackup?8000:4000)%choices.Length)];
    }
}
