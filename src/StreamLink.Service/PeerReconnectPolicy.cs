namespace StreamLink.Service;

// A coordinator supplies presence. Serverless networks have no independent
// presence channel, so an unanswered entry is checked infrequently after one
// bounded foreground attempt rather than recreating native workers forever.
internal sealed class PeerReconnectPolicy
{
    long began,next;
    int failures;
    string endpoints="";
    bool wasFresh;
    public void Wake(){began=next=0;failures=0;}
    public bool Allow(bool direct,bool healthy,bool fresh,string[] hints,long now)
    {
        if(healthy){Wake();wasFresh=fresh;return true;}
        if(!direct)return fresh;
        string current=string.Join('|',hints);
        if(current!=endpoints||fresh&&!wasFresh){Wake();endpoints=current;}
        wasFresh=fresh;
        if(now<next)return false;
        if(began==0)began=now;
        if(now-began<18000)return true;
        began=0;next=now+Math.Min(300000,60000L<<Math.Min(failures++,2));return false;
    }
}
