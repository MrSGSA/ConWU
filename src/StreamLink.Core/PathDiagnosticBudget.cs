namespace StreamLink.Core;

public sealed record PathDiagnosticCost(Guid SessionId, long WirePackets, long WireBytes, long Denied,
    long ElapsedMs, bool Active);

// Independent from maintenance/search: a diagnostic never gets another search
// allowance or silently runs as ordinary business. One machine session, one
// window at a time, and one fixed session deadline/byte ceiling across paths.
internal sealed class PathDiagnosticResources(TimeProvider? clock = null)
{
    public static PathDiagnosticResources Shared { get; } = new();
    readonly object gate = new();
    readonly TimeProvider time = clock ?? TimeProvider.System;
    PathDiagnosticPermit? current;
    public PathDiagnosticPermit? TryBegin(Guid session)
    {
        if(session==Guid.Empty)throw new ArgumentException("Diagnostic session identity required");
        lock(gate){if(current?.Active==true)return null;return current=new(session,time);}
    }
}

internal sealed class PathDiagnosticPermit(Guid session,TimeProvider time):IDisposable
{
    internal const int SessionMs=90000,MaximumBytes=256*1024*1024,MaximumWindowMs=15000;
    readonly object gate=new();
    readonly long began=time.GetTimestamp();
    long packets,bytes,denied;
    bool disposed;
    PathDiagnosticAllowance? window;
    public Guid SessionId=>session;
    public bool Active=>!Volatile.Read(ref disposed)&&time.GetElapsedTime(began).TotalMilliseconds<SessionMs;
    public PathDiagnosticCost Snapshot(){lock(gate)return new(session,packets,bytes,denied,(long)time.GetElapsedTime(began).TotalMilliseconds,Active);}
    public PathDiagnosticAllowance Open(Guid path,int wireMbps,int durationMs)
    {
        if(path==Guid.Empty||wireMbps is<1 or>100||durationMs is<100 or>MaximumWindowMs)throw new ArgumentException("Bounded diagnostic window parameters invalid");
        lock(gate){
            if(!Active||window?.Active==true)throw new InvalidOperationException("One diagnostic window must finish before another starts");
            if(time.GetElapsedTime(began).TotalMilliseconds+durationMs>SessionMs)throw new InvalidOperationException("Session has insufficient remaining time");
            return window=new(this,path,wireMbps,durationMs,time);
        }
    }
    internal bool Admit(PathDiagnosticAllowance source,int length)
    {
        lock(gate){
            if(!Active||!ReferenceEquals(window,source)||length>MaximumBytes-bytes){denied++;return false;}
            packets++;bytes+=length;return true;
        }
    }
    internal void Reject(){lock(gate)denied++;}
    public void Dispose(){lock(gate)disposed=true;}
}

internal sealed class PathDiagnosticAllowance(PathDiagnosticPermit owner,Guid path,int wireMbps,int durationMs,TimeProvider time):IDisposable
{
    readonly object gate=new();
    readonly long began=time.GetTimestamp();
    readonly long maximumBytes=(long)Math.Ceiling(wireMbps*125d*durationMs)+4*1536;
    long at=time.GetTimestamp(),bytes;
    // Shared egress pacing supplies the actual four-frame bursts. This small
    // final gate tolerates scheduler jitter; it cannot create an unbounded queue.
    readonly double burst=Math.Max(4*1536,wireMbps*125d*20);
    double tokens=4*1536;
    bool disposed;
    public Guid PathId=>path;
    public Guid SessionId=>owner.SessionId;
    internal int MaximumSourceCredit => Math.Max(4,(int)(burst/1536));
    public bool Active=>!Volatile.Read(ref disposed)&&owner.Active&&time.GetElapsedTime(began).TotalMilliseconds<durationMs;
    internal double DelaySeconds(int length)
    {
        lock(gate){
            if(!Active||length is<512 or>1536||length>maximumBytes-bytes)return 0;
            double available=Math.Min(burst,tokens+time.GetElapsedTime(at).TotalMilliseconds*wireMbps*125d);
            return Math.Max(0,(length-available)/(wireMbps*125000d));
        }
    }
    public bool Admit(int length)
    {
        lock(gate){
            if(!Active||length is<512 or>1536||length>maximumBytes-bytes){owner.Reject();return false;}
            long now=time.GetTimestamp();tokens=Math.Min(burst,tokens+time.GetElapsedTime(at,now).TotalMilliseconds*wireMbps*125d);at=now;
            if(tokens<length){owner.Reject();return false;}
            if(!owner.Admit(this,length))return false;
            tokens-=length;bytes+=length;return true;
        }
    }
    public void Dispose(){lock(gate)disposed=true;}
}

internal interface IPathDiagnosticWire
{
    bool SupportsDiagnosticWire { get; }
    void GrantDiagnosticWire(PathDiagnosticAllowance allowance);
}
