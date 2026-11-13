using Android.Content;
using ConWU.Mobile;
using StreamLink.Core;
using System.Collections.Concurrent;

namespace ConWU.Android;

sealed class MobileRuntime
{
    static MobileRuntime? instance;static readonly object instanceGate=new();
    public static MobileRuntime Get(Context context){lock(instanceGate)return instance??=new(context.ApplicationContext!);}
    readonly object gate=new(),pairGate=new();readonly AndroidProfileStore store;
    MobileDeviceState? state;
    CancellationTokenSource? pairStop;
    int autoConnectQueued;
    long networkGeneration;
    MobilePairingProgress pairing=new("");
    string error="";
    readonly ConcurrentQueue<string> logs=new();
    public SemaphoreSlim ConnectionsGate {get;}=new(1,1);
    public CancellationTokenSource? ConnectionsStop {get;set;}
    public Task? ConnectionsTask {get;set;}
    public object? ConnectionsOwner {get;set;}
    public ConcurrentDictionary<string,MobileConnectionStatus> Connections {get;}=new();
    public ReleaseUpdateMonitor Updates {get;}
    public string Version {get;}
    public Task Initialization {get;}
    MobileRuntime(Context context)
    {
        store=new(context);
        Version=context.PackageManager!.GetPackageInfo(context.PackageName!,0)!.VersionName??"1.4.0-preview.1";
        Updates=new(current:Version,platform:"android");
        // Keystore initialization and first-time identity creation must not
        // occupy Android's main thread or delay the first usable window.
        Initialization=Task.Run(()=>{
            try{var restored=store.Load();Volatile.Write(ref state,restored);}
            catch(Exception ex){SetError("无法读取保存的配置，原文件已保留。请检查设备存储或密钥状态。");Log("读取配置失败："+ex.GetType().Name);}
        });
    }
    public string Error=>Volatile.Read(ref error);
    public void SetError(string message){Volatile.Write(ref error,message);if(message.Length>0)Log(message);}
    public bool Ready=>Volatile.Read(ref state)!=null;
    public bool PairingActive=>Volatile.Read(ref pairStop)!=null;
    public MobilePairingProgress Pairing=>Volatile.Read(ref pairing);
    public MobileDeviceState State=>Volatile.Read(ref state)??throw new IOException(Error);
    public MobileNetwork[] Networks=>Volatile.Read(ref state)?.Networks.ToArray()??[];
    public string[] Logs=>logs.ToArray();
    public bool TryAutoConnect()=>Interlocked.CompareExchange(ref autoConnectQueued,1,0)==0;
    public void AutoConnectFinished()=>Interlocked.Exchange(ref autoConnectQueued,0);
    public long NetworkGeneration=>Interlocked.Read(ref networkGeneration);
    public void PhysicalNetworkChanged(){Interlocked.Increment(ref networkGeneration);Log("系统网络已变化，正在重新获取主机入口");}
    public void Log(string message){logs.Enqueue(DateTime.Now.ToString("HH:mm:ss")+" "+message);while(logs.Count>80)logs.TryDequeue(out _);}
    public CancellationTokenSource StartPair()
    {
        lock(pairGate){if(!Ready)throw new IOException(Error);if(pairStop!=null)throw new IOException("已有加入申请，先完成或取消后再试");pairStop=new();Volatile.Write(ref pairing,new("正在发送加入申请"));return pairStop;}
    }
    public void PairProgress(MobilePairingProgress progress)=>Volatile.Write(ref pairing,progress);
    public void CancelPair(){CancellationTokenSource? pending;lock(pairGate)pending=pairStop;if(pending!=null)_=Task.Run(()=>{try{pending.Cancel();}catch(ObjectDisposedException){} });}
    public void CancelOwnedPair(CancellationTokenSource? pending)
    {if(pending==null)return;lock(pairGate){if(pairStop!=pending)return;} _=Task.Run(()=>{try{pending.Cancel();}catch(ObjectDisposedException){} });}
    public void EndPair(CancellationTokenSource pending){lock(pairGate){if(pairStop==pending)pairStop=null;}pending.Dispose();}
    void Commit(MobileNetwork[] networks)
    {
        if(state==null)throw new IOException(Error);
        var updated=new MobileDeviceState{SigningPrivate=state.SigningPrivate,DeviceName=state.DeviceName,Networks=networks};
        store.Save(updated);Volatile.Write(ref state,updated);
    }
    public void Add(MobileNetwork network){lock(gate){if(state==null)throw new IOException(Error);if(state.Networks.Any(n=>n.Id==network.Id))throw new IOException("此网络已经加入，无需重复保存");Commit(state.Networks.Append(network).ToArray());}}
    public void SetEnabled(string id,bool enabled){lock(gate){if(state==null)throw new IOException(Error);if(!state.Networks.Any(n=>n.Id==id))throw new IOException("未找到网络");Commit(state.Networks.Select(n=>n.Id==id?n with{Enabled=enabled}:n).ToArray());}}
    public void SetAllDisabled(){lock(gate){if(state!=null)Commit(state.Networks.Select(n=>n with{Enabled=false}).ToArray());}}
    public void Remove(string id){lock(gate){if(state==null)throw new IOException(Error);Commit(state.Networks.Where(n=>n.Id!=id).ToArray());Connections.TryRemove(id,out _);}}
}
