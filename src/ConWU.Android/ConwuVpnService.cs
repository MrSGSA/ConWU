using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Net;
using Android.OS;
using ConWU.Mobile;
using StreamLink.Core;
using OperationCanceledException=System.OperationCanceledException;

namespace ConWU.Android;

[Service(Name="io.github.mrsgsa.conwu.ConwuVpnService",Permission="android.permission.BIND_VPN_SERVICE",Exported=true,ForegroundServiceType=ForegroundService.TypeSpecialUse)]
[IntentFilter([VpnService.ServiceInterface])]
public sealed class ConwuVpnService : VpnService
{
    const string Channel="conwu-vpn";
    const int NotificationId=1145;
    MobileRuntime runtime=null!;
    string lastNotification="";
    volatile bool destroying;
    ConnectivityManager? connectivity;
    PhysicalNetworkCallback? networkCallback;
    CancellationTokenSource? ownedPair;
    public override void OnCreate()
    {
        base.OnCreate();runtime=MobileRuntime.Get(this);
        connectivity=(ConnectivityManager?)GetSystemService(ConnectivityService);
        if(connectivity!=null){
            networkCallback=new(runtime);
            try{connectivity.RegisterDefaultNetworkCallback(networkCallback);}
            catch(Java.Lang.RuntimeException){networkCallback.Dispose();networkCallback=null;runtime.Log("系统网络通知暂不可用，继续通过连接保活检测恢复");}
        }
    }
    Notification Notification(string text)
    {
        var manager=(NotificationManager)GetSystemService(NotificationService)!;
        manager.CreateNotificationChannel(new NotificationChannel(Channel,"ConWU 连接",NotificationImportance.Low));
        var intent=PendingIntent.GetActivity(this,0,new Intent(this,typeof(MainActivity)),PendingIntentFlags.Immutable|PendingIntentFlags.UpdateCurrent);
        return new Notification.Builder(this,Channel).SetContentTitle("ConWU").SetContentText(text).SetSmallIcon(Resource.Drawable.conwu_status).SetContentIntent(intent).SetOngoing(true).Build();
    }
    void Notify(string text){if(!destroying&&Interlocked.Exchange(ref lastNotification,text)!=text)((NotificationManager)GetSystemService(NotificationService)!).Notify(NotificationId,Notification(text));}
    public override StartCommandResult OnStartCommand(Intent? intent,StartCommandFlags flags,int startId)
    {
        try{
            if(OperatingSystem.IsAndroidVersionAtLeast(34))StartForeground(NotificationId,Notification("正在准备连接"),ForegroundService.TypeSpecialUse);
            else StartForeground(NotificationId,Notification("正在准备连接"));
        }catch(Exception ex){runtime.AutoConnectFinished();runtime.SetError("系统未允许启动 VPN 前台服务（"+ex.GetType().Name+"），请重新授权后重试");StopSelf();return StartCommandResult.NotSticky;}
        string action=intent?.Action??"connect-saved";
        if(action=="cancel-join"){runtime.CancelPair();return StartCommandResult.Sticky;}
        if(action=="join"){
            string code=intent?.GetStringExtra("code")??"";
            CancellationTokenSource pending;
            try{pending=runtime.StartPair();}catch(IOException){Notify("已有加入申请，请先完成或取消");return StartCommandResult.Sticky;}
            Volatile.Write(ref ownedPair,pending);
            _=Task.Run(()=>Join(code,pending));
        }else _=Task.Run(()=>Change(action,intent?.GetStringExtra("network")??""));
        return StartCommandResult.Sticky;
    }
    async Task Join(string code,CancellationTokenSource pending)
    {
        try{
            var parsed=CompactDirectCode.Import(code);MobileEnrollment.RequireProtocol(parsed.Mode);
            runtime.SetError("");
            var saved=runtime.State;
            var network=await MobileEnrollment.Join(code,saved.SigningPrivate,saved.DeviceName,p=>{runtime.PairProgress(p);Notify(p.State);},pending.Token);
            // Store approved credentials even if Cancel raced with delivery.
            // Cancellation stops a connection, not an already issued identity.
            runtime.Add(network with{Enabled=!pending.IsCancellationRequested&&!destroying});
            runtime.PairProgress(new("已加入 "+network.Name,network.HostName));
            await Reconfigure();
        }catch(OperationCanceledException){runtime.PairProgress(new("加入申请已取消"));}
        catch(Exception ex){runtime.PairProgress(new("加入未完成"));runtime.SetError(SafeError(ex));}
        finally{runtime.EndPair(pending);Interlocked.CompareExchange(ref ownedPair,null,pending);FinishIfIdle();}
    }
    async Task Change(string action,string id)
    {
        try{
            await runtime.Initialization;
            if(destroying)return;
            if(!runtime.Ready)throw new IOException(runtime.Error);
            runtime.SetError("");
            if(action=="disconnect-all"){runtime.CancelPair();runtime.SetAllDisabled();}
            else if(action=="connect")runtime.SetEnabled(id,true);
            else if(action=="disconnect")runtime.SetEnabled(id,false);
            else if(action=="leave")runtime.Remove(id);
            else if(action!="connect-saved")throw new IOException("不支持的从机操作");
            await Reconfigure();
        }catch(Exception ex){runtime.SetError(SafeError(ex));}
        FinishIfIdle();
    }
    async Task Reconfigure()
    {
        await runtime.ConnectionsGate.WaitAsync();
        try{
            if(destroying)return;
            await StopConnections();
            if(destroying)return;
            var networks=runtime.Networks.Where(n=>n.Enabled).ToArray();
            if(networks.Length==0)return;
            if(Prepare(this)!=null)throw new IOException("系统 VPN 授权已失效，请回到 ConWU 重新授权");
            using var builder=new Builder(this);
            builder.SetSession("ConWU").SetMtu(MeshLink.Mtu).SetBlocking(false);
            // Discovery, TLS sockets and local bridges must bypass this VPN.
            // Only other apps' selected virtual destinations enter the tunnel.
            builder.AddDisallowedApplication(PackageName!);
            // Android otherwise chooses the first address even for a different
            // pair's /32 route. Keep one OS source, translate at the VPN edge.
            string systemIp=networks[0].Mesh.LocalIp;builder.AddAddress(systemIp,32);
            foreach(var network in networks)builder.AddRoute(network.HostIp,32);
            var handle=builder.Establish()??throw new IOException("系统未建立 VPN 接口，请确认没有其他 VPN 接管连接");
            var hub=new MobilePacketHub(new AndroidTunAdapter(handle),networks,systemIp);
            var stop=new CancellationTokenSource();runtime.ConnectionsStop=stop;runtime.ConnectionsOwner=this;
            runtime.ConnectionsTask=RunNetworks(hub,networks,stop);
        }finally{runtime.AutoConnectFinished();runtime.ConnectionsGate.Release();}
    }
    async Task RunNetworks(MobilePacketHub hub,MobileNetwork[] networks,CancellationTokenSource stop)
    {
        var jobs=networks.Select(async network=>{
            try{await new MobileGuestSession(network,hub.Adapter(network.Id),runtime.State.DeviceName,status=>{
                runtime.Connections[network.Id]=status;
                if(status.State=="Revoked")runtime.SetEnabled(network.Id,false);
                int connected=runtime.Connections.Values.Count(s=>s.Connected);
                Notify(connected>0?"已直连 "+connected+" 个网络":"正在连接主机");
            }).Run(stop.Token,networkGeneration:()=>runtime.NetworkGeneration);}
            catch(OperationCanceledException)when(stop.IsCancellationRequested){}
            catch(Exception ex){runtime.Connections[network.Id]=new(network.Id,"Error",SafeError(ex));runtime.Log("网络连接结束："+ex.GetType().Name);}
        }).ToArray();
        try{
            var all=Task.WhenAll(jobs);var first=await Task.WhenAny(all,hub.Completion);
            if(first==hub.Completion&&!stop.IsCancellationRequested){runtime.SetError("系统 VPN 通道已停止，请重新连接");stop.Cancel();}
            await all;
        }finally{
            await hub.DisposeAsync();
            foreach(var network in networks)if(runtime.Connections.TryGetValue(network.Id,out var prior)&&prior.State!="Revoked"&&prior.State!="Error")runtime.Connections[network.Id]=new(network.Id,"Stopped","连接已停止");
        }
    }
    async Task StopConnections()
    {
        var stop=runtime.ConnectionsStop;var task=runtime.ConnectionsTask;
        if(stop!=null)stop.Cancel();
        try{if(task!=null)await task;}finally{runtime.ConnectionsStop=null;runtime.ConnectionsTask=null;runtime.ConnectionsOwner=null;stop?.Dispose();}
    }
    void FinishIfIdle(){if(!destroying&&!runtime.PairingActive&&!runtime.Networks.Any(n=>n.Enabled)){StopForeground(StopForegroundFlags.Remove);StopSelf();}}
    public override void OnRevoke(){runtime.CancelPair();_=Task.Run(()=>Change("disconnect-all",""));base.OnRevoke();}
    public override void OnDestroy()
    {
        destroying=true;runtime.CancelOwnedPair(Volatile.Read(ref ownedPair));
        if(networkCallback!=null){try{connectivity?.UnregisterNetworkCallback(networkCallback);}catch(Java.Lang.RuntimeException){}networkCallback.Dispose();networkCallback=null;}
        _=Task.Run(async()=>{await runtime.ConnectionsGate.WaitAsync();try{if(ReferenceEquals(runtime.ConnectionsOwner,this))await StopConnections();}finally{runtime.ConnectionsGate.Release();}});
        base.OnDestroy();
    }
    static string SafeError(Exception error)=>error switch{
        NotSupportedException or FormatException=>error.Message,
        IOException when error.Message.Length<=220&&!error.Message.Contains("https://")=>error.Message,
        _=>"连接暂未完成（"+error.GetType().Name+"）。网络凭据已保留，可重试。"
    };
    sealed class PhysicalNetworkCallback(MobileRuntime runtime):ConnectivityManager.NetworkCallback
    {
        long current=-1;
        public override void OnCapabilitiesChanged(Network network,NetworkCapabilities capabilities)
        {
            if(capabilities.HasTransport(TransportType.Vpn)||!capabilities.HasCapability(NetCapability.Internet))return;
            long handle=network.NetworkHandle;
            if(Interlocked.Exchange(ref current,handle)!=handle)runtime.PhysicalNetworkChanged();
        }
        public override void OnLost(Network network)
        {long handle=network.NetworkHandle;if(Interlocked.CompareExchange(ref current,-1,handle)==handle)runtime.PhysicalNetworkChanged();}
    }
}
