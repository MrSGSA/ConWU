using Android.App;
using Android.Content;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.Net;
using Android.OS;
using Android.Text;
using Android.Views;
using Android.Widget;
using ConWU.Mobile;
using StreamLink.Core;

namespace ConWU.Android;

[Activity(Label="ConWU",MainLauncher=true,Exported=true)]
public sealed class MainActivity : Activity
{
    MobileRuntime runtime=null!;
    EditText code=null!;TextView error=null!,pairing=null!,updateState=null!,empty=null!;
    Button join=null!,cancel=null!,check=null!,download=null!;LinearLayout networkList=null!;
    CheckBox uuEnabled=null!;TextView uuState=null!,uuNetworks=null!;
    readonly Handler handler=new(Looper.MainLooper!);
    Java.Lang.Runnable? pulse;
    readonly Dictionary<string,(TextView Info,Button Connect)> rows=new();
    string networkSignature="",pendingAction="",pendingCode="",pendingNetwork="";
    bool visible,destroyed,autoConnectAttempted;
    int Dp(int value)=>(int)(value*Resources!.DisplayMetrics!.Density+.5f);
    protected override void OnCreate(Bundle? saved)
    {
        base.OnCreate(saved);runtime=MobileRuntime.Get(this);pulse=new(Pulse);
        pendingAction=saved?.GetString("pending-action")??"";pendingCode=saved?.GetString("pending-code")??"";pendingNetwork=saved?.GetString("pending-network")??"";
        var scroll=new ScrollView(this){FillViewport=true};
        var body=new LinearLayout(this){Orientation=Orientation.Vertical};body.SetPadding(Dp(20),Dp(24),Dp(20),Dp(24));scroll.AddView(body);
        var frame=new FrameLayout(this);frame.SetFitsSystemWindows(true);frame.AddView(scroll);SetContentView(frame);
        if(Window!=null)Window.DecorView.SystemUiFlags=SystemUiFlags.LightStatusBar|SystemUiFlags.LightNavigationBar;
        body.AddView(Label("ConWU",30,true));body.AddView(Label("连接自己的串流主机",15));
        body.AddView(Label("加入网络",22,true),Spacing());
        body.AddView(Label("填写主机生成的 16 位直连码，核对校验码后等待主机批准。",14));
        code=new EditText(this){Hint="XXXX-XXXX-XXXX-XXXX",TextSize=21,Gravity=GravityFlags.Center,InputType=InputTypes.ClassText|InputTypes.TextVariationVisiblePassword};
        code.SetSingleLine(true);code.SetFilters([new InputFilterLengthFilter(64)]);code.AddTextChangedListener(new CodeWatcher(code));
        code.Text=saved?.GetString("code")??"";body.AddView(code,new LinearLayout.LayoutParams(-1,Dp(60)));
        var actions=new LinearLayout(this){Orientation=Orientation.Horizontal};
        var paste=Action("粘贴",()=>{var clipboard=(global::Android.Content.ClipboardManager)GetSystemService(ClipboardService)!;code.Text=clipboard.PrimaryClip?.GetItemAt(0)?.CoerceToText(this)?.ToString()??"";code.SetSelection(code.Text?.Length??0);});
        actions.AddView(paste,new LinearLayout.LayoutParams(0,Dp(48),1));
        join=Action("请求加入",()=>Request("join",code.Text??""),true);actions.AddView(join,new LinearLayout.LayoutParams(0,Dp(48),2));body.AddView(actions);
        pairing=Label("",15);body.AddView(pairing,Spacing());
        cancel=Action("取消申请",()=>Start("cancel-join","",""));body.AddView(cancel);
        error=Label("",14);error.SetTextColor(Color.Rgb(185,28,28));body.AddView(error,Spacing());
        body.AddView(Label("已加入的网络",22,true),Spacing());
        empty=Label("暂无网络。手机仅作为从机，主机请使用 Windows 或 Linux 版。",14);body.AddView(empty);
        networkList=new LinearLayout(this){Orientation=Orientation.Vertical};body.AddView(networkList);
        body.AddView(Label("HTTPS 与纯 TCP 可用于手机；其他协议请在主机另建兼容网络。仅 ConWU 虚拟地址进入 VPN。",13),Spacing());
        body.AddView(Label("UU 远程接管",22,true),Spacing());
        uuEnabled=new CheckBox(this){Text="配合主机接管 UU 串流"};
        uuEnabled.CheckedChange+=(_,_)=>{if(runtime.Ready&&runtime.State.UuTakeoverEnabled!=uuEnabled.Checked){try{runtime.SetUuTakeover(uuEnabled.Checked);}catch(Exception){runtime.SetError("UU 接管设置未能保存");}Update();}};body.AddView(uuEnabled);
        body.AddView(Label("先在目标 Windows 主机开启 UU 接管，再连接 ConWU 网络并重连 UU。所有已直连网络自动参与；只有观察到 UU 应用经过 VPN 的持续流量才显示传输成功。",13));
        uuState=Label("未开启",14);body.AddView(uuState);uuNetworks=Label("",13);body.AddView(uuNetworks);
        body.AddView(Action("打开 UU 远程",()=>{var intent=PackageManager!.GetLaunchIntentForPackage(AndroidUuTakeover.Package)??throw new IOException("请先安装 UU 远程");StartActivity(intent);}));
        body.AddView(Label("软件更新",22,true),Spacing());body.AddView(Label("当前版本："+runtime.Version,14));
        updateState=Label("尚未检查更新",14);body.AddView(updateState);
        check=Action("检查更新",async()=>{try{await runtime.Updates.Check(force:true);}catch(Exception){runtime.SetError("暂时无法检查更新");}Update();});body.AddView(check);
        download=Action("下载新版",RequestUpdate);body.AddView(download);
        body.AddView(Action("查看日志",ShowLogs),Spacing());
        body.AddView(Action("开源许可",ShowLicenses));
        _=runtime.Updates.Check();Update();
    }
    LinearLayout.LayoutParams Spacing()=>new(-1,-2){TopMargin=Dp(18),BottomMargin=Dp(10)};
    TextView Label(string text,int size,bool strong=false)
    {var view=new TextView(this){Text=text,TextSize=size};view.SetTextColor(Color.Rgb(30,41,59));if(strong)view.SetTypeface(null,TypefaceStyle.Bold);view.SetPadding(0,Dp(3),0,Dp(3));return view;}
    Button Action(string title,Action action,bool primary=false)
    {var button=new Button(this){Text=title};button.Click+=(_,_)=>{try{action();}catch(Exception ex){runtime.SetError(ex is FormatException or NotSupportedException?ex.Message:"操作未完成，请稍后重试");Update();}};if(primary){var background=new GradientDrawable();background.SetColor(Color.Rgb(15,118,110));background.SetCornerRadius(Dp(8));button.Background=background;button.SetTextColor(Color.White);}return button;}
    void ShowLogs(){using var dialog=new AlertDialog.Builder(this);dialog.SetTitle("ConWU 日志");dialog.SetMessage(string.Join("\n",runtime.Logs));dialog.SetPositiveButton("关闭",(_,_)=>{});dialog.Show();}
    void ShowLicenses(){var text=new System.Text.StringBuilder();foreach(string file in new[]{"ConWU-MIT.txt","BouncyCastle-LICENSE.txt","dotnet-LICENSE.txt","dotnet-THIRD-PARTY-NOTICES.txt"}){using var reader=new StreamReader(Assets!.Open("licenses/"+file));text.AppendLine(file).AppendLine(reader.ReadToEnd()).AppendLine();}using var dialog=new AlertDialog.Builder(this);dialog.SetTitle("开源许可");dialog.SetMessage(text.ToString());dialog.SetPositiveButton("关闭",(_,_)=>{});dialog.Show();}
    void RequestUpdate()
    {
        if(runtime.LocalUpdates.Status.CanInstall){
            if(OperatingSystem.IsAndroidVersionAtLeast(26)&&!PackageManager!.CanRequestPackageInstalls()){
                StartActivity(new Intent(global::Android.Provider.Settings.ActionManageUnknownAppSources,global::Android.Net.Uri.Parse("package:"+PackageName)));return;
            }
            using var dialog=new AlertDialog.Builder(this);dialog.SetTitle("安装 ConWU 更新？");dialog.SetMessage("APK 已完整下载并核对签名。系统会再要求确认安装；安装期间 VPN 暂时中断，完成后恢复已启用的网络。原配置和身份会保留。");dialog.SetNegativeButton("取消",(_,_)=>{});
            dialog.SetPositiveButton("确认更新",async(_,_)=>{try{await runtime.LocalUpdates.Install();}catch(Exception ex){runtime.SetError(ex is IOException?ex.Message:"系统安装暂未开始，请重试");}Update();});dialog.Show();
        }else StartForegroundService(new Intent(this,typeof(AndroidUpdateService)));
    }
    void Leave(string id,string name){using var dialog=new AlertDialog.Builder(this);dialog.SetTitle("退出 "+name+"？");dialog.SetMessage("移除此手机保存的网络和凭据。主机端授权不会因此自动撤销。");dialog.SetNegativeButton("取消",(_,_)=>{});dialog.SetPositiveButton("退出",(_,_)=>Start("leave","",id));dialog.Show();}
    void Request(string action,string input="",string network="")
    {
        if(!runtime.Ready)throw new IOException(runtime.Error);
        if(action=="join"){var parsed=CompactDirectCode.Import(input);MobileEnrollment.RequireProtocol(parsed.Mode);}
        pendingAction=action;pendingCode=input;pendingNetwork=network;
        var permission=VpnService.Prepare(this);
        if(permission!=null)StartActivityForResult(permission,1145);else{Start(action,input,network);pendingAction="";}
    }
    void Start(string action,string input,string network)
    {
        var intent=new Intent(this,typeof(ConwuVpnService));intent.SetAction(action);intent.PutExtra("code",input);intent.PutExtra("network",network);StartForegroundService(intent);
    }
    protected override void OnActivityResult(int requestCode,Result result,Intent? data)
    {base.OnActivityResult(requestCode,result,data);if(requestCode!=1145)return;if(result==Result.Ok&&pendingAction.Length>0)Start(pendingAction,pendingCode,pendingNetwork);else runtime.SetError("未获得 VPN 授权，现有网络凭据保持不变");pendingAction=pendingCode=pendingNetwork="";Update();}
    protected override void OnSaveInstanceState(Bundle state)
    {state.PutString("code",code.Text);state.PutString("pending-action",pendingAction);state.PutString("pending-code",pendingCode);state.PutString("pending-network",pendingNetwork);base.OnSaveInstanceState(state);}
    protected override void OnResume(){base.OnResume();visible=true;if(pulse!=null)handler.RemoveCallbacks(pulse);Pulse();}
    protected override void OnPause(){visible=false;if(pulse!=null)handler.RemoveCallbacks(pulse);base.OnPause();}
    protected override void OnDestroy(){destroyed=true;visible=false;if(pulse!=null){handler.RemoveCallbacks(pulse);pulse.Dispose();pulse=null;}handler.Dispose();base.OnDestroy();}
    void Pulse(){if(!visible||destroyed)return;Update();if(pulse!=null)handler.PostDelayed(pulse,1500);}
    static void Text(TextView target,string value){if(target.Text!=value)target.Text=value;}
    void Update()
    {
        if(code==null||destroyed)return;
        Text(error,runtime.Error);join.Enabled=runtime.Ready&&!runtime.PairingActive;cancel.Visibility=runtime.PairingActive?ViewStates.Visible:ViewStates.Gone;
        var progress=runtime.Pairing;Text(pairing,!runtime.Initialization.IsCompleted?"正在读取本机网络凭据…":progress.State+(progress.Verification.Length>0?"\n双方校验码："+progress.Verification:""));
        if(!autoConnectAttempted&&runtime.Ready){
            autoConnectAttempted=true;
            if(runtime.Networks.Any(n=>n.Enabled)&&runtime.ConnectionsTask==null&&VpnService.Prepare(this)==null&&runtime.TryAutoConnect()){
                try{Start("connect-saved","","");}catch(Exception){runtime.AutoConnectFinished();runtime.SetError("系统暂未允许恢复 VPN，请点击网络的连接按钮重试");}
            }
        }
        var networks=runtime.Networks;empty.Visibility=networks.Length==0?ViewStates.Visible:ViewStates.Gone;
        string signature=string.Join('|',networks.Select(n=>n.Id+":"+n.Name+":"+n.Enabled));
        if(signature!=networkSignature){
            networkSignature=signature;rows.Clear();networkList.RemoveAllViews();
            foreach(var network in networks){
                string id=network.Id;networkList.AddView(Label(network.Name,18,true),Spacing());var info=Label("",14);networkList.AddView(info);
                var bar=new LinearLayout(this){Orientation=Orientation.Horizontal};
                var connect=Action("连接",()=>{var latest=runtime.Networks.Single(n=>n.Id==id);var connected=runtime.Connections.GetValueOrDefault(id)?.Connected==true;if(latest.Enabled&&connected)Start("disconnect","",id);else Request("connect",network:id);});
                var leave=Action("退出网络",()=>Leave(id,network.Name));
                bar.AddView(connect,new LinearLayout.LayoutParams(0,Dp(48),1));bar.AddView(leave,new LinearLayout.LayoutParams(0,Dp(48),1));networkList.AddView(bar);rows[id]=(info,connect);
            }
        }
        foreach(var network in networks)if(rows.TryGetValue(network.Id,out var views)){
            var status=runtime.Connections.GetValueOrDefault(network.Id);bool connected=network.Enabled&&status?.Connected==true;
            Text(views.Info,"本机虚拟 IP："+network.Mesh.LocalIp+"\n主机虚拟 IP："+network.HostIp+"\n"+(network.Mesh.Pair.Mode=="https"?"HTTPS":"纯 TCP")+" · "+(network.Enabled?status?.Detail??"等待连接":"已停止")+
                (connected?"\n延迟："+(status!.RttMs?.ToString("F0")??"—")+" ms · 上传 "+Bytes(status.SentBytes)+" · 下载 "+Bytes(status.ReceivedBytes):""));
            Text(views.Connect,connected?"断开":network.Enabled?"重试":"连接");
        }
        uuEnabled.Enabled=runtime.Ready;uuEnabled.Checked=runtime.Ready&&runtime.State.UuTakeoverEnabled;
        var uu=runtime.Ready?runtime.Uu.Snapshot(runtime):[];bool observed=uu.Any(n=>n.TrafficObserved);
        Text(uuState,!uuEnabled.Checked?"未开启":!runtime.Uu.Installed?"等待安装 UU 远程":!runtime.Connections.Values.Any(s=>s.Connected)?"等待 ConWU 直连":observed?"已检测到 UU 经由 ConWU 传输":!OperatingSystem.IsAndroidVersionAtLeast(29)?"VPN 已就绪；当前 Android 版本不支持按应用核对流量":"VPN 已就绪，尚未确认 UU 串流经过 ConWU");
        Text(uuNetworks,uuEnabled.Checked?string.Join("\n",uu.Select(n=>n.Name+" · 接收 "+Bytes(n.ReceivedBytes)+" · 发送 "+Bytes(n.SentBytes))):"");
        var update=runtime.Updates.Status;var local=runtime.LocalUpdates.Status;
        Text(updateState,update.Message+(local.State!="Idle"?"\n"+local.Message+(local.State=="Downloading"?" "+(local.DownloadedBytes*100/Math.Max(1,local.TotalBytes))+"%":""):""));check.Enabled=update.State!="Checking";
        Text(download,local.CanInstall?"安装已下载的更新":"下载新版");download.Enabled=!local.Busy&&local.State!="AwaitingSystemConfirmation";download.Visibility=local.CanInstall||update.UpdateAvailable&&update.Package!=null?ViewStates.Visible:ViewStates.Gone;
    }
    static string Bytes(long bytes)=>bytes>=1048576?(bytes/1048576d).ToString("F1")+" MiB":(bytes/1024d).ToString("F0")+" KiB";
    sealed class CodeWatcher(EditText input):Java.Lang.Object,ITextWatcher
    {
        bool changing;string before="";int priorCaret,start,removed,added;
        public void BeforeTextChanged(Java.Lang.ICharSequence? value,int begin,int count,int after){if(changing)return;before=value?.ToString()??"";priorCaret=input.SelectionStart;start=begin;removed=count;added=after;}
        public void OnTextChanged(Java.Lang.ICharSequence? value,int begin,int oldCount,int count){}
        public void AfterTextChanged(IEditable? value){if(changing)return;var next=CompactCodeInput.Edit(before,value?.ToString()??"",input.SelectionStart,priorCaret,start,removed,added);if(next.Text==value?.ToString())return;changing=true;try{input.Text=next.Text;input.SetSelection(next.Caret);}finally{changing=false;}}
    }
}
