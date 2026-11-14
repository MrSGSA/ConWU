using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using StreamLink.Core;
using System.Security.Cryptography;
using System.Text.Json;
using File=System.IO.File;

namespace ConWU.Android;

sealed class AndroidLocalUpdates(Context context)
{
    readonly object gate=new();
    readonly string folder=Path.Combine(context.NoBackupFilesDir!.AbsolutePath,"updates");
    LocalUpdateStatus status=new(true);
    Task? pending;
    public LocalUpdateStatus Status=>Volatile.Read(ref status);
    string Apk=>Path.Combine(folder,"package.apk");
    string ReadyFile=>Path.Combine(folder,"prepared.json");
    public void Restore()
    {
        lock(gate){try{if(File.Exists(ReadyFile)&&new FileInfo(ReadyFile).Length<16384){
            var ready=JsonSerializer.Deserialize<LocalUpdateStatus>(File.ReadAllText(ReadyFile));
            if(ready is {CanInstall:true}&&File.Exists(Apk)&&ready.Version!=context.PackageManager!.GetPackageInfo(context.PackageName!,0)!.VersionName)Volatile.Write(ref status,ready);
        }}catch(IOException){}catch(JsonException){} }
    }
    public Task Download(ReleaseUpdateStatus release)
    {
        lock(gate){if(pending is {IsCompleted:false})return pending;
            var package=OfficialUpdatePackage.Validate(release,".apk");
            if(!package.Name.Contains("-android-",StringComparison.Ordinal))throw new IOException("不是 Android 安装包");
            Volatile.Write(ref status,new(true,"Downloading","正在下载完整 APK，当前连接保持运行"){Version=release.LatestVersion,TotalBytes=package.Bytes});
            return pending=Task.Run(async()=>{
                try{
                    Directory.CreateDirectory(folder);if(File.Exists(Apk))File.Delete(Apk);if(File.Exists(Apk+".partial"))File.Delete(Apk+".partial");
                    await OfficialUpdatePackage.Download(package,Apk,(done,total)=>Volatile.Write(ref status,Status with{DownloadedBytes=done,TotalBytes=total}),CancellationToken.None);
                    VerifyArchive(Apk,release.LatestVersion);
                    File.WriteAllText(Path.Combine(folder,"sha256"),package.Sha256);
                    var ready=new LocalUpdateStatus(true,"Ready","APK 已下载并核对版本、签名，等待确认安装"){Version=release.LatestVersion,CanInstall=true,TotalBytes=package.Bytes,DownloadedBytes=package.Bytes};
                    File.WriteAllText(ReadyFile,JsonSerializer.Serialize(ready));Volatile.Write(ref status,ready);
                }catch(Exception ex){Volatile.Write(ref status,Status with{State="Error",CanInstall=false,Message="更新准备未完成："+(ex is IOException?ex.Message:ex.GetType().Name)});}
            });
        }
    }
    static byte[][] Signers(PackageInfo package)=>OperatingSystem.IsAndroidVersionAtLeast(28)?
        package.SigningInfo?.GetApkContentsSigners()?.Select(s=>s.ToByteArray()!).ToArray()??[]:
        package.Signatures?.Select(s=>s.ToByteArray()!).ToArray()??[];
    void VerifyArchive(string path,string version)
    {
        var flags=OperatingSystem.IsAndroidVersionAtLeast(28)?PackageInfoFlags.SigningCertificates:PackageInfoFlags.Signatures;
        var manager=context.PackageManager!;var archive=manager.GetPackageArchiveInfo(path,flags)??throw new IOException("APK 格式无效");
        var installed=manager.GetPackageInfo(context.PackageName!,flags)!;
        long next=OperatingSystem.IsAndroidVersionAtLeast(28)?archive.LongVersionCode:archive.VersionCode;
        long current=OperatingSystem.IsAndroidVersionAtLeast(28)?installed.LongVersionCode:installed.VersionCode;
        var actual=Signers(archive).Select(s=>Convert.ToHexString(SHA256.HashData(s))).Order().ToArray();
        var trusted=Signers(installed).Select(s=>Convert.ToHexString(SHA256.HashData(s))).Order().ToArray();
        if(archive.PackageName!=context.PackageName||archive.VersionName!=version||next<=current||actual.Length==0||!actual.SequenceEqual(trusted))throw new IOException("APK 的应用身份、版本或签名与当前安装不一致，未开始安装");
    }
    public async Task Install()
    {
        LocalUpdateStatus before;
        lock(gate){before=Status;if(!before.CanInstall||before.Busy)throw new IOException("完整 APK 尚未就绪，或安装正在准备");Volatile.Write(ref status,before with{State="Verifying",CanInstall=false,Message="正在再次核对本地 APK"});}
        try{
        await Task.Run(async()=>{
            using(var input=File.OpenRead(Apk))if(!Convert.ToHexString(await SHA256.HashDataAsync(input)).Equals(File.ReadAllText(Path.Combine(folder,"sha256")).Trim(),StringComparison.OrdinalIgnoreCase))throw new IOException("APK 校验失败，请重新下载");
            VerifyArchive(Apk,before.Version);
        });
        using var installer=context.PackageManager!.PackageInstaller!;
        using var parameters=new PackageInstaller.SessionParams(PackageInstallMode.FullInstall);
        parameters.SetAppPackageName(context.PackageName);parameters.SetSize(new FileInfo(Apk).Length);
        if(OperatingSystem.IsAndroidVersionAtLeast(31))parameters.SetRequireUserAction((int)PackageInstallUserAction.Required);
        int id=installer.CreateSession(parameters);bool committed=false;
        try{using var session=installer.OpenSession(id)!;
            using(var output=session.OpenWrite("ConWU.apk",0,new FileInfo(Apk).Length)!){using var input=File.OpenRead(Apk);await input.CopyToAsync(output);session.Fsync(output);}
            var intent=new Intent(context,typeof(AndroidUpdateReceiver)).SetAction("io.github.mrsgsa.conwu.UPDATE_RESULT");
            var flags=PendingIntentFlags.UpdateCurrent|(OperatingSystem.IsAndroidVersionAtLeast(31)?PendingIntentFlags.Mutable:0);
            using var result=PendingIntent.GetBroadcast(context,id,intent,flags)!;
            session.Commit(result.IntentSender);committed=true;
            Volatile.Write(ref status,before with{State="AwaitingSystemConfirmation",CanInstall=false,Message="请在 Android 系统安装界面确认；安装完成后恢复已启用的网络"});
        }finally{if(!committed)installer.AbandonSession(id);}
        }catch{Volatile.Write(ref status,before);throw;}
    }
    public void InstallResult(int result)
    {
        Volatile.Write(ref status,Status with{State=result==0?"Completed":"Error",CanInstall=result!=0&&File.Exists(Apk),Message=result==0?"更新完成，正在恢复网络":"系统安装未完成，原程序和网络凭据保留，可重试"});
    }
}

[Service(Exported=false,ForegroundServiceType=ForegroundService.TypeDataSync)]
public sealed class AndroidUpdateService:Service
{
    public override global::Android.OS.IBinder? OnBind(Intent? intent)=>null;
    public override StartCommandResult OnStartCommand(Intent? intent,StartCommandFlags flags,int id)
    {
        var manager=(NotificationManager)GetSystemService(NotificationService)!;manager.CreateNotificationChannel(new("conwu-update","ConWU 更新",NotificationImportance.Low));
        var notice=new Notification.Builder(this,"conwu-update").SetContentTitle("ConWU").SetContentText("正在下载并校验更新，组网保持运行").SetSmallIcon(Resource.Drawable.conwu_status).Build();
        if(OperatingSystem.IsAndroidVersionAtLeast(34))StartForeground(1146,notice,ForegroundService.TypeDataSync);else StartForeground(1146,notice);
        var runtime=MobileRuntime.Get(this);
        _=Task.Run(async()=>{try{await runtime.LocalUpdates.Download(runtime.Updates.Status);}catch(Exception ex){runtime.SetError(ex is IOException?ex.Message:"暂时无法下载更新");}finally{StopForeground(StopForegroundFlags.Remove);StopSelf(id);}});
        return StartCommandResult.NotSticky;
    }
}

[BroadcastReceiver(Exported=false)]
[IntentFilter([Intent.ActionMyPackageReplaced])]
public sealed class AndroidUpdateReceiver:BroadcastReceiver
{
    public override void OnReceive(Context? context,Intent? intent)
    {
        if(context==null||intent==null)return;
        if(intent.Action==Intent.ActionMyPackageReplaced){
            // MyPackageReplaced is delivered by the OS only to this package.
            var runtime=MobileRuntime.Get(context);var pending=GoAsync();
            _=Task.Run(async()=>{try{await runtime.Initialization;if(runtime.Ready&&runtime.Networks.Any(n=>n.Enabled)&&global::Android.Net.VpnService.Prepare(context)==null)context.StartForegroundService(new Intent(context,typeof(ConwuVpnService)).SetAction("connect-saved"));}catch(Exception){runtime.Log("更新后请打开 ConWU 恢复 VPN");}finally{pending?.Finish();}});
            return;
        }
        int result=intent.GetIntExtra(PackageInstaller.ExtraStatus,(int)PackageInstallStatus.Failure);
        if(result==(int)PackageInstallStatus.PendingUserAction){
            var confirmation=OperatingSystem.IsAndroidVersionAtLeast(33)?intent.GetParcelableExtra(Intent.ExtraIntent,Java.Lang.Class.FromType(typeof(Intent))) as Intent:intent.GetParcelableExtra(Intent.ExtraIntent) as Intent;
            confirmation?.AddFlags(ActivityFlags.NewTask);if(confirmation!=null)context.StartActivity(confirmation);
        }else MobileRuntime.Get(context).LocalUpdates.InstallResult(result);
    }
}
