namespace StreamLink;

static class Program
{
    static StreamLink.Core.UiControlReply Ui(StreamLink.Core.UiControlRequest request)
    {
        var reply=StreamLink.Core.UiControlProtocol.Call(request).GetAwaiter().GetResult();
        if(!reply.Ok)throw new IOException(reply.Error);return reply;
    }
    static StreamLink.Core.UiControlReply UiMutation(StreamLink.Core.UiControlRequest request)
    {
        var id=Guid.NewGuid();request=request with{OperationId=id};var reply=Ui(request);
        var deadline=DateTime.UtcNow.AddSeconds(90);
        while(reply.Operation is not {Completed:true}){
            if(DateTime.UtcNow>=deadline)throw new TimeoutException("验收操作未及时完成");
            Thread.Sleep(200);reply=Ui(new StreamLink.Core.UiControlRequest("status",OperationId:id){NetworkId=request.NetworkId});
        }
        if(reply.Operation.Error.Length>0)throw new IOException(reply.Operation.Error);return reply;
    }
    /// <summary>
    ///  The main entry point for the application.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        // To customize application configuration such as set high DPI settings or default font,
        // see https://aka.ms/applicationconfiguration.
        ApplicationConfiguration.Initialize();
        if(args.Length>=2&&args[0]=="--validation-instance") { StreamLink.Core.WindowsInstance.ConfigureValidation(args[1]);args=args[2..]; }
        if(args is ["--driver-guard","hold",var guardScope,var guardReport,var guardStop]){
            try{DriverGuard.Hold(guardScope,guardReport,guardStop);}
            catch(Exception){Environment.ExitCode=1;}
            return;
        }
        if(args is ["--adapter-maintenance",var maintenanceAction,var maintenanceOutput]){
            try{if(!Path.IsPathFullyQualified(maintenanceOutput))throw new ArgumentException("维护输出需要绝对路径");File.WriteAllText(maintenanceOutput,System.Text.Json.JsonSerializer.Serialize(ServiceInstaller.AdapterMaintenance(maintenanceAction)));}
            catch(Exception ex){Environment.ExitCode=1;if(Path.IsPathFullyQualified(maintenanceOutput))File.WriteAllText(maintenanceOutput,System.Text.Json.JsonSerializer.Serialize(new{Schema=1,Instance=StreamLink.Core.WindowsInstance.Name,DataRoot=StreamLink.Service.ProfileStore.Root,Released=false,Error=ex.Message}));}
            return;
        }
        if(StreamLink.Core.WindowsInstance.IsValidation&&args is ["--validation-tray"]){
            if(StreamLink.Core.WindowsHost.IsAdmin)throw new UnauthorizedAccessException("Tray validation requires an ordinary user");
            Application.Run(new WebTrayContext(openBrowser:false));return;
        }
        if(args is ["--msi-configure",_,_] or ["--msi-rollback",_] or ["--msi-commit",_] or ["--msi-ready"] or ["--start-service"]){
            try {
                switch(args[0]){
                    case "--msi-configure":ServiceInstaller.ConfigureMsi(args[1],args[2]).GetAwaiter().GetResult();break;
                    case "--msi-rollback":ServiceInstaller.RollbackMsiAuthorization(args[1]);break;
                    case "--msi-commit":ServiceInstaller.CommitMsiAuthorization(args[1]);break;
                    case "--msi-ready":ServiceInstaller.VerifyMsiReady().GetAwaiter().GetResult();break;
                    case "--start-service":if(!StreamLink.Core.WindowsHost.IsAdmin)throw new UnauthorizedAccessException("启动服务需要管理员权限");ServiceInstaller.StartIfNeeded().GetAwaiter().GetResult();break;
                }
            }catch(Exception ex){Environment.ExitCode=1;try{File.AppendAllText(Path.Combine(StreamLink.Service.ProfileStore.Root,"installer-error.log"),DateTimeOffset.UtcNow+" "+args[0]+" "+ex+Environment.NewLine);}catch{}}
            return;
        }
        if(StreamLink.Core.WindowsInstance.IsValidation&&args is ["--acceptance-status",var output]) {
            try {
                var old=StreamLink.Core.ServiceProtocol.Call(new("status")).GetAwaiter().GetResult();
                var status=Ui(new("status")).Status??throw new IOException("工作区状态不可用");
                var networkRow=status.Networks.FirstOrDefault();var network=networkRow?.Status;
                var root=StreamLink.Service.ProfileStore.Root;var file=Path.Combine(root,"profile.dpapi");
                var profiles=new StreamLink.Service.ProfileStore();var revision=profiles.NetworksForMaintenance().FirstOrDefault(n=>n.ConfigurationId==networkRow?.Id).Profile?.Mesh?.Directory?.Revision;
                File.WriteAllText(Path.GetFullPath(output),System.Text.Json.JsonSerializer.Serialize(new{Ok=old.Ok,status.ServiceReady,status.Version,old.ControlOperationsVersion,NetworkEnabled=network?.NetworkEnabled??false,Network=network?.NetworkId,DirectoryRevision=revision,ProfileSha256=File.Exists(file)?Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))):"",UiSid=profiles.UiUserSnapshot(),instance=StreamLink.Core.WindowsInstance.Name,Networks=status.Networks.Select(n=>new{n.Id,n.Name,n.Status.NetworkId}).ToArray()}));
            }catch(Exception ex){Environment.ExitCode=1;File.WriteAllText(Path.GetFullPath(output),System.Text.Json.JsonSerializer.Serialize(new{Ok=false,error=ex.Message}));}return;
        }
        if(StreamLink.Core.WindowsInstance.IsValidation&&args is ["--acceptance-create-network"]) {
            try {
                var status=Ui(new("status")).Status??throw new IOException("工作区状态不可用");
                var settings=status.DeviceSettings??status.Settings??throw new IOException("设备默认设置不可用");
                if(settings.ConnectionSource!="existing"||!settings.DirectMode){
                    var action=new StreamLink.Core.UiNetworkAction("settings",Settings:settings with{ConnectionSource="existing",DirectMode=true},ExpectedRevision:status.DeviceSettingsRevision,ConfirmReplace:true);
                    UiMutation(new StreamLink.Core.UiControlRequest("save-settings"){SettingsBatch=new(action,[])});
                }
                var created=UiMutation(new StreamLink.Core.UiControlRequest("network",Network:new("create-direct",Mode:settings.PathSelection=="udp-only"?"udp":"faketcp")));
                string id=created.Status?.SelectedNetworkId??throw new IOException("创建后未返回网络配置 ID");
                UiMutation(new StreamLink.Core.UiControlRequest("stop"){NetworkId=id});
            }catch(Exception ex){Environment.ExitCode=1;File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"acceptance-error.log"),ex.ToString());}return;
        }
        if(StreamLink.Core.WindowsInstance.IsValidation&&args is ["--acceptance-disable-startup"]) {
            try {
                var status=Ui(new("status")).Status??throw new IOException("工作区状态不可用");
                var action=new StreamLink.Core.UiNetworkAction("settings",Settings:status.DeviceSettings??status.Settings,ExpectedRevision:status.DeviceSettingsRevision,ConfirmReplace:true){AutoStart=false,ExpectedAutoStart=status.Desktop?.AutoStart};
                UiMutation(new StreamLink.Core.UiControlRequest("save-settings"){SettingsBatch=new(action,[])});
            }catch(Exception ex){Environment.ExitCode=1;File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"acceptance-error.log"),ex.ToString());}return;
        }
        if (args.Length == 2 && args[0] == "--verify-bundle") {
            try { int files = ServiceInstaller.VerifyBundle(AppContext.BaseDirectory); File.WriteAllText(Path.GetFullPath(args[1]), System.Text.Json.JsonSerializer.Serialize(new { status = "Pass", files, version = ApplicationVersion.Release })); }
            catch (Exception ex) { Environment.ExitCode = 1; File.WriteAllText(Path.GetFullPath(args[1]), System.Text.Json.JsonSerializer.Serialize(new { status = "Fail", error = ex.Message })); }
            return;
        }
        if(args is ["--install"] or ["--uninstall"] || args is ["--install","--ui-user-account",_]) {
            try {
                if(args[0]=="--uninstall"){
                    if(MsiInstallation.ProductCode!=null)MsiInstallation.Maintain(true).GetAwaiter().GetResult();
                    else ServiceInstaller.Uninstall().GetAwaiter().GetResult();
                }
                else {
                    string? account=args.Length==3?args[2]:null;
                    ServiceInstaller.Install(account).GetAwaiter().GetResult();
                }
            }catch(Exception ex){File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"install-error.log"),ex.ToString());Environment.ExitCode=1;}
            return;
        }
        if(args is ["--tray-preview",var previewPath]) {
            using var menu=new TrayMenu(()=>{},()=>{});
            menu.Show(new Point(-20000,-20000));Application.DoEvents();
            using var bitmap=new Bitmap(menu.Width,menu.Height);menu.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));
            bitmap.Save(Path.GetFullPath(previewPath),System.Drawing.Imaging.ImageFormat.Png);menu.Close();return;
        }
        // Preserve old shortcuts as aliases, with WebUI as the only business UI.
        bool startup=args is ["--startup"];
        if(startup&&!StreamLink.Core.StartupSettings.Read().AutoStart)return;
        if(args.Length!=0 && args is not ["--desktop"] && !startup) {
            Environment.ExitCode=2;MessageBox.Show("无法识别启动参数。请从桌面快捷方式或 ConWU.exe 打开 WebUI。","ConWU");return;
        }
        if(StreamLink.Core.WindowsHost.IsAdmin){if(!startup)MessageBox.Show("请使用日常账号、普通权限打开 ConWU。安装与修复请运行 MSI 安装包。","ConWU");return;}
        using var panelSingle=new Mutex(true,"Local\\"+StreamLink.Core.WindowsInstance.Name+"-WebTray",out bool panelFirst);
        if(!panelFirst){if(!startup)AppExitWindow.OpenExisting();return;}
        Application.Run(new WebTrayContext(openBrowser:!startup));
    }
}
