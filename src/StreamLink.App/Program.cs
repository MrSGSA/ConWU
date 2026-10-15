namespace StreamLink;

static class Program
{
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
                var status=StreamLink.Core.ServiceProtocol.Call(new("status")).GetAwaiter().GetResult();
                var root=StreamLink.Service.ProfileStore.Root;var file=Path.Combine(root,"profile.dpapi");
                File.WriteAllText(Path.GetFullPath(output),System.Text.Json.JsonSerializer.Serialize(new{status.Ok,status.ServiceReady,status.Version,status.ControlOperationsVersion,NetworkEnabled=status.Profile?.Enabled??false,Network=status.Profile?.Mesh?.Pair.Network,DirectoryRevision=status.Profile?.Mesh?.Directory?.Revision,ProfileSha256=File.Exists(file)?Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))):"",UiSid=new StreamLink.Service.ProfileStore().UiUserSnapshot(),instance=StreamLink.Core.WindowsInstance.Name}));
            }catch(Exception ex){Environment.ExitCode=1;File.WriteAllText(Path.GetFullPath(output),System.Text.Json.JsonSerializer.Serialize(new{Ok=false,error=ex.Message}));}return;
        }
        if(StreamLink.Core.WindowsInstance.IsValidation&&args is ["--acceptance-create-network"]) {
            try {var created=StreamLink.Core.ServiceProtocol.Call(new("mesh-create",Service:"https://example.com/")).GetAwaiter().GetResult();if(!created.Ok)throw new IOException(created.Error);}
            catch(Exception ex){Environment.ExitCode=1;File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"acceptance-error.log"),ex.ToString());}return;
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
        if(args.Length!=0 && args is not ["--desktop"]) {
            Environment.ExitCode=2;MessageBox.Show("无法识别启动参数。请从桌面快捷方式或 StreamLink.exe 打开 WebUI。","StreamLink");return;
        }
        if(StreamLink.Core.WindowsHost.IsAdmin){MessageBox.Show("请使用日常账号、普通权限打开 StreamLink。安装与修复请运行 MSI 安装包。","StreamLink");return;}
        using var panelSingle=new Mutex(true,"Local\\"+StreamLink.Core.WindowsInstance.Name+"-WebTray",out bool panelFirst);
        if(!panelFirst){AppExitWindow.OpenExisting();return;}
        Application.Run(new WebTrayContext());
    }
}
