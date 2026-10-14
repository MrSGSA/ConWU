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
            try { int files = ServiceInstaller.VerifyBundle(AppContext.BaseDirectory); File.WriteAllText(Path.GetFullPath(args[1]), System.Text.Json.JsonSerializer.Serialize(new { status = "Pass", files, version = DesktopVersion.Release })); }
            catch (Exception ex) { Environment.ExitCode = 1; File.WriteAllText(Path.GetFullPath(args[1]), System.Text.Json.JsonSerializer.Serialize(new { status = "Fail", error = ex.Message })); }
            return;
        }
        if(args is ["--install"] or ["--install-ui"] or ["--uninstall"] || args is ["--install","--ui-user-account",_]) {
            try {
                if(args[0]=="--uninstall")ServiceInstaller.Uninstall().GetAwaiter().GetResult();
                else {
                    string? account=args[0]=="--install-ui"?UiUserSelection.ConfirmForInstall(null):args.Length==3?args[2]:null;
                    ServiceInstaller.Install(account).GetAwaiter().GetResult();
                }
            }catch(Exception ex){File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"install-error.log"),ex.ToString());Environment.ExitCode=1;}
            return;
        }
        if(args.Length>=2 && args[0]=="--preview") {
            using Form preview=args.Length>2 && args[2]=="connection" ? new SettingsWindow(new()) : new MainWindow(true); preview.StartPosition=FormStartPosition.Manual; preview.Location=new Point(-30000,-30000); preview.ShowInTaskbar=false; preview.Show(); Application.DoEvents(); preview.PerformLayout();
            if(args.Length>2 && preview is MainWindow mainPreview) { mainPreview.PreviewPage(args[2]); Application.DoEvents(); preview.PerformLayout(); }
            using var bitmap=new Bitmap(preview.Width,preview.Height);
            preview.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
            bitmap.Save(Path.GetFullPath(args[1]),System.Drawing.Imaging.ImageFormat.Png);
            IEnumerable<object> Layout(Control c) { yield return new {Type=c.GetType().Name,Text=c.Text,Width=c.Width,Height=c.Height,X=c.Left,Y=c.Top,Dpi=c.DeviceDpi,Font=c.Font.Size,Auto=c.AutoSize}; foreach(Control child in c.Controls) foreach(var item in Layout(child)) yield return item; }
            File.WriteAllText(Path.GetFullPath(args[1])+".json",System.Text.Json.JsonSerializer.Serialize(new {preview.Width,preview.Height,preview.DeviceDpi,Layout=Layout(preview).ToArray()})); return;
        }
        using var single = new Mutex(true, "Local\\"+StreamLink.Core.WindowsInstance.Name+(StreamLink.Core.WindowsHost.IsAdmin?"-Desktop":"-UserDesktop"), out bool first);
        if(!first) { MessageBox.Show("StreamLink 已在运行。"); return; }
        Application.Run(StreamLink.Core.WindowsHost.IsAdmin?new MainWindow():new UserWindow());
    }    
}

