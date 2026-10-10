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
        if(args.Length == 1 && (args[0] == "--install" || args[0] == "--uninstall")) { try { (args[0] == "--install" ? ServiceInstaller.Install() : ServiceInstaller.Uninstall()).GetAwaiter().GetResult(); } catch(Exception ex) { File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"install-error.log"),ex.ToString()); Environment.ExitCode=1; } return; }
        if(args.Length>=2 && args[0]=="--preview") {
            using var preview=new MainWindow(true); preview.StartPosition=FormStartPosition.Manual; preview.Location=new Point(-30000,-30000); preview.ShowInTaskbar=false; preview.Show(); Application.DoEvents(); preview.PerformLayout();
            if(args.Length>2) { preview.PreviewPage(args[2]); Application.DoEvents(); preview.PerformLayout(); }
            using var bitmap=new Bitmap(preview.Width,preview.Height);
            preview.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
            bitmap.Save(Path.GetFullPath(args[1]),System.Drawing.Imaging.ImageFormat.Png);
            IEnumerable<object> Layout(Control c) { yield return new {Type=c.GetType().Name,Text=c.Text,Width=c.Width,Height=c.Height,X=c.Left,Y=c.Top,Dpi=c.DeviceDpi,Font=c.Font.Size,Auto=c.AutoSize}; foreach(Control child in c.Controls) foreach(var item in Layout(child)) yield return item; }
            File.WriteAllText(Path.GetFullPath(args[1])+".json",System.Text.Json.JsonSerializer.Serialize(new {preview.Width,preview.Height,preview.DeviceDpi,Layout=Layout(preview).ToArray()})); return;
        }
        using var single = new Mutex(true, "Local\\StreamLink-Desktop", out bool first);
        if(!first) { MessageBox.Show("StreamLink 已在运行。"); return; }
        Application.Run(new MainWindow());
    }    
}

