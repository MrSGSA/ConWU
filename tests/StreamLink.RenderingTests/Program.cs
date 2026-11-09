using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Text.Json;
using StreamLink;
using StreamLink.Core;

static class Program
{
    static int checks;
    // PreProcessMessage combines synthetic WM_KEYDOWN with the real desktop's
    // ModifierKeys. Exercise the actual WinForms dialog-key handler with an
    // explicit key context, without releasing or synthesizing the user's keys.
    static readonly MethodInfo dialogKey=typeof(TrayMenu).GetMethod("ProcessDialogKey",BindingFlags.Instance|BindingFlags.NonPublic,null,[typeof(Keys)],null)!;
    static void Key(TrayMenu menu,Keys key){if(dialogKey.Invoke(menu,[key]) is not true)throw new Exception("Menu did not handle explicit key: "+key);}
    static void Check(bool ok,string message){if(!ok)throw new Exception(message);checks++;}
    [STAThread]static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        string output=Path.GetFullPath(args.Length>0?args[0]:"rendering.json");Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        int opens=0,exits=0;
        using var menu=new TrayMenu(()=>opens++,()=>exits++);
        menu.Show(new Point(-20000,-20000));Application.DoEvents();
        var actions=menu.Items.OfType<ToolStripMenuItem>().ToArray();
        Check(actions.Length==2&&actions[0].AccessibleName=="打开 WebUI"&&actions[1].AccessibleName!.Contains("网络继续运行"),"Only Open WebUI and Exit are available and accessible");
        Check(menu.Items.OfType<ToolStripSeparator>().Count()==1,"Actions have a clear visual separator");
        foreach(var item in actions){
            Check(item.Bounds.Height>=40*menu.DeviceDpi/96,"DPI-scaled rows retain a usable click target");
            Check(menu.GetItemAt(item.Bounds.Left+item.Bounds.Width/2,item.Bounds.Top+item.Bounds.Height/2)==item,"Visual row matches its hit target");
        }
        void Draw(string suffix){using var bitmap=new Bitmap(menu.Width,menu.Height);menu.DrawToBitmap(bitmap,new Rectangle(Point.Empty,bitmap.Size));bitmap.Save(Path.Combine(Path.GetDirectoryName(output)!,"tray-menu"+suffix+".png"),ImageFormat.Png);}
        Draw("");actions[0].Select();Application.DoEvents();Draw("-hover");
        Key(menu,Keys.Down);Application.DoEvents();
        Check(actions[1].Selected,"Down arrow moves to Exit and skips the separator");
        Key(menu,Keys.Enter);Application.DoEvents();
        Check(exits==1&&opens==0,"Enter activates Exit only");
        menu.Show(new Point(-20000,-20000));actions[0].PerformClick();
        Check(opens==1&&exits==1,"Open invokes only the browser callback");menu.Close();
        var status=new UiStatusDto("test","Thinkbook-14-24","10.126.1.2","已连接",true,true,1,1,[],"info");
        string tip=TrayInformation.Format(status);
        Check(tip.Contains("Thinkbook-14-24")&&tip.Contains("10.126.1.2")&&tip.Contains("已连接")&&tip.Split('\n').Length==4,"Hover information includes version, live state, device and virtual IP");
        Check(!TrayInformation.Format(null,"后台已停止").Contains("10.126.1.2"),"Unavailable backend clears stale virtual IP");
        string bounded=TrayInformation.Format(status with{DeviceName=new string('测',100)+"\n伪造状态",State=new string('态',100)});
        Check(bounded.Length<=127&&bounded.Split('\n').Length==4,"Untrusted display fields cannot add tooltip lines or exceed the native shell limit");
        using(var notify=new NotifyIcon()){notify.Text=bounded;Check(notify.Text==bounded,"Actual NotifyIcon accepts the bounded multiline tooltip");}
        var types=typeof(TrayMenu).Assembly.GetTypes();
        Check(!types.Any(t=>typeof(Form).IsAssignableFrom(t)),"The product assembly contains no desktop business forms");
        File.WriteAllText(output,JsonSerializer.Serialize(new{status="Pass",checks,dpi=menu.DeviceDpi,width=menu.Width,height=menu.Height,tip,keyContext="explicit WinForms dialog keys, independent of ambient desktop modifiers",scope="Actual native menu rendering, dialog-key handler and pointer targets plus bounded shell tooltip. Does not start the service or network, or inject system input."},new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine($"PASS {checks} native tray checks");
    }
}
