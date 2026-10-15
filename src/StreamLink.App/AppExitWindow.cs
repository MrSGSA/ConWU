using System.Runtime.InteropServices;

namespace StreamLink;
// Upgrade requests close only the user interface. The service owns networking.
sealed class AppExitWindow:NativeWindow,IDisposable
{
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern uint RegisterWindowMessage(string name);
    static readonly uint ExitMessage=RegisterWindowMessage("StreamLink.ExitUi.AQ1.v1");
    static readonly uint OpenMessage=RegisterWindowMessage("StreamLink.OpenWeb."+StreamLink.Core.WindowsInstance.Name);
    [DllImport("user32.dll")]static extern bool PostMessage(nint window,uint message,nint wParam,nint lParam);
    readonly Action close;
    readonly Action open;
    public AppExitWindow(Action close,Action open){this.close=close;this.open=open;CreateHandle(new CreateParams{Caption="StreamLink UI lifecycle",Style=unchecked((int)0x80000000)});}
    public static void OpenExisting()=>PostMessage(new nint(0xffff),OpenMessage,0,0);
    protected override void WndProc(ref Message message){if(message.Msg==ExitMessage){close();message.Result=IntPtr.Zero;return;}if(message.Msg==OpenMessage){open();message.Result=IntPtr.Zero;return;}base.WndProc(ref message);}
    public void Dispose(){if(Handle!=IntPtr.Zero)DestroyHandle();}
}
