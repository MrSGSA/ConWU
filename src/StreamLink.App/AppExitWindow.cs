using System.Runtime.InteropServices;

namespace StreamLink;
// Upgrade requests close only the user interface. The service owns networking.
sealed class AppExitWindow:NativeWindow,IDisposable
{
    [DllImport("user32.dll",CharSet=CharSet.Unicode)]static extern uint RegisterWindowMessage(string name);
    static readonly uint ExitMessage=RegisterWindowMessage("StreamLink.ExitUi.AQ1.v1");
    readonly Action close;
    public AppExitWindow(Action close){this.close=close;CreateHandle(new CreateParams{Caption="StreamLink UI lifecycle",Style=unchecked((int)0x80000000)});}
    protected override void WndProc(ref Message message){if(message.Msg==ExitMessage){close();message.Result=IntPtr.Zero;return;}base.WndProc(ref message);}
    public void Dispose(){if(Handle!=IntPtr.Zero)DestroyHandle();}
}
