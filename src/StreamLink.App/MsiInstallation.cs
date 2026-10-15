using System.Diagnostics;
using Microsoft.Win32;
using StreamLink.Core;

namespace StreamLink;
static class MsiInstallation
{
    public static string? ProductCode {
        get {
            if(WindowsInstance.IsValidation)return null;
            using var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\StreamLink\Installation");
            return Guid.TryParse(key?.GetValue("ProductCode") as string,out var id)?id.ToString("B"):null;
        }
    }
    public static async Task Maintain(bool uninstall=false)
    {
        string product=ProductCode??throw new IOException("尚未登记 MSI 安装，请运行新的安装包。");
        using var process=Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"msiexec.exe")){UseShellExecute=true,Arguments=(uninstall?"/x ":"/i ")+product})!;
        await process.WaitForExitAsync();
        if(process.ExitCode is not(0 or 3010 or 1602))throw new IOException("Windows 安装程序未完成，错误码 "+process.ExitCode);
    }
}
