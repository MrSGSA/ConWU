using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using StreamLink.Core;

namespace StreamLink;
static class MsiInstallation
{
    const string UpgradeCode="{AD076018-A9B8-47F5-B098-97479A363416}";
    [DllImport("msi.dll",CharSet=CharSet.Unicode)]static extern uint MsiEnumRelatedProducts(string upgrade,uint reserved,uint index,StringBuilder product);
    [DllImport("msi.dll",CharSet=CharSet.Unicode)]static extern int MsiQueryProductState(string product);
    [DllImport("msi.dll",CharSet=CharSet.Unicode)]static extern uint MsiGetProductInfo(string product,string property,StringBuilder value,ref uint length);
    static string Info(string product,string property){var text=new StringBuilder(128);uint length=128;return MsiGetProductInfo(product,property,text,ref length)==0?text.ToString():"";}
    public static string? ProductCode {
        get {
            // Query Windows Installer's public product registration. Private
            // recovery keys are intentionally unreadable to ordinary users.
            string upgrade=WindowsInstance.IsValidation?Guid.Parse(WindowsInstance.ValidationId!).ToString("B"):UpgradeCode;
            string? selected=null;Version highest=new(0,0);
            for(uint index=0;index<1024;index++){
                var product=new StringBuilder(39);uint result=MsiEnumRelatedProducts(upgrade,0,index,product);
                if(result!=0)break;
                string code=product.ToString();
                if(MsiQueryProductState(code)!=5||Info(code,"AssignmentType")!="1"||!Guid.TryParse(code,out _))continue;
                if(Version.TryParse(Info(code,"VersionString"),out var version)&&version>highest){selected=code;highest=version;}
            }
            return selected;
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
