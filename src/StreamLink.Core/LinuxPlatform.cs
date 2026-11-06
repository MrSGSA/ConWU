using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StreamLink.Core;

public static class LinuxPlatform
{
    [DllImport("libc")] public static extern uint geteuid();
    public static string UserIdentity=>"uid:"+geteuid();
    public static void PrivateDirectory(string path) {
        string full=Path.GetFullPath(path);
        if(full=="/")throw new IOException("不能将系统根目录用作 StreamLink 数据目录");
        for(var current=new DirectoryInfo(full);current!=null;current=current.Parent)
            if(current.Exists&&(current.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("数据目录不能经过符号链接");
        Directory.CreateDirectory(full,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        File.SetUnixFileMode(full,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
    }
    public static void PrivateWrite(string file,ReadOnlySpan<byte> bytes) {
        if(File.Exists(file)&&(File.GetAttributes(file)&FileAttributes.ReparsePoint)!=0)throw new IOException("配置文件不能是符号链接");
        string temporary=file+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var stream=new FileStream(temporary,new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,Options=FileOptions.WriteThrough,UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite})) {
                stream.Write(bytes);stream.Flush(true);
            }
            File.Move(temporary,file,true);
        }finally {if(File.Exists(temporary))File.Delete(temporary);}
    }
    public static string Run(string executable,params string[] arguments) {
        var info=new ProcessStartInfo(executable){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(var arg in arguments)info.ArgumentList.Add(arg);
        using var process=Process.Start(info)??throw new IOException("无法运行系统网络工具");
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        if(!process.WaitForExit(10000)){process.Kill(true);process.WaitForExit();throw new IOException(Path.GetFileName(executable)+" 执行超时");}
        string result=output.GetAwaiter().GetResult(),detail=error.GetAwaiter().GetResult();
        if(process.ExitCode!=0)throw new IOException(Path.GetFileName(executable)+" 执行失败："+detail.Trim());
        return result;
    }
}
