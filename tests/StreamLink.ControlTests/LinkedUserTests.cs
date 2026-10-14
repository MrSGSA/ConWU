using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using StreamLink.Core;

static class LinkedUserTests
{
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct StartupInfo {
        public int Size; public string? Reserved,Desktop,Title; public uint X,Y,Width,Height,XChars,YChars,Fill,Flags;
        public ushort Show,ReservedLength; public IntPtr Reserved2,In,Out,Error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process,Thread;public uint Pid,Tid; }
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int type,out IntPtr information,int size,out int returned);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessWithTokenW(IntPtr token,uint flags,string application,StringBuilder command,uint creation,IntPtr environment,string directory,ref StartupInfo start,out ProcessInfo process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("userenv.dll",SetLastError=true)] static extern bool CreateEnvironmentBlock(out IntPtr block,IntPtr token,bool inherit);
    [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr block);
    public sealed record Result(bool Administrator,bool UiStatus,bool Patch,bool PrivatePipeDenied,bool ProfileDenied,string Error);
    public static async Task Child(string output,string profile)
    {
        bool status=false,patch=false,pipeDenied=false,profileDenied=false;string error="";
        try {
            async Task<UiControlReply> Call(UiControlRequest request) {
                using var limit=new CancellationTokenSource(5000);
                using var pipe=new NamedPipeClientStream(".",UiControlProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
                await pipe.ConnectAsync(3000,limit.Token);await ServiceProtocol.Write(pipe,request,limit.Token);return await ServiceProtocol.Read<UiControlReply>(pipe,limit.Token);
            }
            status=(await Call(new("status"))).Ok;
            patch=(await Call(new("patch",new("standard-token device","error"),Guid.NewGuid()))).Ok;
            using(var full=new NamedPipeClientStream(".",ServiceProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous)) {
                try { await full.ConnectAsync(1500); }
                catch(UnauthorizedAccessException) { pipeDenied=true; }
                catch(IOException ex) when((ex.HResult&0xffff)==5) { pipeDenied=true; }
            }
            try { _=File.ReadAllBytes(profile); } catch(UnauthorizedAccessException) { profileDenied=true; }
        } catch(Exception ex) { error=ex.GetType().Name+": "+ex.Message; }
        File.WriteAllText(output,JsonSerializer.Serialize(new Result(WindowsHost.IsAdmin,status,patch,pipeDenied,profileDenied,error)));
    }
    public static async Task<Result> Run(string profile)
    {
        if(!WindowsInstance.IsValidation)throw new IOException("Linked-token control test requires an isolated validation instance");
        using var identity=WindowsIdentity.GetCurrent();
        if(!GetTokenInformation(identity.Token,19,out var linked,IntPtr.Size,out _)) throw new Win32Exception(Marshal.GetLastWin32Error(),"No linked UAC ordinary token; this gate must remain unverified");
        string output=Path.Combine(Path.GetTempPath(),"StreamLink-linked-ui-"+Guid.NewGuid().ToString("N")+".json");
        var start=new StartupInfo {Size=Marshal.SizeOf<StartupInfo>()};
        string exe=Environment.ProcessPath!;
        if(exe.EndsWith("dotnet.exe",StringComparison.OrdinalIgnoreCase))throw new IOException("Run the built test apphost for the real linked-token child");
        try {
            var command=new StringBuilder($"\"{exe}\" --ui-linked-client \"{output}\" \"{profile}\" {WindowsInstance.ValidationId}");
            // Documented Unicode user environment, avoiding the implicit
            // environment lookup of CreateProcessWithTokenW in remote sessions.
            if(!CreateEnvironmentBlock(out var environment,linked,false))throw new Win32Exception(Marshal.GetLastWin32Error());
            ProcessInfo created;
            try { if(!CreateProcessWithTokenW(linked,0,exe,command,0x08000400,environment,Environment.SystemDirectory,ref start,out created))throw new Win32Exception(Marshal.GetLastWin32Error()); }
            finally { DestroyEnvironmentBlock(environment); }
            try {using var process=Process.GetProcessById((int)created.Pid);using var timeout=new CancellationTokenSource(15000);
                try{await process.WaitForExitAsync(timeout.Token);}catch(OperationCanceledException){process.Kill();await process.WaitForExitAsync();throw;}
                if(process.ExitCode!=0)throw new IOException("Ordinary-token child failed: "+process.ExitCode);
            }finally{CloseHandle(created.Thread);CloseHandle(created.Process);}
            return JsonSerializer.Deserialize<Result>(File.ReadAllText(output))!;
        } finally {CloseHandle(linked);if(File.Exists(output))File.Delete(output);}
    }
}
