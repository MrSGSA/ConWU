using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using StreamLink.Core;

namespace StreamLink.Service;
static class LocalControlPipe
{
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern SafePipeHandle CreateNamedPipe(string name, uint openMode, uint pipeMode, uint maxInstances, uint outputSize, uint inputSize, uint timeout, ref SecurityAttributes attributes);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static string ClientSid(NamedPipeServerStream pipe)
    {
        IntPtr process=IntPtr.Zero,token=IntPtr.Zero;
        try {
            // PIPE_REJECT_REMOTE_CLIENTS and the SID-only pipe ACL form the
            // first boundary. Bind the second check to the kernel-reported
            // local process token, without impersonating the client in the
            // service. The process handle pins its identity against PID reuse.
            if(!GetNamedPipeClientProcessId(pipe.SafePipeHandle,out uint pid)||pid==0)throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot identify local UI process");
            process=OpenProcess(0x1000,false,pid);
            if(process==IntPtr.Zero||!OpenProcessToken(process,8,out token))throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot query local UI process token");
            using var identity=new WindowsIdentity(token);
            return identity.User?.Value??throw new IOException("UI client has no user SID");
        } finally {if(token!=IntPtr.Zero)CloseHandle(token);if(process!=IntPtr.Zero)CloseHandle(process);}
    }
    public static NamedPipeServerStream Create(bool firstInstance = true,string? authorizedUiSid=null)
    {
        var acl = new PipeSecurity(); acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid }) acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        if(authorizedUiSid!=null){var sid=new SecurityIdentifier(authorizedUiSid);if(!sid.IsAccountSid())throw new IOException("UI授权必须是单一用户SID");acl.AddAccessRule(new PipeAccessRule(sid,PipeAccessRights.ReadWrite,AccessControlType.Allow));}
        var bytes = acl.GetSecurityDescriptorBinaryForm(); var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Descriptor = pinned.AddrOfPinnedObject() };
            // Reject remote SMB clients at the pipe boundary, while allowing a local
            // administrator process started through SSH (which has a Network SID).
            string name=authorizedUiSid==null?ServiceProtocol.PipeName:UiControlProtocol.PipeName;
            var handle = CreateNamedPipe(@"\\.\pipe\" + name, firstInstance ? 0x40080003u : 0x40000003u, 0x00000008, 8, 65536, 65536, 0, ref attributes);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try { return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle); } catch { handle.Dispose(); throw; }
        }
        finally { pinned.Free(); }
    }
}
