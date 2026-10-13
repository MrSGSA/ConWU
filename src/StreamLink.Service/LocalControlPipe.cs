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
