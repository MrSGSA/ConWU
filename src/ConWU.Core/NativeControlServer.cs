using System.IO.Pipes;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

internal sealed class NativeControlServer : Stream
{
    readonly NamedPipeServerStream? windows;
    readonly Socket? listener;
    readonly string? directory;
    Stream? connected;
    public string Name {get;}
    public bool IsConnected=>windows?.IsConnected??connected!=null;
    [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe,out uint pid);
    [StructLayout(LayoutKind.Sequential)]struct Cred{public int Pid;public uint Uid;public uint Gid;}
    [DllImport("libc",SetLastError=true)]static extern int getsockopt(int socket,int level,int option,out Cred value,ref uint length);
    public NativeControlServer(int size) {
        string id=Guid.NewGuid().ToString("N");
        if(OperatingSystem.IsLinux()) {
            directory=Path.Combine(Path.GetTempPath(),"sl-attach-"+id);LinuxPlatform.PrivateDirectory(directory);
            Name=Path.Combine(directory,"control.sock");listener=new(AddressFamily.Unix,SocketType.Stream,ProtocolType.Unspecified);
            try{listener.Bind(new UnixDomainSocketEndPoint(Name));File.SetUnixFileMode(Name,UnixFileMode.UserRead|UnixFileMode.UserWrite);listener.Listen(1);}
            catch{listener.Dispose();if(File.Exists(Name))File.Delete(Name);Directory.Delete(directory);throw;}
        }else {
            Name="StreamLink.Attach."+id;windows=new(Name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly|PipeOptions.FirstPipeInstance,size*2,size*2);connected=windows;
        }
    }
    public async Task Accept(int child,CancellationToken token) {
        if(windows!=null){await windows.WaitForConnectionAsync(token);if(!GetNamedPipeClientProcessId(windows.SafePipeHandle,out uint pid)||pid!=child)throw new IOException("Native IPC client is not the launched process");}
        else {
            var socket=await listener!.AcceptAsync(token);
            try {uint size=12;if(getsockopt((int)socket.Handle,1,17,out var cred,ref size)!=0||size!=12||cred.Pid!=child||cred.Uid!=LinuxPlatform.geteuid())throw new IOException("Native Unix peer identity mismatch");connected=new NetworkStream(socket,true);}
            catch{socket.Dispose();throw;}
        }
    }
    Stream Connection=>connected??throw new IOException("Native IPC is not connected");
    public override bool CanRead=>connected?.CanRead==true;public override bool CanWrite=>connected?.CanWrite==true;public override bool CanSeek=>false;
    public override long Length=>throw new NotSupportedException();public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
    public override void Flush()=>Connection.Flush();public override int Read(byte[] b,int o,int c)=>Connection.Read(b,o,c);public override void Write(byte[] b,int o,int c)=>Connection.Write(b,o,c);
    public override ValueTask<int> ReadAsync(Memory<byte> b,CancellationToken t=default)=>Connection.ReadAsync(b,t);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> b,CancellationToken t=default)=>Connection.WriteAsync(b,t);
    public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();public override void SetLength(long v)=>throw new NotSupportedException();
    protected override void Dispose(bool disposing) {
        if(disposing){connected?.Dispose();connected=null;windows?.Dispose();listener?.Dispose();if(directory!=null&&Directory.Exists(directory)){if(File.Exists(Name))File.Delete(Name);Directory.Delete(directory);}}
        base.Dispose(disposing);
    }
}
