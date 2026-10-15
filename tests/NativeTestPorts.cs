using System.Net;
using System.Net.Sockets;

// Native fixtures sometimes need both protocol namespaces for one port. Do
// not pick a released port from Windows' ephemeral pool: parent IPC sockets
// can otherwise take it before the native child binds its TCP listener.
static class NativeTestPorts
{
    public static int Take(ISet<int>? used=null)
    {
        for(int attempt=0;attempt<256;attempt++){
            int port=Random.Shared.Next(20000,40000);
            if(used?.Contains(port)==true)continue;
            try {
                using var tcp=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){ExclusiveAddressUse=true};
                using var udp=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp){ExclusiveAddressUse=true};
                tcp.Bind(new IPEndPoint(IPAddress.Any,port));udp.Bind(new IPEndPoint(IPAddress.Any,port));
                used?.Add(port);return port;
            }catch(SocketException ex)when(ex.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied){}
        }
        throw new IOException("No free TCP/UDP native fixture port outside the default ephemeral range");
    }
}
