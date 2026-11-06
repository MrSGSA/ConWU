using System.Net;

namespace StreamLink.Core;

// Suppress kernel TCP replies only for this leased peer tuple. The STUN TCP
// helper remains available, and AF_PACKET still sees the incoming raw frame.
internal sealed class LinuxRawGuard:IDisposable
{
    readonly LinuxKernelResource resource=new();
    string table=>resource.Table;
    public LinuxRawGuard(IPEndPoint local,IPEndPoint peer) {
        try {
            LinuxPlatform.Run("nft","add","table","inet",table);
            LinuxPlatform.Run("nft","add","chain","inet",table,"input","{","type","filter","hook","input","priority","-150",";","policy","accept",";","}");
            LinuxPlatform.Run("nft","add","rule","inet",table,"input","ip","saddr",peer.Address.ToString(),"ip","daddr",local.Address.ToString(),"tcp","sport",peer.Port.ToString(),"tcp","dport",local.Port.ToString(),"drop");
        }catch{Dispose();throw;}
    }
    public void Dispose()=>resource.Dispose();
}
