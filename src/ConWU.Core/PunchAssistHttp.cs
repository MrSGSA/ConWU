using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace StreamLink.Core;

internal static class PunchAssistHttp
{
    public static HttpClient Create(string service,string pin,bool bootstrap=false)
    {
        Pairing.Create(service,pin).Validate();var uri=new Uri(service);
        var handler=new SocketsHttpHandler{UseProxy=false,AllowAutoRedirect=false,MaxConnectionsPerServer=2};
        // Candidate/source binding concerns IPv4 NAT. A dual-stack hostname
        // must not send this HTTP control request over an unrelated IPv6 path.
        handler.ConnectCallback=async(context,token)=>{
            var addresses=await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host,token);
            var address=addresses.FirstOrDefault(ip=>ip.AddressFamily==AddressFamily.InterNetwork)??throw new IOException("Mimic 协调辅助需要 IPv4 监听地址");
            var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
            try{await socket.ConnectAsync(new IPEndPoint(address,context.DnsEndPoint.Port),token);return new NetworkStream(socket,true);}
            catch{socket.Dispose();throw;}
        };
        if(pin.Length>0||bootstrap){
            if(bootstrap&&pin.Length==0&&(!IPAddress.TryParse(uri.Host,out var ip)||!PortControlRoute.GlobalV4(ip)))throw new FormatException("辅助直连码需要公网 IPv4 协调地址");
            string? firstPin=null;
            handler.SslOptions.RemoteCertificateValidationCallback=(_,value,_,_)=>{
                if(value==null)return false;
                using var cert=X509CertificateLoader.LoadCertificate(value.GetRawCertData());
                if(DateTime.UtcNow<cert.NotBefore.ToUniversalTime()||DateTime.UtcNow>=cert.NotAfter.ToUniversalTime())return false;
                byte[] actual=SHA256.HashData(cert.RawData);
                if(pin.Length>0)return CryptographicOperations.FixedTimeEquals(actual,Convert.FromHexString(pin));
                string encoded=Convert.ToHexString(actual);Interlocked.CompareExchange(ref firstPin,encoded,null);return firstPin==encoded;
            };
        }
        return new(handler){BaseAddress=uri,Timeout=TimeSpan.FromSeconds(5),MaxResponseContentBufferSize=8192};
    }
}
