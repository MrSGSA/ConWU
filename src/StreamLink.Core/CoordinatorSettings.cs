using System.Net;

namespace StreamLink.Core;

public sealed record CoordinatorSettings(bool Enabled=false, string ListenUrl="http://127.0.0.1:47822",
    string CertificateFile="", string CertificateKeyFile="", bool TrustCloudflare=false)
{
    public void Validate() {
        if (!Uri.TryCreate(ListenUrl, UriKind.Absolute, out var url) || url.Scheme is not ("http" or "https") ||
            !IPAddress.TryParse(url.Host, out var address) || url.Port is <1024 or >65535 ||
            url.AbsolutePath != "/" || url.Query.Length!=0 || url.Fragment.Length!=0 || url.UserInfo.Length!=0)
            throw new FormatException("协调监听地址需为 http(s)://监听IP:端口，端口范围 1024–65535");
        if(url.Scheme=="http" && !IPAddress.IsLoopback(address)) throw new FormatException("HTTP 协调仅允许本机监听；公网访问请配置 HTTPS 或本机反向代理");
        foreach(var path in new[]{CertificateFile,CertificateKeyFile})
            if(path==null||path.Length>512||path.Any(char.IsControl)||path.Length>0&&!Path.IsPathFullyQualified(path))throw new FormatException("证书及私钥需为本机绝对路径");
        if(Enabled&&url.Scheme=="https"&&(CertificateFile.Length==0||CertificateKeyFile.Length==0))throw new FormatException("HTTPS 协调监听需要证书和私钥");
    }
}
public sealed record CoordinatorStatus(bool Enabled, bool Running, string State, string[] Addresses);
