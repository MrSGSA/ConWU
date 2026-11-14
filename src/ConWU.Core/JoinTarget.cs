namespace StreamLink.Core;

// A single user-supplied address may identify HTTPS coordination or an entry
// source. Detect the service before submitting any pairing code or identity.
public static class JoinTarget
{
    public static async Task<UiNetworkAction> Resolve(UiNetworkAction action,
        Func<string,string,CancellationToken,Task<CoordinatorDiagnostic>> probe,CancellationToken token)
    {
        string source=action.Entry?.Trim()??"";
        if(!action.AutoConfigure||action.Code is not {Length:6}||!action.Code.All(char.IsAsciiDigit)||source.Length is <1 or >2048||source.Any(char.IsControl))
            throw new FormatException("请填写目标网络的协调服务器或已有入口，并输入六位配对码");
        string pin=action.CertificatePin??"";
        if(pin.Length>0&&(pin.Length!=64||!pin.All(char.IsAsciiHexDigit)))throw new FormatException("协调证书指纹需要 64 位十六进制字符");
        if(Uri.TryCreate(source,UriKind.Absolute,out var uri)&&uri.Scheme=="https"&&uri.UserInfo.Length==0&&uri.Query.Length==0&&uri.Fragment.Length==0){
            string service=uri.AbsoluteUri.EndsWith('/')?uri.AbsoluteUri:uri.AbsoluteUri+"/";
            var result=await probe(service,pin,token);
            if(result.Reachable)return action with{Action="join",Service=service,CertificatePin=pin,Entry=""};
            // A failed trust/connection check must not turn into an unpinned
            // fetch or leak a short code into a subscription HTTP request.
            if(pin.Length>0||result.Code is not ("protocol" or "http-404" or "http-405"))throw new IOException(result.Detail);
        }
        if(pin.Length>0)throw new FormatException("证书指纹仅用于 HTTPS 协调服务器；使用已有入口时请清空指纹");
        var entries=new[]{new ExistingEntry(ExistingEntry.NetworkOwner,source)};
        ExistingEntryResolver.Validate(entries);
        if(ExistingEntryResolver.Kind(source)=="PKARR")throw new FormatException("此处填写协调服务器或已有入口；PKARR 首次加入请使用直连邀请");
        return action with{Action="join-direct-short",Service="",CertificatePin="",Entry=ExistingEntryResolver.NormalizeSource(source),Mode=source.StartsWith("udp://",StringComparison.OrdinalIgnoreCase)?"udp":source.StartsWith("tcp://",StringComparison.OrdinalIgnoreCase)?"faketcp":action.Mode};
    }
}
