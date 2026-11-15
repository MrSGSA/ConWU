namespace StreamLink.Core;

// Used by clients that hand a complete local package to the OS installer.
// The caller still verifies its platform's package identity and signing key.
public static class OfficialUpdatePackage
{
    public static ReleaseUpdatePackage Validate(ReleaseUpdateStatus release,string extension)
    {
        var package=release.Package??throw new IOException("没有适合本机的安装包");
        string prefix=ReleaseUpdateClient.Repository+"/releases/tag/";
        string tag=release.ReleaseUrl.StartsWith(prefix,StringComparison.Ordinal)?release.ReleaseUrl[prefix.Length..]:"";
        if(!release.UpdateAvailable||!ReleaseVersion.TryParse(release.LatestVersion,out _)||tag!=release.LatestVersion&&tag!="v"+release.LatestVersion||
            !package.Name.StartsWith("ConWU-"+release.LatestVersion+"-",StringComparison.Ordinal)||!package.Name.EndsWith(extension,StringComparison.Ordinal)||
            package.Name.Any(c=>char.IsControl(c)||c is '/' or '\\')||package.Url!=ReleaseUpdateClient.Repository+"/releases/download/"+Uri.EscapeDataString(tag)+"/"+Uri.EscapeDataString(package.Name)||
            package.Bytes is <1024 or >1_073_741_824||package.Sha256.Length!=64||!package.Sha256.All(char.IsAsciiHexDigit))throw new IOException("安装包的来源、版本或校验信息不完整");
        return package;
    }
    public static async Task Download(ReleaseUpdatePackage package,string target,Action<long,long> progress,CancellationToken token,HttpClient? client=null)
    {
        bool owns=client==null;
        client??=new(new SocketsHttpHandler{AllowAutoRedirect=false,UseCookies=false,ConnectTimeout=TimeSpan.FromSeconds(10)}){Timeout=Timeout.InfiniteTimeSpan};
        try{await UpdatePackageTransfer.Download(package,target,progress,token,client);}
        finally{if(owns)client.Dispose();}
    }
}
