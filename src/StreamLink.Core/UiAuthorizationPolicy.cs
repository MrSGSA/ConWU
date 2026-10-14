namespace StreamLink.Core;

public static class UiAuthorizationPolicy
{
    // Arguments are SIDs already resolved/validated by the Windows boundary.
    // Installation is not an implicit grant-change operation.
    public static string SelectForInstall(string? previousSid,string? explicitlySelectedSid)
    {
        if(previousSid!=null){
            if(explicitlySelectedSid!=null&&explicitlySelectedSid!=previousSid)
                throw new IOException("升级保留既有日常用户授权；更改授权必须另行确认，不能通过安装覆盖");
            return previousSid;
        }
        return explicitlySelectedSid??throw new IOException("首次安装请明确指定日常登录用户；命令行使用 --install --ui-user-account 域\\用户名，或运行交互安装");
    }
}
