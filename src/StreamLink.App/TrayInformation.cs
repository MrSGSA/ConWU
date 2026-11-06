using StreamLink.Core;

namespace StreamLink;
public static class TrayInformation
{
    static string Line(string? value,int limit)
    {
        string clean=new((value??"").Where(c=>!char.IsControl(c)&&c!='\u2028'&&c!='\u2029').ToArray());
        return clean.Length>limit?clean[..(limit-1)]+"…":clean;
    }
    public static string Format(UiStatusDto? status,string unavailable="正在读取")
    {
        string state=status==null?unavailable:!status.ServiceReady?"后台正在启动":!status.NetworkEnabled?"网络未启动":Line(status.State,22);
        return $"ConWU {Line(ApplicationVersion.Release.Replace("1.0.0-aq1-personal.","1.0.0 · 个人版 ."),28)}\n状态：{Line(state,22)}\n设备：{Line(status?.DeviceName??Environment.MachineName,28)}\nIP：{Line(string.IsNullOrEmpty(status?.VirtualIp)?"未分配":status.VirtualIp,18)}";
    }
}
