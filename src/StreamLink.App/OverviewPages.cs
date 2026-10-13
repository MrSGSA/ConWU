using System.Text.Json;
using StreamLink.Core;

namespace StreamLink;
public sealed partial class MainWindow
{
    Label? overviewCount,overviewMode;
    void BuildOverview(TableLayoutPanel stack)
    {
        stack.Controls.Add(Design.Label("你的直连网络",22,true));stack.Controls.Add(Design.Label("业务由设备之间传输，协调服务只交换配对与地址信息。",10));
        var state=Card(stack,"网络状态");networkState=Design.Label("正在读取本机状态",18,true);addresses=Design.Label("",10);
        overviewCount=Design.Label("",10);overviewMode=Design.Label("",9);state.Controls.Add(networkState);state.Controls.Add(addresses);state.Controls.Add(overviewCount);state.Controls.Add(overviewMode);
        var start=ActionButton("启动网络","正在启动网络…",async()=>{Apply(await Call(new("start")));return "启动请求已接受，等待对端认证直连";},true);
        var stop=ActionButton("停止网络","正在停止网络…",async()=>{Apply(await Call(new("stop")));return "网络已停止，配对已保留";});
        state.Controls.Add(Design.Row(start,stop));
        var pairing=Card(stack,"配对与成员");
        var join=Design.Button("加入网络");join.AccessibleName="输入配对码加入网络";join.Click+=(_,_)=>{if(!busy)ShowPage("join");};actions.Add(join);
        var create=Design.Button("创建 / 邀请");create.AccessibleName="创建网络或邀请设备";create.Click+=(_,_)=>{if(!busy)ShowPage("create");};actions.Add(create);
        pairing.Controls.Add(Design.Row(join,create));pairing.Controls.Add(Design.Label("首次配对使用6位码；创建者身份不决定谁提供公网入口。",9));
        quality=Design.Label("",9);quality.MaximumSize=new(640,0);state.Controls.Add(quality);
    }
    void BuildDevices(TableLayoutPanel stack)
    {
        stack.Controls.Add(Design.Label("设备",22,true));stack.Controls.Add(Design.Label("这里显示与本机的直连关系，未连通的成员不会经其他设备中继。",10));
        var mine=Card(stack,"本机");localDevice=Design.Label("",12,true);mine.Controls.Add(localDevice);addresses=Design.Label("",10);mine.Controls.Add(addresses);
        var peers=Card(stack,"网络成员");BuildMembers(peers);
        var diagnose=Design.Button("查看诊断");diagnose.Click+=(_,_)=>ShowPage("diagnostics");peers.Controls.Add(diagnose);
    }
    void BuildDiagnostics(TableLayoutPanel stack)
    {
        stack.Controls.Add(Design.Label("诊断",22,true));stack.Controls.Add(Design.Label("连接可用与负载质量是两项证据。只读检查不会启动压测。",10));
        var current=Card(stack,"当前连接");networkState=Design.Label("",16,true);quality=Design.Label("",10);quality.MaximumSize=new(640,0);current.Controls.Add(networkState);current.Controls.Add(quality);BuildMembers(current);
        var read=ActionButton("刷新状态","正在读取本机状态…",async()=>{Apply(await Call(new("status")));return "已更新只读状态，未发送测速负载";});
        var load=ActionButton("测 50 Mbps","正在请求20秒测速…",async()=>{if(last?.ManualQualityVersion!=2)throw new IOException("后台未支持有许可的manual-v2测速，请先升级后台");Apply(await Call(new("quality",PeerSlot:(qualityPeer?.SelectedItem as PeerChoice)?.Slot??0)));return "测速已启动；可取消，结果含接收计数";});
        current.Controls.Add(Design.Row(read,load));current.Controls.Add(Design.Label("对端需在设置允许测速。最多20秒，每90秒一次；会与正在使用的业务争用带宽。",9));
        var export=Design.Button("导出只读诊断");export.Click+=(_,_)=>ExportReadOnly();var logs=Design.Button("显示日志");logs.Click+=(_,_)=>ShowLogs();current.Controls.Add(Design.Row(export,logs));
    }
    void UpdateOverview()
    {
        if(overviewCount is{IsDisposed:false}){var peers=last?.Status?.Peers??[];int connected=peers.Count(p=>p.Connected);overviewCount.Text=$"与本机直连 {connected}/{peers.Length} 台设备";}
        if(overviewMode is{IsDisposed:false})overviewMode.Text=$"{(backend.IsService?"后台服务":"前台运行")} · 当前策略 {last?.Profile?.PathSelection??"prefer-faketcp"} · 官方 Wintun / WinDivert";
    }
    void ExportReadOnly()
    {
        using var dialog=new SaveFileDialog{Filter="诊断JSON|*.json",FileName="streamlink-readonly-diagnostic.json"};if(dialog.ShowDialog(this)!=DialogResult.OK)return;
        var state=last?.Status;
        var report=new{schema=1,kind="ReadOnlySnapshot",capturedUtc=DateTimeOffset.UtcNow,version=last?.Version,device=last?.Profile?.DeviceName,virtualIp=last?.Profile?.Mesh?.LocalIp,
            connected=state?.Connected??false,state=state?.State,peers=state?.Peers?.Select(p=>new{p.Slot,p.Name,p.Ip,p.Connected,p.Degraded,p.RttMs}),businessRelay=false};
        File.WriteAllText(dialog.FileName,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true}));notice.Text="已导出只读诊断；不包含配对凭据或原始控制回复";
    }
}
