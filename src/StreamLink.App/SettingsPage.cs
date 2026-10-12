using System.Net;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink;

public sealed partial class MainWindow
{
    void BuildSettings(TableLayoutPanel stack)
    {
        stack.Controls.Add(Design.Label("设置", 22, true)); stack.Controls.Add(Design.Label("按你的网络习惯连接。", 10));
        var server = Card(stack, "协调服务器"); server.Controls.Add(Design.Label("用于配对与更新公网地址，不中继业务流量。", 9));
        var selection = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 360 }; selection.Items.AddRange(["自定义服务器", "公共服务器（暂未提供）"]); selection.SelectedIndex = 0; server.Controls.Add(selection);
        var url = new TextBox { Width = 590, PlaceholderText = "https://你的服务器/", Text = preferences.Server, Margin = new(0, 8, 0, 8) }; var pin = new TextBox { Width = 590, PlaceholderText = "证书 SHA-256（仅自签证书需要）", Text = preferences.Pin };
        server.Controls.Add(Design.Label("服务器地址（HTTPS）", 9)); server.Controls.Add(url);
        server.Controls.Add(Design.Label("证书指纹（选填，仅自签证书需要）", 9)); server.Controls.Add(pin);
        selection.SelectedIndexChanged += (_, _) => { url.Enabled = pin.Enabled = selection.SelectedIndex == 0; }; server.Controls.Add(Design.Label("修改仅用于下一次配对。当前配对保留原服务器。", 9));
        var network = Card(stack, "连接与组网"); var method = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 340 }; method.Items.AddRange(["TCP 映射 + FakeTCP（推荐）", "UDP 映射（实验）"]); method.SelectedIndex = last?.Profile?.TransportMode == "udp" ? 1 : 0;
        network.Controls.Add(Design.Label("打洞方式 · 用于新创建的网络", 9)); network.Controls.Add(method); network.Controls.Add(Design.Label("加入端跟随创建端。UDP 不保证绕过 QoS，当前自动映射需要 UPnP。", 9));
        var transport = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 340 }; transport.Items.Add("原生虚拟网卡 + UDP2RAW"); transport.SelectedIndex = 0; network.Controls.Add(Design.Label("组网传输", 9)); network.Controls.Add(transport); network.Controls.Add(Design.Label("每台设备一张虚拟网卡；各成员独立直连，无业务中继。", 9));
        var advanced = ActionButton("STUN 与端口设置", "正在读取网络设置…", async () => { Apply(await Call(new("status"))); if (last!.Version == "0.2.0") throw new IOException("请先更新后台服务，再保存新版 STUN 设置"); using var settings = new SettingsWindow(last.Profile!, last.PathSelectionVersion == 1, last.TcpObserverVersion == 1, last.PortControlVersion >= 1, last.PortControlVersion >= 2, last.UdpIpv6Version == 1, last.FakeTcpIpv6Version == 1, last.EgressPacingVersion == 1, last.TcpCalibrationVersion == 1, last.TcpPredictionVersion == 1, last.TcpPeerReflexiveVersion == 1); if (settings.ShowDialog(this) == DialogResult.OK) { Apply(await Call(new("save", settings.Result))); return "网络设置已保存，已启用的网络正在重连"; } return "已保留原网络设置"; }); advanced.Width = 180; network.Controls.Add(advanced);
        var log = Card(stack, "日志与设备"); var name = new TextBox { Width = 340, Text = last?.Profile?.DeviceName ?? Environment.MachineName, MaxLength = 64 }; log.Controls.Add(Design.Label("设备名称", 9)); log.Controls.Add(name);
        var level = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 }; level.Items.AddRange(["关闭文件日志", "仅错误", "常规", "详细调试"]); string[] levels = ["off", "error", "info", "debug"]; level.SelectedIndex = Math.Max(0, Array.IndexOf(levels, last?.Profile?.LogLevel ?? "info")); log.Controls.Add(Design.Label("日志等级", 9)); log.Controls.Add(level);
        var folder = new TextBox { Width = 440, Text = last?.Profile?.LogDirectory ?? "", PlaceholderText = "留空使用 ProgramData\\StreamLink\\logs" }; var browse = Design.Button("选择目录"); browse.Width = 100; browse.Click += (_, _) => { using var dialog = new FolderBrowserDialog(); if (dialog.ShowDialog(this) == DialogResult.OK) folder.Text = dialog.SelectedPath; }; log.Controls.Add(Design.Label("日志保存目录", 9)); log.Controls.Add(Design.Row(folder, browse));
        log.Controls.Add(ActionButton("显示日志", "正在读取日志…", async () => { Apply(await Call(new("status"))); ShowLogs(); return "已打开日志窗口"; }));
        var background = Card(stack, "后台与托盘"); var useTray = new CheckBox { Text = "显示右下角托盘图标", Checked = preferences.Tray, AutoSize = true }; var closeTray = new CheckBox { Text = "关闭窗口时驻留托盘", Checked = preferences.CloseToTray, AutoSize = true }; background.Controls.Add(useTray); background.Controls.Add(closeTray); var animations = new CheckBox { Text = "启用轻量界面动效（遵循系统动画设置）", Checked = preferences.Animations, AutoSize = true }; background.Controls.Add(animations);
        background.Controls.Add(Design.Label(backend.IsService ? "已安装开机服务；服务可在未登录桌面时运行。" : "当前为前台模式；按需安装服务，实现未登录桌面自动连接。", 9));
        background.Controls.Add(Design.Row(ActionButton(backend.IsService ? "更新后台服务" : "安装后台服务", "正在安装后台服务，请稍候…", async () => { await backend.ReleaseLocal(); await ServiceInstaller.Install(); Apply(await Call(new("status"))); ShowPage("settings"); return "后台服务已安装并启动"; }), ActionButton("卸载后台服务", "正在停止并卸载后台服务…", async () => { if (!backend.IsService) return "当前未安装后台服务，前台连接保持原状态"; await ServiceInstaller.Uninstall(); await backend.ReleaseLocal(); Apply(await Call(new("status"))); ShowPage("settings"); return "后台服务已卸载，配对保留，现为前台模式"; })));
        background.Controls.Add(Design.Label("安装／更新会切换当前连接；卸载会停止网络，保留配对与日志。", 9));
        var about = Card(stack, "关于 StreamLink"); var github = Design.Button("访问 GitHub"); github.Click += (_, _) => OpenUrl("https://github.com/MrSGSA/StreamLink"); about.Controls.Add(Design.Row(github, ActionButton("检查更新", "正在检查 GitHub 发布…", CheckUpdate)));
        stack.Controls.Add(ActionButton("保存设置", "正在保存设置…", async () => {
            if (selection.SelectedIndex != 0) throw new IOException("公共协调服务器尚未提供，请选择自定义服务器");
            string service = url.Text.Trim(); if (service.Length > 0) { if (!service.EndsWith('/')) service += "/"; Pairing.Create(service, pin.Text.Trim()).Validate(); }
            var profile = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(last?.Profile ?? new()))!;
            profile.DeviceName = name.Text.Trim(); profile.TransportMode = method.SelectedIndex == 1 ? "udp" : "faketcp"; profile.LogLevel = levels[level.SelectedIndex]; profile.LogDirectory = folder.Text.Trim(); profile.Validate();
            if (JsonSerializer.Serialize(profile) != JsonSerializer.Serialize(last?.Profile)) { if (last?.Version == "0.2.0") throw new IOException("请先更新后台服务，再更改连接与日志选项"); Apply(await Call(new("save", profile))); }
            if ((service != preferences.Server || pin.Text.Trim() != preferences.Pin) && room != null) await ClearPair(true);
            preferences.Server = service; preferences.Pin = pin.Text.Trim(); preferences.Tray = useTray.Checked; preferences.CloseToTray = useTray.Checked && closeTray.Checked; preferences.Animations = animations.Checked; Motion.Enabled = animations.Checked; preferences.Save(); ApplyTray(); return "设置已保存";
        }, true));
    }
    async Task<string> CheckUpdate()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 262144 }; http.DefaultRequestHeaders.UserAgent.ParseAdd("StreamLink/" + DesktopVersion.Number);
        using var response = await http.GetAsync("https://api.github.com/repos/MrSGSA/StreamLink/releases?per_page=10", lifetime.Token);
        if (response.StatusCode == HttpStatusCode.NotFound) return "仓库目前为私有，请点击“访问 GitHub”登录后查看 Release";
        response.EnsureSuccessStatusCode(); using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(lifetime.Token)); var latest = json.RootElement.EnumerateArray().FirstOrDefault(r => !r.GetProperty("draft").GetBoolean());
        if (latest.ValueKind == JsonValueKind.Undefined) return "暂未发现发布版本";
        string tag = latest.GetProperty("tag_name").GetString() ?? ""; string ver = tag.TrimStart('v').Split('-')[0];
        return Version.TryParse(ver, out var version) && version > DesktopVersion.Current ? $"发现新版本 {tag}，请前往 GitHub Release 下载" : $"当前版本 {DesktopVersion.Number}；GitHub 最近发布 {tag}";
    }
}
