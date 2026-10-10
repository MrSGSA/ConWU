using System.Text.Json;
using StreamLink.Core;

namespace StreamLink;
public sealed class MainWindow : Form
{
    readonly Label state = new() { Text = "准备连接", AutoSize = true, Font = new Font("Microsoft YaHei UI", 13, FontStyle.Bold) };
    readonly Label address = new() { Text = "组网后显示本机与对端的虚拟 IP", AutoSize = true };
    readonly Label detail = new() { Text = "一端创建网络，另一端粘贴邀请加入；以后自动连接。", AutoSize = true, MaximumSize = new Size(780, 0) };
    readonly TextBox input = new() { Multiline = true, Dock = DockStyle.Fill, Height = 65, PlaceholderText = "加入已有网络：在此粘贴 SL2. 邀请" };
    readonly TextBox invite = new() { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, Height = 65, ScrollBars = ScrollBars.Vertical };
    readonly TextBox logs = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly TextBox discovery = new() { Width = 360, Text = "https://ssh.space4sgsa.com:42860/" };
    readonly TextBox pin = new() { Width = 390, PlaceholderText = "证书 SHA-256（自托管时填写，正规证书可留空）" };
    readonly System.Windows.Forms.Timer timer = new() { Interval = 2500 };
    readonly CancellationTokenSource lifetime = new();
    DeviceProfile? profile;
    bool busy;
    public MainWindow(bool preview = false)
    {
        AutoScaleMode = AutoScaleMode.None; Text = "StreamLink · 自动 P2P 组网 · 0.2.0 预览版"; Font = new("Microsoft YaHei UI", 9); Size = new(920, 800); MinimumSize = new(820, 690); StartPosition = FormStartPosition.CenterScreen; BackColor = Color.FromArgb(245, 247, 251);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(22), ColumnCount = 1, RowCount = 12 }; Controls.Add(layout);
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "配对一次，自动直连", AutoSize = true, Font = new(Font.FontFamily, 18, FontStyle.Bold), ForeColor = Color.FromArgb(28, 51, 79) });
        layout.Controls.Add(new Label { Text = "内置原生 udp2raw 与组网组件 · FakeTCP + HTTP 特征 · 业务始终 P2P", AutoSize = true });
        var serviceRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        var serviceSettings = new Button { Text = "发现服务设置", AutoSize = true };
        serviceSettings.Click += (_, _) => {
            using var dialog = new Form { Text = "自托管发现服务", Size = new(700, 240), StartPosition = FormStartPosition.CenterParent, Font = Font, AutoScaleMode = AutoScaleMode.Dpi };
            var table = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(16), ColumnCount = 1, RowCount = 5 }; table.ColumnStyles.Add(new(SizeType.Percent,100)); dialog.Controls.Add(table);
            table.Controls.Add(new Label { Text = "HTTPS 服务地址（仅用于新建配对；现有配对保持原服务）", AutoSize = true }); discovery.Dock=DockStyle.Fill; table.Controls.Add(discovery);
            table.Controls.Add(new Label { Text = "自签名证书 SHA-256 指纹；受信任的正规证书留空", AutoSize = true }); pin.Dock=DockStyle.Fill; table.Controls.Add(pin);
            var done = new Button { Text = "完成", AutoSize=true }; done.Click += (_,_) => dialog.Close(); table.Controls.Add(done); dialog.ShowDialog(this); table.Controls.Remove(discovery); table.Controls.Remove(pin);
        };
        serviceRow.Controls.AddRange([new Label { Text = "地址发现已配置，业务数据由两端直接传输。", AutoSize = true, Padding = new(0, 5, 0, 0) }, serviceSettings]); layout.Controls.Add(serviceRow);
        var inputGroup = new GroupBox { Text = "加入网络：粘贴另一台电脑生成的邀请", Dock = DockStyle.Fill, Height = 90 }; inputGroup.Controls.Add(input); layout.Controls.Add(inputGroup);
        var pairActions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        Button Button(string text, Func<Task> action) { var b = new Button { Text = text, AutoSize = true, Height = 36 }; b.Click += async (_, _) => await Action(action); return b; }
        pairActions.Controls.Add(Button("创建网络", async () => { await Ensure(); Apply(await Call(new("create", Service: discovery.Text.Trim(), Pin: pin.Text.Trim()))); Apply(await Call(new("start"))); }));
        pairActions.Controls.Add(Button("粘贴邀请后加入", async () => { await Ensure(); Apply(await Call(new("join", Invite: input.Text))); input.Clear(); Apply(await Call(new("start"))); }));
        pairActions.Controls.Add(Button("复制配对邀请", () => { if (invite.Text.Length > 0) Clipboard.SetText(invite.Text); return Task.CompletedTask; })); layout.Controls.Add(pairActions);
        var inviteGroup = new GroupBox { Text = "本机创建的网络邀请（仅首次配对需要）", Dock = DockStyle.Fill, Height = 90 }; inviteGroup.Controls.Add(invite); layout.Controls.Add(inviteGroup);
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        actions.Controls.Add(Button("启动网络", async () => { await Ensure(); Apply(await Call(new("start"))); }));
        actions.Controls.Add(Button("停止网络", async () => Apply(await Call(new("stop")))));
        actions.Controls.Add(Button("连接设置", async () => { await Ensure(); Apply(await Call(new("status"))); using var settings = new SettingsWindow(profile!); if (settings.ShowDialog(this) == DialogResult.OK) Apply(await Call(new("save", settings.Result))); }));
        actions.Controls.Add(Button("测 50 Mbps", async () => { detail.Text = "测试对端 → 本机，50 Mbps、20 秒；会占用带宽。"; Apply(await Call(new("quality"))); }));
        actions.Controls.Add(Button("移除后台服务", async () => { await ServiceInstaller.Uninstall(); state.Text = "后台服务已移除"; detail.Text = "配对配置与日志保留；再次启动可重新安装。"; })); layout.Controls.Add(actions);
        layout.Controls.Add(state); layout.Controls.Add(address); layout.Controls.Add(detail);
        layout.Controls.Add(new Label { Text = "首次操作会安装开机自启服务。关闭界面后继续组网；要断开请点“停止网络”。邀请包含密钥。", AutoSize = true }); layout.Controls.Add(logs);
        for (int i = 0; i < 11; i++) layout.RowStyles.Add(new(SizeType.AutoSize)); layout.RowStyles.Add(new(SizeType.Percent, 100));
        for (int i = 0; i < layout.Controls.Count; i++) layout.SetCellPosition(layout.Controls[i], new(0, i));
        string defaults = Path.Combine(AppContext.BaseDirectory, "discovery-defaults.json");
        if (File.Exists(defaults)) { using var json = JsonDocument.Parse(File.ReadAllText(defaults)); discovery.Text = json.RootElement.GetProperty("Service").GetString(); pin.Text = json.RootElement.GetProperty("CertificatePin").GetString(); }
        timer.Tick += async (_, _) => { if (busy || !ServiceInstaller.Installed) return; await Action(async () => Apply(await Call(new("status"))), false); };
        if (!preview) Shown += async (_, _) => { timer.Start(); if (ServiceInstaller.Installed) await Action(async () => Apply(await Call(new("status"))), false); };
        FormClosed += (_, _) => { timer.Stop(); timer.Dispose(); lifetime.Cancel(); lifetime.Dispose(); };
        float scale = DeviceDpi / 96f; if (scale != 1f) Scale(new SizeF(scale, scale));
    }
    async Task Ensure() { state.Text = "正在准备后台服务"; await ServiceInstaller.Install(); }
    async Task<ControlReply> Call(ControlRequest request) { var reply = await ServiceProtocol.Call(request, lifetime.Token); if (!reply.Ok) throw new IOException(reply.Error); return reply; }
    async Task Action(Func<Task> action, bool show = true)
    {
        if (busy) return; busy = true;
        try { await action(); } catch (Exception ex) { if (!IsDisposed) { state.Text = "操作未完成"; detail.Text = ex.Message; if (show) logs.AppendText(ex.Message + Environment.NewLine); } } finally { busy = false; }
    }
    void Apply(ControlReply reply)
    {
        profile = reply.Profile; invite.Text = reply.Invite;
        if (profile?.Pair != null) { discovery.Text = profile.Pair.Service; pin.Text = profile.Pair.CertificatePin; }
        state.Text = reply.Status?.State ?? "后台服务就绪";
        state.ForeColor = reply.Status?.Connected == true ? Color.DarkGreen : Color.FromArgb(28, 51, 79);
        address.Text = reply.Status is { } s ? $"本机 {s.LocalIp}  ·  对端 {s.PeerIp}" + (s.RttMs.HasValue ? $"  ·  RTT {s.RttMs:F1} ms" : "") : "配对后提供固定虚拟 IP，入口角色可自动切换";
        detail.Text = reply.Quality.Length > 0 ? reply.Quality : reply.Status?.Detail ?? "创建新网络或粘贴另一端的邀请";
        string text = string.Join(Environment.NewLine, reply.Logs); if (logs.Text != text) { logs.Text = text; logs.SelectionStart = logs.TextLength; logs.ScrollToCaret(); }
    }
}
