using System.Diagnostics;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink;

public sealed partial class MainWindow : Form
{
    readonly DesktopBackend backend = new();
    readonly DesktopSettings preferences = DesktopSettings.Load();
    readonly CancellationTokenSource lifetime = new();
    readonly SemaphoreSlim uiGate = new(1, 1);
    readonly System.Windows.Forms.Timer timer = new() { Interval = 2500 };
    readonly NotifyIcon tray = new();
    readonly Panel content = new ScrollViewport { Dock = DockStyle.Fill, AutoScroll = true, Padding = new(28, 18, 28, 20) };
    readonly Label notice = Design.Label("准备就绪", 10), modeLabel = Design.Label("", 9);
    readonly ProgressBar progress = new() { Style = ProgressBarStyle.Marquee, Height = 3, Dock = DockStyle.Top, Visible = false, MarqueeAnimationSpeed = 25 };
    readonly Dictionary<string, RoundedButton> nav = new();
    readonly List<Control> actions = [];
    readonly bool preview;
    string page = "join";
    bool busy, polling, exiting, allowClose;
    ControlReply? last;
    Label? networkState, addresses, localDevice, peerDevice, quality, pairText, pairHint;
    TextBox? input;
    RoundedButton? approve, reject;
    FlowLayoutPanel? approvalRow;
    ShortPairClient? pairClient;
    PairKeyExchange? pairKey;
    PairRoomTicket? room;
    PairRoomState? roomState;
    byte[]? exchange;
    bool owner, revealed;
    public MainWindow(bool preview = false)
    {
        SuspendLayout();
        this.preview = preview;
        Text = $"StreamLink · {DesktopVersion.Number} 预览版"; ClientSize = new(1080, 740); MinimumSize = new(940, 680);
        AutoScaleMode = AutoScaleMode.None; Font = Design.Font(); ForeColor = Design.Ink; StartPosition = FormStartPosition.CenterScreen; Icon = MakeIcon();
        DoubleBuffered = true;
        var background = new PearlPanel { Dock = DockStyle.Fill }; Controls.Add(background);
        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 3, BackColor = Color.Transparent, Padding = new(24, 22, 24, 16) };
        shell.ColumnStyles.Add(new(SizeType.Absolute, 180)); shell.ColumnStyles.Add(new(SizeType.Percent, 100)); shell.RowStyles.Add(new(SizeType.Absolute, 78)); shell.RowStyles.Add(new(SizeType.Percent, 100)); shell.RowStyles.Add(new(SizeType.Absolute, 62)); background.Controls.Add(shell);
        var heading = Design.Stack(); heading.Controls.Add(Design.Label("StreamLink", 25, true)); heading.Controls.Add(Design.Label("连接彼此，保持直达。", 10)); shell.Controls.Add(heading, 0, 0); shell.SetColumnSpan(heading, 2);
        var navigation = Design.Stack(); navigation.Padding = new(0, 24, 10, 0); shell.Controls.Add(navigation, 0, 1);
        foreach (var (id, text) in new[] { ("join", "加入网络"), ("create", "创建网络"), ("settings", "设置") }) {
            var button = Design.Button(text); button.Width = 166; button.Height = 48; button.Margin = new(0, 0, 0, 12); nav[id] = button;
            button.Click += (_, _) => { if (!busy) ShowPage(id); }; navigation.Controls.Add(button);
        }
        navigation.Controls.Add(Design.Label($"Windows · P2P\n{DesktopVersion.Number} 预览版", 9)); shell.Controls.Add(content, 1, 1);
        var footer = Design.Stack(); footer.Controls.Add(progress); notice.MaximumSize = new(920, 0); footer.Controls.Add(notice); footer.Controls.Add(modeLabel); shell.Controls.Add(footer, 0, 2); shell.SetColumnSpan(footer, 2);
        tray.Icon = Icon; tray.Text = "StreamLink"; tray.DoubleClick += (_, _) => Restore();
        var menu = new ContextMenuStrip(); menu.Items.Add("打开 StreamLink", null, (_, _) => Restore()); menu.Items.Add("停止网络", null, async (_, _) => await Run("正在停止网络…", async () => { Apply(await Call(new("stop"))); return "网络已停止，配对已保留"; })); menu.Items.Add("退出界面", null, (_, _) => { exiting = true; Close(); }); tray.ContextMenuStrip = menu;
        timer.Tick += async (_, _) => await Poll();
        if (preview) last = new(true, "", new DeviceProfile { Slot = 2, Pair = Pairing.Create("https://example.com/", ""), Enabled = true, DeviceName = "我的电脑" }, new("已直连", "10.129.129.2", "10.129.129.1", "faketcp", true, 16.1, "业务数据由两端直接传输", "远端电脑"), "", [], "", "0.3.0");
        ShowPage("join"); if (!preview) Shown += async (_, _) => { ApplyTray(); await Poll(); timer.Start(); }; FormClosing += OnClosingWindow;
        AutoScaleMode = AutoScaleMode.Dpi; AutoScaleDimensions = new(96, 96); ResumeLayout(true);
    }
    static Icon MakeIcon()
    {
        using var bitmap = new Bitmap(32, 32); using var g = Graphics.FromImage(bitmap); g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias; g.Clear(Color.Transparent);
        using var pen = new Pen(Design.Accent, 5); g.DrawLine(pen, 9, 23, 23, 9); using var a = new SolidBrush(Color.FromArgb(71, 183, 224)); using var b = new SolidBrush(Design.Accent); g.FillEllipse(a, 1, 15, 16, 16); g.FillEllipse(b, 15, 1, 16, 16);
        IntPtr handle = bitmap.GetHicon(); try { return (Icon)Icon.FromHandle(handle).Clone(); } finally { DestroyIcon(handle); }
    }
    [System.Runtime.InteropServices.DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr handle);
    void Restore() { Show(); WindowState = FormWindowState.Normal; Activate(); }
    void ApplyTray() { tray.Visible = !preview && preferences.Tray; }
    RoundedButton ActionButton(string text, string pending, Func<Task<string>> action, bool primary = false)
    {
        var button = Design.Button(text, primary); actions.Add(button); button.Click += async (_, _) => await Run(pending, action); return button;
    }
    void SetBusy(bool value, string? message = null)
    {
        busy = value; progress.Visible = value; if (message != null) { notice.Text = message; notice.ForeColor = Design.Accent; }
        foreach (var control in actions.Concat(nav.Values)) if (!control.IsDisposed) control.Enabled = !value;
    }
    async Task Run(string pending, Func<Task<string>> action)
    {
        if (busy || preview) return; SetBusy(true, pending);
        await uiGate.WaitAsync();
        try { await Task.Yield(); notice.Text = await action(); notice.ForeColor = Color.FromArgb(40, 130, 98); }
        catch (Exception ex) { notice.Text = ex is OperationCanceledException ? "操作已取消" : ex.Message; notice.ForeColor = Color.FromArgb(182, 65, 78); }
        finally { uiGate.Release(); SetBusy(false); UpdateStatus(); }
    }
    async Task<ControlReply> Call(ControlRequest request) { var reply = await backend.Call(request, lifetime.Token); if (!reply.Ok) throw new IOException(reply.Error); return reply; }
    void Apply(ControlReply reply)
    {
        last = reply;
        // This is local IPC only. Faster startup feedback does not increase
        // requests to the public coordination service.
        timer.Interval = reply.Profile?.Enabled == true && reply.Status?.Connected != true ? 750 : 2500;
        UpdateStatus();
    }
    async Task Poll()
    {
        if (busy || polling || preview || lifetime.IsCancellationRequested || !await uiGate.WaitAsync(0)) return;
        polling = true;
        try { var reply = await Call(new("status")); if (busy) return; Apply(reply); if (room != null) await PollPair(); }
        catch (Exception ex) { if (!busy) { notice.Text = "暂未完成检查：" + ex.Message; notice.ForeColor = Design.Muted; } }
        finally { polling = false; uiGate.Release(); }
    }
    public void PreviewPage(string id) { if (!preview) throw new InvalidOperationException(); ShowPage(id); }
    void ShowPage(string id)
    {
        page = id; content.SuspendLayout(); foreach (Control c in content.Controls.Cast<Control>().ToArray()) c.Dispose(); content.Controls.Clear(); actions.Clear();
        networkState = addresses = localDevice = peerDevice = quality = pairText = pairHint = null; input = null; approve = reject = null; approvalRow = null;
        foreach (var item in nav) { item.Value.Selected = item.Key == id; item.Value.Invalidate(); }
        content.AutoScrollPosition = Point.Empty;
        var stack = Design.Stack(); stack.BackColor = Design.Surface; stack.Width = content.ClientSize.Width - content.Padding.Horizontal - 20; content.Controls.Add(stack);
        if (id == "settings") BuildSettings(stack); else BuildNetwork(stack, id == "create");
        if (IsHandleCreated && DeviceDpi != 96) stack.Scale(new SizeF(DeviceDpi / 96f, DeviceDpi / 96f));
        content.ResumeLayout(true); UpdateStatus();
    }
    TableLayoutPanel Card(TableLayoutPanel stack, string title)
    {
        var card = Design.Stack(); card.BackColor = Color.White; card.Padding = new(16); card.Margin = new(0, 0, 0, 14); card.Width = 720; card.MinimumSize = new(570, 0); card.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        if (title.Length > 0) card.Controls.Add(Design.Label(title, 12, true)); stack.Controls.Add(card); return card;
    }
    void UpdateStatus()
    {
        var s = last?.Status; var p = last?.Profile;
        if (networkState != null) { networkState.Text = s?.State ?? (p?.Pair != null ? "已配对，网络未启动" : "尚未配对"); networkState.ForeColor = s?.Connected == true ? Color.FromArgb(29, 139, 102) : Design.Ink; }
        if (addresses != null) addresses.Text = p?.Pair != null ? $"本机 10.129.129.{p.Slot}    ·    对端 10.129.129.{3-p.Slot}" + (s?.RttMs is { } rtt ? $"    ·    {rtt:F1} ms" : "") : "配对成功后显示双方虚拟 IP";
        if (localDevice != null) localDevice.Text = "●  " + (p?.DeviceName ?? Environment.MachineName) + "  ·  本机";
        if (peerDevice != null) peerDevice.Text = "●  " + (s?.PeerName is { Length: > 0 } name ? name : "另一台设备") + (s?.Connected == true ? "  ·  已直连" : "  ·  等待连接");
        if (quality != null) quality.Text = last?.Quality is { Length: > 0 } q ? q : s?.Detail ?? "业务数据仅在两台设备间传输。";
        modeLabel.Text = backend.IsService ? "服务模式 · 关闭界面后继续连接" : preferences.Tray && preferences.CloseToTray ? "前台模式 · 关闭窗口后驻留托盘，退出程序时断开" : "前台模式 · 退出程序时断开，可在设置中安装开机服务";
        if (room != null && pairText != null && pairHint != null && page != "settings") {
            if (owner && page == "create") pairText.Text = string.Join(" ", room.Code.ToCharArray());
            int seconds = (int)Math.Max(0, room.Expires - DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (exchange != null) {
                string check = PairKeyExchange.Verification(exchange);
                pairHint.Text = owner ? $"{roomState?.GuestName} 请求加入。请与对方核对校验码 {check}，一致后再允许。" : $"请让创建端核对校验码 {check}，一致后允许加入。";
                if (!owner) pairText.Text = "等待确认 · 校验码 " + check;
            } else pairHint.Text = owner ? $"配对码剩余 {seconds / 60}:{seconds % 60:D2}，等待另一台设备申请。" : "已提交申请，正在建立安全配对会话…";
        }
        if (approve != null) approve.Visible = owner && room != null && exchange != null && roomState?.Approved == false;
        if (reject != null) reject.Visible = owner && room != null && roomState?.Candidate.Length > 0;
        if (approvalRow != null) approvalRow.Visible = owner && room != null && roomState?.Candidate.Length > 0;
        if (pairText != null) pairText.Visible = pairText.Text.Length > 0;
        tray.Text = "StreamLink · " + (s?.Connected == true ? "已直连" : "等待连接");
    }
    void ShowLogs()
    {
        var window = new Form { Text = "StreamLink · 日志", Size = new(820, 500), StartPosition = FormStartPosition.CenterParent, Font = Design.Font() };
        window.Controls.Add(new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new("Consolas", 10), Text = string.Join(Environment.NewLine, last?.Logs ?? []), BackColor = Color.White, WordWrap = false }); window.Show(this);
    }
    static void OpenUrl(string url) => Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    async void OnClosingWindow(object? sender, FormClosingEventArgs e)
    {
        if (allowClose || preview) return;
        if (!exiting && preferences.Tray && preferences.CloseToTray && e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); tray.ShowBalloonTip(2000, "StreamLink 正在托盘运行", "双击图标恢复窗口；要断开请停止网络。", ToolTipIcon.Info); return; }
        e.Cancel = true; if (busy) { notice.Text = "正在执行操作，请完成后再退出"; return; }
        SetBusy(true, backend.IsService ? "正在关闭界面…" : "正在停止前台连接…"); timer.Stop(); lifetime.Cancel();
        try { while (polling) await Task.Delay(50); await ClearPair(true); await backend.DisposeAsync(); }
        finally { tray.Visible = false; allowClose = true; Close(); }
    }
    protected override void Dispose(bool disposing) { if (disposing) { timer.Dispose(); tray.Dispose(); lifetime.Dispose(); Icon?.Dispose(); } base.Dispose(disposing); }
}
