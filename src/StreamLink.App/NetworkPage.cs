using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink;

public sealed partial class MainWindow
{
    void BuildNetwork(TableLayoutPanel stack, bool create)
    {
        stack.Controls.Add(Design.Label(create ? "创建你的网络" : "加入一个网络", 22, true));
        stack.Controls.Add(Design.Label(create ? "一次创建，逐台邀请。最多 8 台设备，各自建立直连。" : "输入创建者显示的 6 位配对码，加入同一个网络。", 10));
        var pairCard = Card(stack, create ? "配对邀请" : "输入配对码");
        if (create) {
            pairText = Design.Label("— — — — — —", 28, true); pairCard.Controls.Add(pairText);
            pairHint = Design.Label("创建后显示配对码，有效期 5 分钟。", 9); pairHint.MaximumSize = new(620, 0); pairCard.Controls.Add(pairHint);
            var createButton = ActionButton("创建网络", "正在创建网络和配对码…", CreateNetwork, true);
            var refresh = ActionButton("邀请下一台设备", "正在生成新的配对码…", async () => { if (last?.Profile?.Mesh?.IsOwner != true) throw new IOException("请先创建新版多机网络"); await OpenRoom(); return "新配对码已生成，现有成员继续连接"; }); refresh.Width = 166;
            var copy = ActionButton("复制配对码", "正在复制…", () => { if (room == null || !owner) throw new IOException("请先生成配对码"); Clipboard.SetText(room.Code); return Task.FromResult("6 位配对码已复制"); });
            pairCard.Controls.Add(Design.Row(createButton, refresh, copy));
            approve = ActionButton("校验码一致，允许加入", "正在批准设备并加密配对…", Approve, true); approve.Width = 230; approve.Visible = false;
            reject = ActionButton("拒绝并换码", "正在撤销申请…", async () => { await OpenRoom(); return "已拒绝申请并生成新配对码"; }); reject.Visible = false;
            approvalRow = Design.Row(approve, reject); approvalRow.Visible = false; pairCard.Controls.Add(approvalRow);
        } else {
            input = new TextBox { Font = Design.Font(24, FontStyle.Bold), MaxLength = 6, Width = 255, PlaceholderText = "6 位配对码", BorderStyle = BorderStyle.FixedSingle, Margin = new(0, 0, 14, 0), AccessibleName = "6 位配对码" };
            input.KeyPress += (_, e) => { if (!char.IsControl(e.KeyChar) && (e.KeyChar < '0' || e.KeyChar > '9')) e.Handled = true; };
            var join = ActionButton("加入网络", "正在提交加入申请…", JoinNetwork, true); join.Height = 52; pairCard.Controls.Add(Design.Row(input, join));
            pairText = Design.Label("", 15, true); pairHint = Design.Label("双方需选择同一个协调服务器。", 9); pairHint.MaximumSize = new(620, 0); pairCard.Controls.Add(pairText); pairCard.Controls.Add(pairHint);
        }
        var network = Card(stack, "当前网络");
        networkState = Design.Label("尚未连接", 18, true); network.Controls.Add(networkState); addresses = Design.Label("配对成功后显示成员虚拟 IP", 10); network.Controls.Add(addresses);
        localDevice = Design.Label("本机设备", 10); peerDevice = Design.Label("等待另一台设备", 10); network.Controls.Add(localDevice); network.Controls.Add(peerDevice);
        BuildMembers(network);
        quality = Design.Label("", 9); quality.MaximumSize = new(620, 0); network.Controls.Add(quality);
        network.Controls.Add(Design.Row(ActionButton("启动网络", "正在启动网络…", async () => { Apply(await Call(new("start"))); return "已开始连接，状态将在下方更新"; }), ActionButton("停止网络", "正在停止网络并清理映射…", async () => { Apply(await Call(new("stop"))); return "网络已停止，成员与地址已保留"; }), ActionButton("测试连接质量", "正在准备 20 秒质量测试…", async () => { Apply(await Call(new("quality", PeerSlot: (qualityPeer?.SelectedItem as PeerChoice)?.Slot ?? 0))); return "质量测试已启动，20 秒后显示结果"; })));
        stack.Controls.Add(Design.Label("创建与加入决定配对身份；公网入口由软件自动选择。", 9));
    }
    void RequireServer()
    {
        if (preferences.Server.Length == 0) throw new IOException("请先在“设置 → 协调服务器”填写服务器地址"); Pairing.Create(preferences.Server, preferences.Pin).Validate();
    }
    bool ConfirmReplace() => last?.Profile?.Pair == null && last?.Profile?.Mesh == null || MessageBox.Show(this, "这会替换当前网络并中断现有连接。若要添加设备，请使用“邀请下一台设备”。继续？", "替换当前网络", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK;
    async Task<string> CreateNetwork()
    {
        RequireServer(); if (!ConfirmReplace()) return "已保留当前配对"; string mode = last?.Profile?.TransportMode ?? "faketcp";
        RequireMeshVersion();
        using (var check = new ShortPairClient(preferences.Server, preferences.Pin)) await check.RequireMeshSupport(OperationToken);
        await ClearPair(true); Apply(await Call(new("mesh-create", Service: preferences.Server, Pin: preferences.Pin, Mode: mode)));
        await OpenRoom(); Apply(await Call(new("start"))); return "网络已创建，请将 6 位配对码交给另一台电脑";
    }
    async Task OpenRoom()
    {
        await ClearPair(true); RequireServer();
        var current = last?.Profile?.Mesh?.Pair ?? last?.Profile?.Pair;
        if (current?.Service != preferences.Server || current.CertificatePin != preferences.Pin) throw new IOException("当前网络属于另一个协调服务器，请切回原服务器或创建新网络");
        owner = true; pairKey = new(); pairClient = new(preferences.Server, preferences.Pin); room = await pairClient.Create(pairKey, last!.Profile!.DeviceName, OperationToken); UpdateStatus();
    }
    async Task<string> JoinNetwork()
    {
        RequireServer(); string code = input?.Text.Trim() ?? ""; if (code.Length != 6) throw new FormatException("请输入完整的 6 位数字配对码");
        RequireMeshVersion();
        using (var check = new ShortPairClient(preferences.Server, preferences.Pin)) await check.RequireMeshSupport(OperationToken);
        if (!ConfirmReplace()) return "已保留当前配对";
        await ClearPair(true); owner = false; pairKey = new(); pairClient = new(preferences.Server, preferences.Pin);
        room = await pairClient.Join(code, pairKey, last?.Profile?.DeviceName ?? Environment.MachineName, OperationToken); input!.Clear(); UpdateStatus(); return "加入申请已发送，等待创建端核对并允许";
    }
    async Task PollPair()
    {
        if (room!.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) { await ClearPair(false); notice.Text = "配对码已过期，请创建端重新生成"; if (pairHint != null) pairHint.Text = notice.Text; if (pairText != null) pairText.Text = "已过期"; UpdateStatus(); return; }
        var received = await pairClient!.Poll(room, owner, lifetime.Token); if (busy) return;
        PairKeyExchange.ValidateState(room, roomState, received, pairKey!, owner);
        roomState = received;
        if (!revealed && (owner ? roomState.Candidate.Length > 0 : roomState.HostPublic.Length > 0)) {
            if (!owner) PairKeyExchange.ValidatePublic(roomState.HostPublic, room.HostCommitment);
            received = await pairClient.Reveal(room, owner, pairKey!, lifetime.Token);
            PairKeyExchange.ValidateState(room, roomState, received, pairKey!, owner);
            roomState = received; revealed = true;
        }
        if (exchange == null && roomState.HostPublic.Length > 0 && roomState.GuestPublic.Length > 0) {
            exchange = pairKey!.Derive(owner ? roomState.GuestPublic : roomState.HostPublic, owner ? roomState.GuestCommitment : room.HostCommitment, room.Room, roomState.Candidate, owner);
            if (owner && tray.Visible && !Visible) tray.ShowBalloonTip(5000, "设备请求加入", "打开 StreamLink，核对校验码并允许加入。", ToolTipIcon.Info);
        }
        if (owner && roomState.Approved && exchange != null && pendingMeshInvitation.Length > 0) {
            // Approval may succeed even if its HTTP reply was lost. Confirm the
            // exact granted credential before completing the local UI action.
            if (PairKeyExchange.DecryptInvitation(exchange, roomState.Ciphertext, room.Room, roomState.Candidate) != pendingMeshInvitation)
                throw new CryptographicException("已批准邀请与本次设备凭据不符");
            await ClearPair(false);
            if (pairText != null) pairText.Text = "已允许加入";
            if (pairHint != null) pairHint.Text = "配对码已失效，正在等待设备连接。";
            notice.Text = "已确认设备获准加入，原批准请求已成功"; UpdateStatus(); return;
        }
        if (!owner && roomState.Approved && exchange != null && !busy) {
            SetBusy(true, "正在保存配对并启动网络…");
            try {
                string invitation = PairKeyExchange.DecryptInvitation(exchange, roomState.Ciphertext, room.Room, roomState.Candidate);
                if (invitation.StartsWith("SL4.")) {
                    RequireMeshVersion(); var mesh = MeshIdentity.Import(invitation);
                    if (new Uri(mesh.Pair.Service) != new Uri(preferences.Server) || !mesh.Pair.CertificatePin.Equals(preferences.Pin, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("邀请中的协调服务器不符");
                    Apply(await Call(new("mesh-join", Invite: invitation)));
                } else {
                    var pair = PairKeyExchange.Decrypt(exchange, roomState.Ciphertext, room.Room, roomState.Candidate, preferences.Server, preferences.Pin);
                    Apply(await Call(new("join", Invite: pair.Invite())));
                }
                Apply(await Call(new("start"))); await ClearPair(false);
                if (pairText != null) pairText.Text = "配对成功"; if (pairHint != null) pairHint.Text = "配对已保存，下次直接启动网络。"; notice.Text = "配对成功，正在建立直连";
            } finally { SetBusy(false); }
        }
        UpdateStatus();
    }
    async Task<string> Approve()
    {
        if (exchange == null || roomState == null || room == null || last?.Profile?.Mesh?.IsOwner != true) throw new IOException("没有待批准的多机网络申请");
        if (pendingMeshInvitation.Length == 0) { var issued = await Call(new("mesh-invite")); pendingMeshInvitation = issued.Invite; Apply(issued); }
        await pairClient!.Approve(room, roomState.Candidate, PairKeyExchange.EncryptInvitation(exchange, pendingMeshInvitation, room.Room, roomState.Candidate), OperationToken);
        pendingMeshInvitation = "";
        await ClearPair(false); if (pairText != null) pairText.Text = "已允许加入"; if (pairHint != null) pairHint.Text = "配对码已失效，正在等待设备连接。"; return "已批准设备，配对信息已加密发送";
    }
    async Task ClearPair(bool revoke)
    {
        // A timed-out approval may already have delivered its credential. Keep
        // the reserved member on cancellation; the owner can explicitly remove
        // it from the member list instead of silently revoking a joined device.
        pendingMeshInvitation = "";
        if (revoke && owner && room != null && pairClient != null) { try { using var timeout = new CancellationTokenSource(3000); await pairClient.Close(room, timeout.Token); } catch { } }
        room = null; roomState = null; revealed = false; pairKey?.Dispose(); pairKey = null; pairClient?.Dispose(); pairClient = null; if (exchange != null) CryptographicOperations.ZeroMemory(exchange); exchange = null;
    }
}
