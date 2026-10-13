using StreamLink.Core;

namespace StreamLink;

public sealed partial class MainWindow
{
    TableLayoutPanel? memberList;
    ComboBox? qualityPeer;
    readonly Dictionary<int, (Label Name, Label State)> memberLabels = [];
    string memberLayout = "", pendingMeshInvitation = "";
    sealed record PeerChoice(int Slot, string Name) { public override string ToString() => Name; }
    void RequireMeshVersion()
    {
        if (!Version.TryParse(last?.Version, out var version) || version < new Version(0, 4, 0)) throw new IOException("请先在设置中更新后台服务至 0.4，再创建或加入多机网络");
    }
    void BuildMembers(TableLayoutPanel parent)
    {
        memberLabels.Clear(); memberLayout = "";
        memberList = Design.Stack(); memberList.Margin = new(0, 10, 0, 10); parent.Controls.Add(memberList);
        qualityPeer = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 360, AccessibleName = "选择测速设备", Visible = false, Margin = new(0, 6, 0, 4) }; parent.Controls.Add(qualityPeer);
    }
    void UpdateMembers()
    {
        if (memberList == null || memberList.IsDisposed || qualityPeer == null) return;
        var mesh = last?.Profile?.Mesh;
        memberList.Visible = mesh != null;
        if (peerDevice != null) peerDevice.Visible = mesh == null;
        if (mesh == null) { qualityPeer.Visible = false; return; }
        var peers = last?.Status?.Peers ?? mesh.Directory?.Members.Where(m => m.Slot != mesh.Self.Slot).Select(m => new MeshPeerStatus(m.Slot, MeshIdentity.Address(mesh.Pair.Network, m.Slot), $"设备 {m.Slot}", false, null, "尚未连接")).ToArray() ?? [];
        string layout = string.Join(',', peers.Select(p => p.Slot)) + "/" + mesh.IsOwner;
        if (layout != memberLayout) {
            memberList.SuspendLayout(); foreach (Control control in memberList.Controls.Cast<Control>().ToArray()) control.Dispose(); memberList.Controls.Clear(); memberLabels.Clear();
            foreach (var peer in peers) {
                var row = Design.Stack(); row.BackColor = Color.FromArgb(246, 247, 252); row.Padding = new(12); row.Margin = new(0, 0, 0, 8); row.MinimumSize = new(500, 0); row.Anchor = AnchorStyles.Left | AnchorStyles.Right;
                var title = Design.Label(peer.Name, 11, true); var state = Design.Label("", 9); row.Controls.Add(title); row.Controls.Add(state);
                var copy = Design.Button("复制 IP"); copy.Width = 94; copy.Height = 32; string ip = peer.Ip; copy.Click += (_, _) => { Clipboard.SetText(ip); notice.Text = "已复制 " + ip; };
                var buttons = Design.Row(copy);
                if (mesh.IsOwner) {
                    int slot = peer.Slot;
                    var remove = ActionButton("移除设备", "正在更新成员列表…", async () => {
                        if (MessageBox.Show(this, "移除后该设备需要重新配对。其他成员的连接会保留。", "移除设备", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK) return "已保留设备";
                        Apply(await Call(new("mesh-revoke", PeerSlot: slot))); return "成员已移除；其他在线设备收到目录更新后生效";
                    }); remove.Width = 110; remove.Height = 32; buttons.Controls.Add(remove);
                }
                row.Controls.Add(buttons);
                if(IsHandleCreated&&DeviceDpi!=96)row.Scale(new SizeF(DeviceDpi/96f,DeviceDpi/96f));
                memberList.Controls.Add(row);
                memberLabels[peer.Slot] = (title, state);
            }
            if (peers.Length == 0) memberList.Controls.Add(Design.Label(mesh.IsOwner ? "还没有其他成员。生成配对码，邀请第一台设备。" : "正在同步网络成员…", 10));
            actions.RemoveAll(control => control.IsDisposed);
            memberLayout = layout; memberList.ResumeLayout(true);
        }
        foreach (var peer in peers) if (memberLabels.TryGetValue(peer.Slot, out var labels)) {
            string name=peer.Name+"  ·  "+peer.Ip;
            string state=(peer.Connected ? peer.Degraded ? "● UDP 降级直连" : "● 已直连" : "○ " + peer.Detail)+(peer.Connected&&peer.RttMs is{} rtt?$"   {rtt:F1} ms":"");
            if(labels.Name.Text!=name)labels.Name.Text=name;if(labels.State.Text!=state)labels.State.Text=state;
            labels.State.ForeColor = peer.Degraded ? Color.FromArgb(153, 102, 0) : peer.Connected ? Color.FromArgb(29, 139, 102) : Design.Muted;
        }
        var choices = peers.Where(p => p.Connected).Select(p => new PeerChoice(p.Slot, p.Name + " · " + p.Ip)).ToArray();
        if (!qualityPeer.Items.Cast<PeerChoice>().SequenceEqual(choices)) {
            int selected = (qualityPeer.SelectedItem as PeerChoice)?.Slot ?? 0;
            qualityPeer.Items.Clear(); qualityPeer.Items.AddRange(choices);
            if (choices.Length > 0) qualityPeer.SelectedIndex = Math.Max(0, Array.FindIndex(choices, p => p.Slot == selected));
        }
        qualityPeer.Visible = choices.Length > 0;
    }
}
