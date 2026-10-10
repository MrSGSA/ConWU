using StreamLink.Core;
using System.Text.Json;

namespace StreamLink;
public sealed class SettingsWindow : Form
{
    readonly DeviceProfile profile;
    readonly ComboBox preference = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 240 };
    readonly TextBox tcp = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly TextBox udp = new() { Multiline = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    readonly TextBox manual = new() { Dock = DockStyle.Fill, PlaceholderText = "留空自动探测；也可填写 Lucky 公网 IPv4:端口" };
    readonly NumericUpDown source = new() { Minimum = 1024, Maximum = 65535, Width = 110 };
    readonly NumericUpDown listen = new() { Minimum = 1024, Maximum = 65535, Width = 110 };
    public DeviceProfile Result => profile;
    public SettingsWindow(DeviceProfile current)
    {
        profile = JsonSerializer.Deserialize<DeviceProfile>(JsonSerializer.Serialize(current))!;
        Text = "连接偏好与 STUN"; Size = new(740, 620); StartPosition = FormStartPosition.CenterParent; Font = new("Microsoft YaHei UI", 9); AutoScaleMode = AutoScaleMode.Dpi;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new(18), ColumnCount = 1, RowCount = 10 }; Controls.Add(layout);
        preference.Items.AddRange(["自动选择可用入口", "优先本机提供入口", "优先对端提供入口"]); preference.SelectedIndex = profile.Preference == "local" ? 1 : profile.Preference == "peer" ? 2 : 0;
        layout.Controls.Add(preference); layout.Controls.Add(new Label { AutoSize = true, Text = "偏好决定谁提供入口，与应用流量方向无关；直连成功后记忆。" });
        var ports = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill }; source.Value = profile.SourcePort; listen.Value = profile.ListenPort;
        ports.Controls.AddRange([new Label { Text = "探测源端口", AutoSize = true }, source, new Label { Text = "本机传输端口", AutoSize = true }, listen]); layout.Controls.Add(ports);
        manual.Text = profile.ManualEndpoint; layout.Controls.Add(manual);
        layout.Controls.Add(new Label { AutoSize = true, Text = "TCP STUN（每行 主机名:端口；最近成功的服务优先尝试）" }); tcp.Lines = profile.TcpStun; layout.Controls.Add(tcp);
        layout.Controls.Add(new Label { AutoSize = true, Text = "UDP STUN（实验配置保留；当前默认传输为 FakeTCP）" }); udp.Lines = profile.UdpStun; layout.Controls.Add(udp);
        layout.Controls.Add(new Label { AutoSize = true, Text = "导入导出仅含 STUN 列表，不含配对密钥。保存后后台重新连接。" });
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
        var import = new Button { Text = "导入列表", AutoSize = true }; var export = new Button { Text = "导出列表", AutoSize = true }; var save = new Button { Text = "保存", AutoSize = true }; var community = new Button { Text = "补充社区 TCP 列表", AutoSize = true }; actions.Controls.AddRange([import, export, community, save]); layout.Controls.Add(actions);
        community.Click += async (_, _) => { community.Enabled = false; community.Text = "正在获取…"; try { var downloaded = await StunCatalog.Download(CancellationToken.None); var merged = tcp.Lines.Select(x => x.Trim()).Where(x => x.Length > 0).Concat(downloaded).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(); DeviceProfile.ValidateServers(merged); tcp.Lines = merged; MessageBox.Show(this, $"已补充列表，共 {merged.Length} 项。来源：pradt2/always-online-stun。可达性以本机实际探测为准。点击保存后生效。"); } catch (Exception ex) { MessageBox.Show(this, ex.Message); } finally { community.Enabled = true; community.Text = "补充社区 TCP 列表"; } };
        string[] Lines(TextBox box) => box.Lines.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        void Lists() { DeviceProfile.ValidateServers(Lines(tcp)); DeviceProfile.ValidateServers(Lines(udp)); }
        import.Click += (_, _) => { using var dialog = new OpenFileDialog { Filter = "STUN 列表|*.json" }; if (dialog.ShowDialog(this) != DialogResult.OK) return; try { var data = JsonSerializer.Deserialize<StunLists>(File.ReadAllText(dialog.FileName))!; DeviceProfile.ValidateServers(data.Tcp); DeviceProfile.ValidateServers(data.Udp); tcp.Lines = data.Tcp; udp.Lines = data.Udp; } catch (Exception ex) { MessageBox.Show(this, ex.Message); } };
        export.Click += (_, _) => { try { Lists(); using var dialog = new SaveFileDialog { Filter = "STUN 列表|*.json", FileName = "streamlink-stun.json" }; if (dialog.ShowDialog(this) == DialogResult.OK) File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(new StunLists(Lines(tcp), Lines(udp)), new JsonSerializerOptions { WriteIndented = true })); } catch (Exception ex) { MessageBox.Show(this, ex.Message); } };
        save.Click += (_, _) => { try { Lists(); profile.Preference = preference.SelectedIndex == 1 ? "local" : preference.SelectedIndex == 2 ? "peer" : "auto"; profile.TcpStun = Lines(tcp); profile.UdpStun = Lines(udp); profile.SourcePort = (int)source.Value; profile.ListenPort = (int)listen.Value; profile.ManualEndpoint = manual.Text.Trim(); profile.Validate(); DialogResult = DialogResult.OK; Close(); } catch (Exception ex) { MessageBox.Show(this, ex.Message); } };
        for (int i = 0; i < 10; i++) layout.RowStyles.Add(new RowStyle(i == 5 || i == 7 ? SizeType.Percent : SizeType.AutoSize, i == 5 || i == 7 ? 50 : 0));
    }
    sealed record StunLists(string[] Tcp, string[] Udp);
}
