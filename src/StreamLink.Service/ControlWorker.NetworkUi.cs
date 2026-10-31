using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    PairRoomTicket? uiRoom;
    PairRoomState? uiRoomState;
    PairKeyExchange? uiPairKey;
    ShortPairClient? uiPairClient;
    byte[]? uiExchange;
    bool uiPairOwner, uiRevealed;
    string uiPairService = "", uiPairPin = "", uiPendingInvite = "", uiExpectedNetwork = "";
    UiPairingDto? uiPairSnapshot;

    static UiNetworkSettings PublicSettings(DeviceProfile p) => new(p.Mesh?.Pair.Service ?? "", p.Mesh?.Pair.CertificatePin ?? "", p.ManualEndpoint, p.PathSelection, p.AllowManualQualityRequests, p.ListenPort, p.SourcePort);
    static string SettingsRevision(DeviceProfile p) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(PublicSettings(p))));
    void RequireUiNetwork(string expected)
    {
        if ((profile.Mesh?.Pair.Network ?? "") != expected) throw new IOException("网络已改变，请刷新后重新确认操作");
    }
    void PairSnapshot(string state)
    {
        Volatile.Write(ref uiPairSnapshot, new(uiRoom != null, uiPairOwner, uiPairOwner ? uiRoom?.Code ?? "" : "",
            uiExchange == null ? "" : PairKeyExchange.Verification(uiExchange), uiRoomState?.Candidate ?? "",
            uiPairOwner ? uiRoomState?.GuestName ?? "" : uiRoom?.HostName ?? "", uiRoom?.Expires ?? 0, state));
    }
    void ResetUiPair(string state)
    {
        uiRoom = null; uiRoomState = null; uiRevealed = false; uiPendingInvite = "";
        uiPairKey?.Dispose(); uiPairKey = null; uiPairClient?.Dispose(); uiPairClient = null;
        if (uiExchange != null) CryptographicOperations.ZeroMemory(uiExchange);
        uiExchange = null; PairSnapshot(state);
    }
    async Task CloseUiPair(CancellationToken token)
    {
        // Keep an already issued member if an approval reply was lost. Revoking
        // that credential is a separate, explicit owner action.
        if (uiPairOwner && uiRoom != null && uiPairClient != null)
            try { await uiPairClient.Close(uiRoom, token); } catch (IOException) { }
        ResetUiPair("已取消配对");
    }
    async Task OpenUiRoom(string service, string pin, CancellationToken token)
    {
        await CloseUiPair(token);
        uiPairOwner = true; uiPairService = service; uiPairPin = pin;
        uiExpectedNetwork = profile.Mesh!.Pair.Network;
        uiPairKey = new(); uiPairClient = new(service, pin);
        try { uiRoom = await uiPairClient.Create(uiPairKey, profile.DeviceName, token); PairSnapshot("等待另一台设备输入配对码"); }
        catch { ResetUiPair("创建配对码未完成，请重试邀请"); throw; }
    }
    async Task ApplyUiNetwork(UiNetworkAction action, Operation operation)
    {
        var token = operation.Stop.Token;
        if (action.Service is null || action.Service.Length > 2048 || action.CertificatePin is null || action.CertificatePin.Length > 128 || action.Code is null || action.Code.Length > 6 || action.Verification is null || action.Verification.Length > 6 || action.Candidate is null || action.Candidate.Length > 32)
            throw new FormatException("网络操作参数无效");
        switch (action.Action)
        {
            case "create":
            case "join":
                RequireUiNetwork(action.ExpectedNetwork);
                if ((profile.Mesh != null || profile.Pair != null) && !action.ConfirmReplace) throw new IOException("替换网络需要明确确认");
                if (action.Mode is not ("faketcp" or "udp")) throw new FormatException("网络承载无效");
                using (var check = new ShortPairClient(action.Service, action.CertificatePin)) await check.RequireMeshSupport(token);
                if (action.Action == "create") {
                    var mesh = MeshIdentity.Create(action.Service, action.CertificatePin, action.Mode);
                    var next = ProfileChanges.Copy(profile);
                    next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;
                    next.SelectTransport(action.Mode == "udp" ? "udp-only" : "faketcp-only");
                    next = PersonalFeature.EnhancedPreset(next);
                    next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
                    SetOperation(operation, "保存新网络", false); await End(token);
                    lock (sync) { store.BackupLegacy(profile); store.Save(next); profile = next; }
                    await OpenUiRoom(action.Service, action.CertificatePin, token);
                    lock (sync) { profile.Enabled = true; store.Save(profile); } Begin();
                } else {
                    await CloseUiPair(token);
                    uiPairOwner = false; uiPairService = action.Service; uiPairPin = action.CertificatePin;
                    uiExpectedNetwork = action.ExpectedNetwork; uiPairKey = new(); uiPairClient = new(action.Service, action.CertificatePin);
                    try { uiRoom = await uiPairClient.Join(action.Code, uiPairKey, profile.DeviceName, token); PairSnapshot("等待双方核对校验码"); }
                    catch { ResetUiPair("加入申请未完成"); throw; }
                }
                break;
            case "invite":
                RequireUiNetwork(action.ExpectedNetwork);
                var network = profile.Mesh ?? throw new IOException("请先创建网络");
                if (!network.IsOwner) throw new IOException("只有创建者可以邀请成员");
                await OpenUiRoom(network.Pair.Service, network.Pair.CertificatePin, token); break;
            case "pair-poll":
                await PollUiPair(operation); break;
            case "approve":
                RequireUiNetwork(uiExpectedNetwork);
                if (!uiPairOwner || uiRoom == null || uiRoomState == null || uiExchange == null || profile.Mesh?.IsOwner != true ||
                    action.Candidate != uiRoomState.Candidate || action.Verification != PairKeyExchange.Verification(uiExchange))
                    throw new IOException("配对申请或校验码已改变，请重新核对");
                if (uiPendingInvite.Length == 0) lock (sync) {
                    uiPendingInvite = MeshIdentity.Export(MeshIdentity.Issue(profile.Mesh));
                    store.Save(profile); meshRunner?.UpdateDirectory(profile.Mesh.Directory!);
                }
                await uiPairClient!.Approve(uiRoom, uiRoomState.Candidate, PairKeyExchange.EncryptInvitation(uiExchange, uiPendingInvite, uiRoom.Room, uiRoomState.Candidate), token);
                ResetUiPair("已批准设备加入"); break;
            case "pair-cancel":
                await CloseUiPair(token); break;
            case "revoke":
                RequireUiNetwork(action.ExpectedNetwork);
                lock (sync) {
                    var current = profile.Mesh ?? throw new IOException("尚未加入网络");
                    MeshIdentity.Revoke(current, action.PeerSlot); store.Save(profile); meshRunner?.UpdateDirectory(current.Directory!);
                }
                break;
            case "settings":
                var settings = action.Settings ?? throw new FormatException("设置为空");
                var updated = ProfileChanges.Copy(profile);
                if (action.ExpectedRevision != SettingsRevision(updated)) throw new IOException("连接设置已改变；草稿已保留，请刷新后核对");
                if (settings.Service != PublicSettings(updated).Service || settings.CertificatePin != PublicSettings(updated).CertificatePin) throw new IOException("当前网络的协调身份不能通过设置替换；请创建或加入新网络");
                updated.ManualEndpoint = settings.ManualEndpoint; updated.SelectTransport(settings.PathSelection);
                updated.AllowManualQualityRequests = settings.AllowManualQualityRequests;
                updated.ListenPort = settings.ListenPort; updated.SourcePort = settings.SourcePort;
                updated.Validate();
                bool restart = ProfileChanges.Impact(profile, updated) == ProfileChangeImpact.RestartNetwork;
                bool resume = profile.Enabled;
                if (restart && resume && !action.ConfirmReplace) throw new IOException("端口或承载设置需要重建连接，请确认后保存");
                if (restart) { SetOperation(operation, "重建受影响资源", false); await End(token); }
                try { lock (sync) { store.Save(updated); profile = updated; if (!restart && runningProfile is {} active) active.AllowManualQualityRequests = updated.AllowManualQualityRequests; } }
                catch { if (restart && resume) Begin(); throw; }
                if (restart && resume) Begin();
                break;
            default: throw new FormatException("不支持的网络操作");
        }
    }

    async Task PollUiPair(Operation operation)
    {
        if (uiRoom == null) return;
        var token = operation.Stop.Token;
        if (uiRoom.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) { ResetUiPair("配对码已过期，请重新邀请"); return; }
        RequireUiNetwork(uiExpectedNetwork);
        var received = await uiPairClient!.Poll(uiRoom, uiPairOwner, token);
        PairKeyExchange.ValidateState(uiRoom, uiRoomState, received, uiPairKey!, uiPairOwner); uiRoomState = received;
        if (!uiRevealed && (uiPairOwner ? received.Candidate.Length > 0 : received.HostPublic.Length > 0)) {
            received = await uiPairClient.Reveal(uiRoom, uiPairOwner, uiPairKey!, token);
            PairKeyExchange.ValidateState(uiRoom, uiRoomState, received, uiPairKey!, uiPairOwner);
            uiRoomState = received; uiRevealed = true;
        }
        if (uiExchange == null && received.HostPublic.Length > 0 && received.GuestPublic.Length > 0)
            uiExchange = uiPairKey!.Derive(uiPairOwner ? received.GuestPublic : received.HostPublic, uiPairOwner ? received.GuestCommitment : uiRoom.HostCommitment, uiRoom.Room, received.Candidate, uiPairOwner);
        PairSnapshot(uiExchange == null ? "等待对端交换公钥" : "请双方核对校验码；一致后由创建者批准");
        if (!received.Approved || uiExchange == null) return;
        string invitation = PairKeyExchange.DecryptInvitation(uiExchange, received.Ciphertext, uiRoom.Room, received.Candidate);
        if (uiPairOwner) {
            if (uiPendingInvite.Length == 0 || invitation != uiPendingInvite) throw new CryptographicException("批准凭据与当前申请不符");
            ResetUiPair("已确认设备获准加入"); return;
        }
        var mesh = MeshIdentity.Import(invitation);
        if (new Uri(mesh.Pair.Service) != new Uri(uiPairService) || !mesh.Pair.CertificatePin.Equals(uiPairPin, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("邀请的协调身份不符");
        var next = ProfileChanges.Copy(profile); next.Mesh = mesh; next.Pair = null; next.Enabled = false; next.Slot = 1; next.LastEntry = 0;
        next.SelectTransport(mesh.Pair.Mode == "udp" ? "udp-only" : "faketcp-only");
        next = PersonalFeature.EnhancedPreset(next);
        next.Validate(); await PersonalPacketAdapters.Preflight(next, token);
        SetOperation(operation, "保存配对并启动网络", false); await End(token);
        lock (sync) { store.BackupLegacy(profile); store.Save(next); profile = next; profile.Enabled = true; store.Save(profile); }
        Begin(); ResetUiPair("配对成功，正在建立直连");
    }
}
