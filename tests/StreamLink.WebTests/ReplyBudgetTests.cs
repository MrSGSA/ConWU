using System.Reflection;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

static class ReplyBudgetTests
{
    public static void Run(Action<bool, string> check)
    {
        var fit = typeof(ControlWorker).GetMethod("FitUiReply", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate<Func<UiControlReply, UiControlReply>>();
        var operation = new ControlOperationStatus(Guid.NewGuid(), "start", "准备网络", false, true);
        var peers = Enumerable.Range(2, 7).Select(slot => new UiPeerDto(slot, "设备 " + slot, "10.20.30." + slot,
            slot == 2, false, slot == 2 ? 8 : null, "正在连接") {
            Connection = new("Connecting", "等待验证", CanRetry: true), Liveness = new("WaitingForPath", null, null)
        }).ToArray();
        var status = new UiStatusDto("candidate", "本机", "10.20.30.1", "正在连接", true, true, 1, 7, peers, "info") {
            Operation = operation, Settings = new("https://example.com/"), SettingsRevision = "exact-revision"
        };
        var normal = new UiControlReply(true, "", status);
        check(JsonSerializer.Serialize(fit(normal)) == JsonSerializer.Serialize(normal), "normal status is not reduced");

        var logStatus = status with { Logs = Enumerable.Repeat(new string('长', 12000), 8).Append("newest-event").ToArray() };
        var logReply = new UiControlReply(true, "", logStatus, Operation: operation);
        string original = JsonSerializer.Serialize(logReply);
        var reduced = fit(logReply);
        check(JsonSerializer.SerializeToUtf8Bytes(reduced).Length <= ServiceProtocol.MaximumMessageBytes &&
            reduced.Status?.Logs.LastOrDefault() == "newest-event" && reduced.Status.DiagnosticsNotice.Length > 0,
            "oversized logs retain newest evidence and disclose omission within wire limit");
        check(reduced.Ok && reduced.Operation == operation && reduced.Status?.Peers.SequenceEqual(peers) == true &&
            reduced.Status.Settings == status.Settings && reduced.Status.SettingsRevision == status.SettingsRevision,
            "log reduction preserves all members, settings and actual operation result");
        check(JsonSerializer.Serialize(logReply) == original, "response reduction does not mutate original records");

        var worker = new UiLegacyStage(Guid.NewGuid(), 1, "faketcp", "local", new string('详', 16000), null, null, []);
        var stages = fit(normal with { Status = status with { Stages = new(null, null, [worker]) } });
        check(stages.Status?.Stages?.ExplicitWorkers.Length == 0 && stages.Status.DiagnosticsNotice.Contains("出口分项") &&
            stages.Status.Peers.Length == 7 && JsonSerializer.SerializeToUtf8Bytes(stages).Length <= ServiceProtocol.MaximumMessageBytes,
            "large stage details cannot remove members or overflow UI reply");

        var largeSettings = status with { Settings = status.Settings! with { Service = "https://example.com/" + new string('测', 16000) + "/" } };
        var unavailable = fit(normal with { Status = largeSettings });
        check(unavailable.Status == null && unavailable.Ok && unavailable.Operation == operation && unavailable.StatusNotice.Length > 0 &&
            JsonSerializer.SerializeToUtf8Bytes(unavailable).Length <= ServiceProtocol.MaximumMessageBytes,
            "status polling preserves current operation when essential exact settings cannot fit");
        var commandOperation = new ControlOperationStatus(Guid.NewGuid(), "stop", "未完成", true, false, "resource still held");
        var failed = fit(new(false, "resource still held", largeSettings, Operation: commandOperation));
        check(!failed.Ok && failed.Error == "resource still held" && failed.Operation == commandOperation && failed.Status == null,
            "explicit command outcome is not replaced by another operation in the status snapshot");

        string emoji = new string('a', 1022) + "😃" + new string('b', 20);
        var clipped = fit(new(false, emoji, null, Operation: commandOperation with { Error = emoji }));
        check(clipped.Error.Length <= 1024 && !clipped.Error.Any(char.IsSurrogate) && clipped.Operation!.Error == clipped.Error &&
            clipped.Error.EndsWith('…'), "display clipping does not split a UTF-16 surrogate pair");
    }
}
