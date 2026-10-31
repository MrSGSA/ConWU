using System.Text.Json;
using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    // Display text only. Never truncate settings, identities, revisions or
    // pairing tokens that a later command must return exactly.
    static string ShortText(string text, int limit)
    {
        if (text.Length <= limit) return text;
        int end = limit - 1;
        if (end > 0 && char.IsHighSurrogate(text[end - 1])) end--;
        return text[..end] + "…";
    }
    static string PublicText(string text, DeviceProfile profile, int limit) => ShortText(SensitiveText.Redact(text, profile), limit);
    static ControlOperationStatus? PublicOperation(ControlOperationStatus? operation, DeviceProfile profile) => operation == null ? null :
        operation with { Error = PublicText(operation.Error, profile, 1024) };

    // Run outside the service's state lock, using the same serializer as the
    // pipe. Only immutable presentation copies are reduced; the operation
    // result and the runner's evidence used for selection remain unchanged.
    internal static UiControlReply FitUiReply(UiControlReply source)
    {
        static bool Fits(UiControlReply value) => JsonSerializer.SerializeToUtf8Bytes(value).Length <= ServiceProtocol.MaximumMessageBytes;
        static ControlOperationStatus? ShortOperation(ControlOperationStatus? op) => op == null ? null : op with {
            Command = ShortText(op.Command, 64), Phase = ShortText(op.Phase, 128), Error = ShortText(op.Error, 1024)
        };
        var reply = source with { Error = ShortText(source.Error, 1024), Operation = ShortOperation(source.Operation) };
        if (reply.Status is not {} status) return reply;
        status = status with { Operation = ShortOperation(status.Operation) };
        reply = reply with { Status = status };
        if (Fits(reply)) return reply;

        int originalLogs = status.Logs.Length;
        var omissions = new List<string>();
        void Update()
        {
            string logs = originalLogs > status.Logs.Length ? $"本次状态省略了 {originalLogs - status.Logs.Length} 条较早或过长日志。" : "";
            status = status with { DiagnosticsNotice = logs + string.Join("", omissions) };
            reply = reply with { Status = status };
        }
        // Prefer recent lines. Halving bounds serialization work even when a
        // single exception line is larger than the entire allowed message.
        while (status.Logs.Length > 0) {
            status = status with { Logs = status.Logs.TakeLast(status.Logs.Length / 2).ToArray() };
            Update(); if (Fits(reply)) return reply;
        }
        if (status.Stages is {} stages) {
            if (stages.ExplicitWorkers.Length > 0 || stages.Egress is {} e && (e.Peers.Length > 0 || e.Outlets.Length > 0)) {
                status = status with { Stages = stages with {
                    ExplicitWorkers = [], Egress = stages.Egress is {} egress ? egress with { Peers = [], Outlets = [] } : null
                } };
                omissions.Add("出口分项诊断已省略。");
                Update(); if (Fits(reply)) return reply;
            }
            status = status with { Stages = null };
            omissions.Add("本次状态未包含传输阶段统计。");
            Update(); if (Fits(reply)) return reply;
        }
        if (status.LastQuality != null) {
            status = status with { LastQuality = null };
            omissions.Add("本次状态未包含上次测速明细。");
            Update(); if (Fits(reply)) return reply;
        }
        if (status.Peers.Any(p => p.LocalDrops != null || p.Liveness?.Keepalive != null)) {
            status = status with { Peers = status.Peers.Select(p => p with {
                LocalDrops = null, Liveness = p.Liveness is {} liveness ? liveness with { Keepalive = null } : null
            }).ToArray() };
            omissions.Add("设备分段诊断已省略，连接判定与操作状态保留。");
            Update(); if (Fits(reply)) return reply;
        }

        // Do not turn a committed command into an apparent failure or return
        // a partial member list. The client explicitly marks status unknown,
        // while Ok/Error/Operation still describe the actual command result.
        return reply with { Status = null, Operation = reply.Operation ?? status.Operation,
            StatusNotice = "连接状态超过本地消息限制，暂时无法显示。操作结果已单独返回；请勿因状态缺失重复提交。" };
    }
}
