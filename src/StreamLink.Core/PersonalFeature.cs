using System.Text.Json;
using System.Text.Json.Serialization;

namespace StreamLink.Core;

// Compile-time edition, never an IPC/profile bool which grants driver access.
public static class PersonalFeature
{
    public static bool Enabled {
        get {
#if STREAMLINK_PERSONAL_FEATURE
            return true;
#else
            return false;
#endif
        }
    }
    public const string Contract = "AQ-1-personal";
    public static string InstanceName => Enabled ? "StreamLink-PersonalFeature" : "StreamLink";
    public static string DataRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), InstanceName);
    public static string AdapterText(AdapterRuntimeStatus? status) => status is null ? "虚拟网卡尚未打开" :
        $"网卡：{status.ActualProvider ?? "未打开"}（请求 {status.RequestedProvider}） · {status.State}" +
        (status.State=="Blocked" ? " · "+status.Reason : "");

    public static DeviceProfile EnhancedPreset(DeviceProfile current)
    {
        if (!Enabled) throw new IOException("个人增强预设仅在个人功能先行包开放");
        var next = ProfileChanges.Copy(current);
        if (next.Pair?.Mode == "udp" || next.Mesh?.Pair.Mode == "udp") throw new IOException("个人增强预设需要 FakeTCP 网络");
        next.TransportMode = "faketcp";
        next.TraversalMode = "tcp-udp";
        next.PathSelection = "prefer-faketcp";
        bool Intent(string name) => !next.CapabilityIntents.TryGetValue(name, out var value) || value != false;
        next.AllowUdpFallback = Intent(nameof(DeviceProfile.AllowUdpFallback));
        next.TcpPeerReflexive = Intent(nameof(DeviceProfile.TcpPeerReflexive));
        // High-cost exploration, prediction, active load and gateway changes
        // retain their existing independent permission and eligibility gates.
        next.Validate();
        return next;
    }
}

[JsonConverter(typeof(PacketAdapterBackendConverter))]
public enum PacketAdapterBackend { OfficialWintun, StreamLinkTun }

public sealed class PacketAdapterBackendConverter : JsonConverter<PacketAdapterBackend>
{
    public override PacketAdapterBackend Read(ref Utf8JsonReader reader, Type type, JsonSerializerOptions options)
        => reader.TokenType == JsonTokenType.String ? reader.GetString() switch {
            "official-wintun" => PacketAdapterBackend.OfficialWintun,
            "streamlink-tun-experimental" => PacketAdapterBackend.StreamLinkTun,
            _ => throw new JsonException("虚拟网卡后端不在白名单")
        } : throw new JsonException("虚拟网卡后端必须是受支持的字符串");
    public override void Write(Utf8JsonWriter writer, PacketAdapterBackend value, JsonSerializerOptions options)
        => writer.WriteStringValue(value switch {
            PacketAdapterBackend.OfficialWintun => PacketAdapterProviders.OfficialWintun,
            PacketAdapterBackend.StreamLinkTun => PacketAdapterProviders.NativeExperimental,
            _ => throw new JsonException("虚拟网卡后端无效")
        });
}

public sealed record AdapterRuntimeStatus(string RequestedProvider, string? ActualProvider, string State, string Reason,
    int? Abi = null, string? DeviceInstance = null, uint? InterfaceIndex = null, string? PackageHash = null,
    bool? SignatureValid = null, bool? Loaded = null, long? ReadPackets = null, long? WrittenPackets = null);
