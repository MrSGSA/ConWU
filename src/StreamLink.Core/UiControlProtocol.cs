using System.IO.Pipes;

namespace StreamLink.Core;
public sealed record UiPeerDto(int Slot,string Name,string VirtualIp,bool Connected,bool Degraded,double? RttMs,string Phase)
{
    public ConnectionProgress? Connection {get;init;}
    public PeerLiveness? Liveness {get;init;}
    public string TraversalMethod {get;init;}="None";
    public string ActualTransport {get;init;}="None";
    public long SentBytes {get;init;}
    public long ReceivedBytes {get;init;}
    public long DroppedPackets {get;init;}
    public RouterPeerDrops? LocalDrops {get;init;}
    public string Quality {get;init;}="Unknown";
    public string OuterSource {get;init;}="Unknown";
    public string OuterTarget {get;init;}="Unknown";
}
public sealed record UiStatusDto(string Version,string DeviceName,string VirtualIp,string State,bool ServiceReady,bool NetworkEnabled,int DirectPeers,int TotalPeers,UiPeerDto[] Peers,string LogLevel,int SettingsPatchVersion=1)
{
    public ConnectionProgress? Connection {get;init;}
    public AdapterRuntimeStatus? Adapter {get;init;}
    public bool PersonalFeatureEdition {get;init;}
    public string NetworkId {get;init;}="";
    public bool IsOwner {get;init;}
    public UiNetworkSettings? Settings {get;init;}
    public string SettingsRevision {get;init;}="";
    public string MigrationNotice {get;init;}="";
    public UiPairingDto? Pairing {get;init;}
    public string QualityText {get;init;}="质量尚未测量";
    public QualityResult? LastQuality {get;init;}
    public string[] Logs {get;init;}=[];
    public ControlOperationStatus? Operation {get;init;}
    public UiStageLedger? Stages {get;init;}
    public string DiagnosticsNotice {get;init;}="";
    public long NetworkEstablishedAt {get;init;}
    public bool NetworkCreatedHere {get;init;}
    public EntryResolution[] EntryResolutions {get;init;}=[];
    public UiDesktopStatus? Desktop {get;init;}
}
public sealed record UiDesktopStatus(bool ServiceRegistered,bool AutoStart,string ServiceState);
public sealed record UiLegacyStage(Guid ResourceId,int ProcessId,string Mode,string Listener,string Target,
    LegacyBusinessHandoffReport? Handoff,LegacyBusinessEgressStats? Egress,EgressRouteWitness[] Routes);
public sealed record UiStageLedger(PacketAdapterStatistics? Adapter,EgressStats? Egress,UiLegacyStage[] ExplicitWorkers)
{
    public RouterPressureSnapshot? RouterPressure {get;init;}
    public string Accounting => "Wintun inner packets/bytes; Mesh counters are inner bytes; native injection is local API acceptance. Encapsulation sizes differ and cannot be subtracted. Remote/application delivery requires paired measurement.";
    public string PhysicalDelivery => "UnknownWithoutIndependentWitness";
}
public sealed record UiPairingDto(bool Active,bool Owner,string Code,string Verification,string Candidate,string PeerName,long Expires,string State)
{
    public string ProposedIp {get;init;}="";
}
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiNetworkSettings(string Service="",string CertificatePin="",string ManualEndpoint="",string PathSelection="faketcp-only",bool AllowManualQualityRequests=false,int ListenPort=44680,int SourcePort=44691)
{
    public string ConnectionSource {get;init;}="custom";
    public ExistingEntry[] ExistingEntries {get;init;}=[];
    public string[]? TcpStun {get;init;}
    public string[]? UdpStun {get;init;}
    public string RequestedVirtualIp {get;init;}="";
}
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiNetworkAction(string Action,string Service="",string CertificatePin="",string Code="",string ExpectedNetwork="",bool ConfirmReplace=false,string Verification="",string Candidate="",int PeerSlot=0,UiNetworkSettings? Settings=null,string ExpectedRevision="",string Mode="faketcp",string ProposedIp="");
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiConfigPatch(string? DeviceName=null,string? LogLevel=null,
    [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ExpectedDeviceName=null,
    [property:System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)] string? ExpectedLogLevel=null)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? RequestedVirtualIp {get;init;}
    [System.Text.Json.Serialization.JsonIgnore(Condition=System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public string? ExpectedVirtualIp {get;init;}
    // Preconditions concern ONLY edited fields. An unrelated network setting
    // changing while the request waits must not conflict or be copied back.
    public DeviceProfile ApplyTo(DeviceProfile current)
    {
        if(DeviceName==null&&ExpectedDeviceName!=null || LogLevel==null&&ExpectedLogLevel!=null || RequestedVirtualIp==null&&ExpectedVirtualIp!=null)
            throw new FormatException("补丁前置值必须对应一个待修改字段");
        if(DeviceName!=null&&ExpectedDeviceName!=null&&current.DeviceName!=ExpectedDeviceName ||
           LogLevel!=null&&ExpectedLogLevel!=null&&current.LogLevel!=ExpectedLogLevel ||
           RequestedVirtualIp!=null&&ExpectedVirtualIp!=null&&current.RequestedVirtualIp!=ExpectedVirtualIp)
            throw new IOException("设置已被其他窗口修改；草稿已保留，请核对最新值后重试");
        var updated=ProfileChanges.Copy(current);
        if(DeviceName!=null)updated.DeviceName=DeviceName;
        if(LogLevel!=null)updated.LogLevel=LogLevel;
        if(RequestedVirtualIp!=null)updated.RequestedVirtualIp=RequestedVirtualIp;
        updated.Validate();
        return updated;
    }
}
[System.Text.Json.Serialization.JsonUnmappedMemberHandling(System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow)]
public sealed record UiControlRequest(string Method,UiConfigPatch? Patch=null,Guid OperationId=default,UiNetworkAction? Network=null,int PeerSlot=0,int Mbps=50,Guid CancelOperationId=default);
public sealed record UiControlReply(bool Ok,string Error,UiStatusDto? Status,int Api=1,ControlOperationStatus? Operation=null)
{
    public string StatusNotice {get;init;}="";
}
public sealed class UiBackendException(string code,string message,Exception? inner=null):IOException(message,inner)
{
    public string Code {get;}=code;
}
public static class UiControlProtocol
{
    public static string PipeName=>WindowsInstance.Name + "-UI-v1";
    public static async Task<UiControlReply> Call(UiControlRequest request,CancellationToken token=default)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(20000);
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        using var pipe=new NamedPipeClientStream(".",PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,System.Security.Principal.TokenImpersonationLevel.Identification);
        try {
            await pipe.ConnectAsync(3000,deadline.Token);ControlServerIdentity.Verify(pipe);
            await ServiceProtocol.Write(pipe,request,deadline.Token);return await ServiceProtocol.Read<UiControlReply>(pipe,deadline.Token);
        } catch(UnauthorizedAccessException ex){throw new UiBackendException("AccessDenied","当前 Windows 账号未获个人后台访问权限，请运行 MSI 修复安装并核对日常使用账号。",ex);}
        catch(Exception ex)when(ex is IOException or TimeoutException && ex is not UiBackendException){
            string state=OperatingSystem.IsWindows()?ControlServerIdentity.Availability():"Unavailable";
            throw state switch {
                "NotInstalled"=>new UiBackendException(state,"尚未安装个人后台，请运行 MSI 安装包。",ex),
                "Stopped"=>new UiBackendException(state,"个人后台已停止，请在 Windows 服务中启动 StreamLink 个人后台，或运行 MSI 修复安装。",ex),
                "AccessDenied"=>new UiBackendException(state,"当前 Windows 账号无法查询个人后台，请修复安装并核对授权。",ex),
                _=>new UiBackendException("ServiceError","个人服务正在运行，但本地控制连接未完成。请修复安装或查看诊断日志。",ex)
            };
        }
    }
}
