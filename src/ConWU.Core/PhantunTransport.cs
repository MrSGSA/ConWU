using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("ConWU.PhantunTests")]

namespace StreamLink.Core;

// The carrier owns only IP/TCP framing. PairNetworkFrame and MeshLink retain
// network identity, approved membership, AEAD and replay protection above it.
public interface IMeshCarrierRoutes { event Action<IPEndPoint>? RouteClosed; event Action<IPEndPoint>? RouteOpened; }

public class PacketCarrierTransport : IMeshTransport, IMeshCarrierRoutes
{
    readonly ChildJob children;
    readonly string mode;
    Socket? sourceLease;
    LinuxKernelResource? kernel;
    IDisposable? firewall;
    Process? child;
    int disposed, failed;
    string failure = "";
    public IPEndPoint? ClientEndpoint { get; }
    public bool Exited => Volatile.Read(ref disposed) != 0 || Volatile.Read(ref failed) != 0 || children.AnyExited;
    public bool ControlsWirePackets => true;
    public string FailureReason => Volatile.Read(ref disposed) != 0 ? "" : Exited ? mode+"CarrierExited:" + failure : "";
    internal int ProcessId { get; }
    public event Action<IPEndPoint>? RouteClosed;
    public event Action<IPEndPoint>? RouteOpened;

    public PacketCarrierTransport(string components, string sessionRoot, MeshProfile profile, IPEndPoint target,
        bool server, int listenPort, string logLevel, Action<IPEndPoint>? reserve = null)
    {
        mode=profile.Pair.Mode;
        if (!TransportModes.PacketCarrier(profile.Pair.Mode) || target.AddressFamily != AddressFamily.InterNetwork || target.Port == 0
            || server && (!IPAddress.IsLoopback(target.Address) || listenPort is < 1024 or > 65535))
            throw new ArgumentException("数据报 TCP 需要独立的 IPv4 入口及有效本机转发目标");
        if (OperatingSystem.IsLinux()) LinuxPlatform.PrivateDirectory(sessionRoot);
        else Directory.CreateDirectory(sessionRoot);
        children = new();
        string executable = Path.Combine(components, (mode=="phantun"?"conwu-phantun":"conwu-raw")+(OperatingSystem.IsWindows()?".exe":""));
        try {
            PacketCarrierCapabilities.Require(executable,mode);
            IPEndPoint source;
            sourceLease = new(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ExclusiveAddressUse = true };
            if(mode=="tcpraw"&&OperatingSystem.IsLinux()){
                sourceLease.ExclusiveAddressUse=false;
                sourceLease.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);
            }
            if (server) sourceLease.Bind(new IPEndPoint(IPAddress.Any, listenPort));
            else {
                using var route = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                route.Connect(target);
                sourceLease.Bind(new IPEndPoint(((IPEndPoint)route.LocalEndPoint!).Address, 0));
            }
            source = (IPEndPoint)sourceLease.LocalEndPoint!;
            if (OperatingSystem.IsWindows()) {
                if (server) firewall = WindowsHost.AllowStreamListener(listenPort, sessionRoot, executable);
            } else if (OperatingSystem.IsLinux()) {
                kernel = new();
                LinuxPlatform.Run("nft", "add", "table", "inet", kernel.Table);
                string hook=mode=="tcpraw"?"output":"input";
                LinuxPlatform.Run("nft", "add", "chain", "inet", kernel.Table, hook, "{", "type", "filter", "hook", hook, "priority", "-150", ";", "policy", "accept", ";", "}");
                List<string> rule = ["add", "rule", "inet", kernel.Table, hook];
                if(mode=="tcpraw") {
                    rule.AddRange(["ip","ttl","1","tcp","sport",source.Port.ToString()]);
                    if(!server)rule.AddRange(["ip","saddr",source.Address.ToString(),"ip","daddr",target.Address.ToString(),"tcp","dport",target.Port.ToString()]);
                    if(server)firewall=LinuxFirewall.AllowStreamListener(listenPort);
                } else if (server) rule.AddRange(["tcp", "dport", listenPort.ToString()]);
                else rule.AddRange(["ip", "saddr", target.Address.ToString(), "ip", "daddr", source.Address.ToString(), "tcp", "sport", target.Port.ToString(), "tcp", "dport", source.Port.ToString()]);
                rule.Add("drop");
                LinuxPlatform.Run("nft", rule.ToArray());
            } else throw new PlatformNotSupportedException("数据报 TCP 支持 Windows 和 Linux");
            var ready = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            void Observe(string line) {
                string prefix = mode=="phantun"?"CONWU_PHANTUN ":"CONWU_RAW ";
                if (!line.StartsWith(prefix, StringComparison.Ordinal) || line.Length > 4096) return;
                try {
                    using var parsed = JsonDocument.Parse(line[prefix.Length..], new JsonDocumentOptions { MaxDepth = 8 });
                    var value = parsed.RootElement;
                    if (value.GetProperty("event").GetString() == "failed") {
                        failure = value.GetProperty("reason").GetString() ?? "Unknown";
                        ready.TrySetException(new IOException("数据报 TCP 启动失败：" + failure));
                    } else if (value.GetProperty("event").GetString() == "ready") ready.TrySetResult(value.Clone());
                    else if (value.GetProperty("event").GetString() is ("peer-closed" or "peer-opened") && value.GetProperty("abi").GetInt32() == 1
                        && IPEndPoint.TryParse(value.GetProperty("udp").GetString()??"", out var closed)
                        && closed.AddressFamily == AddressFamily.InterNetwork && IPAddress.IsLoopback(closed.Address) && closed.Port > 0) {
                        try { if(value.GetProperty("event").GetString()=="peer-opened")RouteOpened?.Invoke(closed);else RouteClosed?.Invoke(closed); }
                        catch (Exception error) { failure="RouteCleanup:"+error.GetType().Name;Volatile.Write(ref failed,1); }
                    }
                } catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException) {
                    ready.TrySetException(new IOException("数据报 TCP 组件就绪消息无效", ex));
                }
            }
            // TCPRAW must bind/connect using a real kernel socket in the child.
            // Releasing this probe never falls back to another port silently;
            // readiness confirms the exact tuple, or construction fails.
            if(mode=="tcpraw"){sourceLease.Dispose();sourceLease=null;}
            List<string> arguments=[server ? "--server" : "--client", "--source", source.ToString(), "--remote", target.ToString(), "--parent", Environment.ProcessId.ToString()];
            if(mode!="phantun")arguments.AddRange(["--carrier",mode]);
            var process = child = children.StartObserved(executable, arguments,
                logLevel == "off" ? null : Path.Combine(sessionRoot, mode+"-" + Guid.NewGuid().ToString("N") + ".log"), null, null, Observe,redirectInput:true);
            ProcessId = process.Id;
            try { Task.WhenAny(ready.Task, process.WaitForExitAsync()).WaitAsync(TimeSpan.FromSeconds(6)).GetAwaiter().GetResult(); }
            catch (TimeoutException error) { throw new IOException("数据报 TCP 本机组件启动超时，请检查驱动及会话日志", error); }
            if (!ready.Task.IsCompleted) throw new IOException("数据报 TCP 组件未就绪，请检查完整安装包、驱动及端口占用");
            var reply = ready.Task.GetAwaiter().GetResult();
            if (process.HasExited || reply.GetProperty("abi").GetInt32() != 1 || reply.GetProperty("pid").GetInt32() != process.Id
                || mode!="phantun"&&reply.GetProperty("carrier").GetString()!=mode
                || reply.GetProperty("role").GetString() != (server ? "server" : "client") || reply.GetProperty("source").GetString() != source.ToString())
                throw new IOException("数据报 TCP 组件身份或端口确认失败");
            if (!server) {
                if (!IPEndPoint.TryParse(reply.GetProperty("udp").GetString()??"", out var endpoint)
                    || endpoint.AddressFamily != AddressFamily.InterNetwork || !IPAddress.IsLoopback(endpoint.Address) || endpoint.Port == 0)
                    throw new IOException("数据报 TCP 本机转发端口无效");
                ClientEndpoint = endpoint;
                reserve?.Invoke(endpoint);
            }
        } catch (Exception original) {
            try { Dispose(); } catch (Exception cleanup) { throw new AggregateException("数据报 TCP 启动失败且资源回收未完成", original, cleanup); }
            throw;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        List<Exception> failures = [];
        try {
            if (child is { HasExited: false }) {
                child.StandardInput.WriteLine("stop");child.StandardInput.Flush();
                child.WaitForExit(1500);
            }
        } catch (Exception error) when (error is IOException or InvalidOperationException) { }
        try { children.Dispose(); } catch (Exception error) { failures.Add(error); }
        try { kernel?.Dispose(); } catch (Exception error) { failures.Add(error); }
        try { firewall?.Dispose(); } catch (Exception error) { failures.Add(error); }
        sourceLease?.Dispose();
        if (failures.Count > 0) throw new AggregateException("数据报 TCP 配套资源未完全回收，请检查日志", failures);
    }
}

internal static class PacketCarrierCapabilities
{
    static readonly object gate = new();
    static readonly Dictionary<string, (long Size, DateTime At)> validated = [];
    internal static void Require(string executable,string mode)
    {
        var file = new FileInfo(executable);
        if (!file.Exists) throw new IOException("缺少数据报 TCP 组件，请更新完整安装包");
        if (OperatingSystem.IsWindows() && !File.Exists(Path.Combine(file.DirectoryName!, "WinDivert.dll")))
            throw new IOException("数据报 TCP 的 WinDivert 依赖不完整，请更新完整安装包");
        lock (gate) {
            if (validated.TryGetValue(file.FullName, out var before) && before.Size == file.Length && before.At == file.LastWriteTimeUtc) return;
            var start = new ProcessStartInfo(file.FullName) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add("--conwu-info");
            using var child = Process.Start(start) ?? throw new IOException("无法查询数据报 TCP 组件");
            var output = child.StandardOutput.ReadToEndAsync(); var error = child.StandardError.ReadToEndAsync();
            if (!child.WaitForExit(3000)) { child.Kill(true); child.WaitForExit(3000); throw new IOException("数据报 TCP 组件查询超时"); }
            string text = output.GetAwaiter().GetResult(); error.GetAwaiter().GetResult();
            if (child.ExitCode != 0 || text.Length > 4096) throw new IOException("数据报 TCP 组件查询失败，请核对安装包中的 WinDivert 依赖");
            using var document = JsonDocument.Parse(text);
            var info = document.RootElement;
            if (info.GetProperty("component").GetString() != (mode=="phantun"?"ConWU.Phantun":"ConWU.RawCarriers") || info.GetProperty("abi").GetInt32() != 1
                || info.GetProperty("platform").GetString() != (OperatingSystem.IsWindows() ? "windows" : "linux")
                || info.GetProperty("maxDatagram").GetInt32() < PairNetworkFrame.HeaderSize+MeshLink.Overhead+MeshLink.Mtu || !info.GetProperty("fixedSourcePort").GetBoolean()
                || !info.GetProperty("parentWatchdog").GetBoolean() || !info.GetProperty("boundedConnections").GetBoolean()
                || !info.GetProperty("inputStop").GetBoolean() || !info.GetProperty("routeCloseEvents").GetBoolean() || !info.GetProperty("routeOpenEvents").GetBoolean())
                throw new NotSupportedException("数据报 TCP 组件与本版不匹配，请更新完整安装包");
            if(mode!="phantun"&&(!info.GetProperty("carriers").EnumerateArray().Any(c=>c.GetString()=="mimic-v1-zero-padding")||!info.GetProperty("carriers").EnumerateArray().Any(c=>c.GetString()=="tcpraw-v1-kernel-handshake")))throw new NotSupportedException("原始 TCP 承载能力不完整");
            if (validated.Count > 32) validated.Clear();
            validated[file.FullName] = (file.Length, file.LastWriteTimeUtc);
        }
    }
}

public sealed class PhantunTransport(string components,string folder,MeshProfile mesh,IPEndPoint target,bool server,int port,string level,Action<IPEndPoint>? reserve=null)
    : PacketCarrierTransport(components,folder,mesh.Pair.Mode=="phantun"?mesh:throw new ArgumentException("Phantun 需要相应的配对协议"),target,server,port,level,reserve);
public sealed class RawTcpTransport(string components,string folder,MeshProfile mesh,IPEndPoint target,bool server,int port,string level,Action<IPEndPoint>? reserve=null)
    : PacketCarrierTransport(components,folder,mesh.Pair.Mode is "mimic" or "tcpraw"?mesh:throw new ArgumentException("请选择 Mimic 或 TCPRAW 配对协议"),target,server,port,level,reserve);
