using StreamLink.Core;
using StreamLink.Discovery;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    public Func<Microsoft.AspNetCore.Http.HttpContext,Task>? RemoteManagement {get;set;}
    CoordinatorStatus coordinatorStatus = new(false, false, "未启用", []);
    Task? coordinating;
    CancellationTokenSource? coordinatorStop;
    void StartCoordinator() {
        if (coordinating is { IsCompleted: false }) return;
        coordinatorStop?.Dispose(); coordinatorStop = CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        var token = coordinatorStop.Token;
        coordinating = Task.Run(() => RunCoordinator(token), CancellationToken.None);
    }

    async Task RunCoordinator(CancellationToken token)
    {
        CoordinationHost? host = null;
        CoordinatorSettings? applied = null, probedSettings = null;
        CoordinatorDiagnostic? external = null;
        Task<CoordinatorDiagnostic>? probe = null;
        CancellationTokenSource? probeStop = null;
        long retry = 0, nextProbe = 0;
        async Task ClearProbe() {
            probeStop?.Cancel();
            try { if (probe != null) await probe; }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log("协调地址诊断未完成：" + ex.GetType().Name); }
            finally { probe = null; probeStop?.Dispose(); probeStop = null; }
        }
        async Task CloseHost() {
            await ClearProbe(); probedSettings = null; external = null;
            var closing = host; host = null;
            if (closing != null) {
                try { await closing.DisposeAsync(); }
                catch (Exception ex) { Log("协调服务释放资源时发生错误，将重新检查监听和数据锁：" + ex.Message); }
            }
        }
        void Failed(Exception ex) {
            retry = Environment.TickCount64 + 15000;
            Volatile.Write(ref coordinatorStatus, new(true, false, "启动失败：" + ex.Message, []) { RetryAt = DateTimeOffset.UtcNow.AddSeconds(15) });
            Log("本机协调服务暂不可用，15 秒后重试：" + ex.Message);
        }
        try {
            while (!token.IsCancellationRequested) {
                if(automaticCoordinator){
                    CoordinatorSettings? pending;lock(sync)pending=profile.CoordinatorRoleVersion<1?profile.Coordinator:null;
                    if(pending!=null){
                        try{
                            // Use the same gate as device preference writes so
                            // neither side can commit an older profile over the
                            // other's completed listener/version migration.
                            await requests.WaitAsync(token);
                            try{
                            lock(sync)pending=profile.CoordinatorRoleVersion<1?profile.Coordinator:null;
                            if(pending!=null){
                            var prepared=CoordinatorProvisioning.Enable(store,pending);
                            lock(sync){if(profile.CoordinatorRoleVersion<1&&profile.Coordinator==pending){
                                var next=ProfileChanges.Copy(profile);next.Coordinator=prepared;next.CoordinatorRoleVersion=1;store.Save(next);profile=next;PublishReply();
                            }}
                            }
                            }finally{requests.Release();}
                        }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException or FormatException){
                            Failed(ex);await Task.Delay(15000,token);continue;
                        }
                    }
                }
                CoordinatorSettings desired; lock (sync) desired = profile.Coordinator;
                // Changing the advertised probe URL does not restart the listener
                // or discard pending pairing rooms.
                var listener = desired with { PublicUrl = "", PublicCertificatePin = "" };
                if (applied != listener || host?.IsStopping == true) {
                    if (host?.IsStopping == true) Log("协调宿主已停止，正在恢复；现有直连不受此操作影响");
                    await CloseHost(); applied = listener; retry = 0;
                }
                if (!desired.Enabled) Volatile.Write(ref coordinatorStatus, new(false, false, "未启用", []));
                else if (host == null && Environment.TickCount64 >= retry) {
                    try {
                        desired.Validate();
                        Volatile.Write(ref coordinatorStatus, new(true, false, "正在启动", []));
                        host = CoordinationHost.Create(new(Path.Combine(store.DirectoryPath, "coordination"), desired.ListenUrl,
                            desired.CertificateFile, desired.CertificateKeyFile, desired.TrustCloudflare){ManagementHandler=RemoteManagement});
                        await host.Start(token);
                        Log("本机协调服务已启动；成员身份与数据连接独立运行");
                    } catch (Exception ex) when (!token.IsCancellationRequested) { await CloseHost(); Failed(ex); }
                }
                if (host != null) {
                    if (probedSettings != desired) {
                        await ClearProbe(); probedSettings = desired; nextProbe = 0;
                        external = new(desired.PublicUrl.Length == 0 ? "unconfigured" : "checking",
                            desired.PublicUrl.Length == 0 ? "尚未设置外部 HTTPS 地址，未检查外部访问路径" : "正在检查外部 HTTPS 地址", DateTimeOffset.UtcNow);
                    }
                    if (probe?.IsCompleted == true) {
                        try { external = await probe; }
                        catch (Exception ex) when (!token.IsCancellationRequested) {
                            external = new("probe-error", "协调地址诊断未完成：" + ex.GetType().Name, DateTimeOffset.UtcNow);
                        }
                        finally { probe = null; probeStop?.Dispose(); probeStop = null; nextProbe = Environment.TickCount64 + 60000; }
                    }
                    if (probe == null && desired.PublicUrl.Length > 0 && Environment.TickCount64 >= nextProbe) {
                        probeStop = CancellationTokenSource.CreateLinkedTokenSource(token);
                        probe = MeshCoordinatorPreflight.Probe(desired.PublicUrl, desired.PublicCertificatePin, host.InstanceId, probeStop.Token);
                    }
                    string state = host.CertificateExpires is { } expires && expires <= DateTimeOffset.UtcNow.AddDays(7)
                        ? expires <= DateTimeOffset.UtcNow ? "运行中；监听证书已过期，请更换证书并重启协调角色" : "运行中；监听证书将在 7 天内过期"
                        : "运行中";
                    Volatile.Write(ref coordinatorStatus, new(true, true, state, host.Addresses) { External = external, CertificateExpires = host.CertificateExpires,CertificatePin=host.CertificatePin });
                }
                await Task.Delay(1000, token);
            }
        } catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally {
            await CloseHost();
            Volatile.Write(ref coordinatorStatus, new(applied?.Enabled == true, false, "已停止", []));
        }
    }

    async Task StopCoordinator() {
        coordinatorStop?.Cancel();
        try { if (coordinating != null) await coordinating; }
        catch (Exception ex) { Log("协调后台停止时发生错误：" + ex.Message); }
        finally { coordinating = null; coordinatorStop?.Dispose(); coordinatorStop = null; }
    }
}
