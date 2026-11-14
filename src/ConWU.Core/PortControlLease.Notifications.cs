using System.Diagnostics;
using System.Net;

namespace StreamLink.Core;

public sealed partial class PortControlLease
{
    readonly SemaphoreSlim noticeWake = new(0, 1);
    long notifications, revalidations, lastRevalidation, notificationDue;
    bool noticePending;

    // Connected UDP or the multicast demultiplexer has checked the source.
    // A hint only wakes renewal. MAP updates and replies are wire-identical;
    // a matching update may satisfy that renewal, but never authenticates a
    // business path. Notifications cannot destroy an existing data path.
    void ObserveNotification(ReadOnlyMemory<byte> packet)
    {
        try { if (!currentRoute()) return; }
        catch (System.Net.NetworkInformation.NetworkInformationException) { return; }
        lock (sync) {
            if (disposed || !confirmed || state != "Granted") return;
            long now = Stopwatch.GetTimestamp(); bool reboot = false, changed = false;
            if (kind == PortControlKind.Pcp) {
                if (PortControlProtocol.PcpAnnounceEpoch(packet.Span) is { } announced) {
                    reboot = PortControlTiming.EpochChanged(kind, epoch, announced, Stopwatch.GetElapsedTime(epochAt, now).TotalSeconds);
                    if (!reboot) { epoch = announced; epochAt = now; return; }
                } else {
                    var request = PortControlProtocol.Pcp(route.Local, internalPort, protocol, nonce, RequestedLifetime, external!);
                    var update = PortControlProtocol.ParsePcp(packet.Span, request);
                    if (update == null || update.NatPmpFallback) return;
                    reboot = PortControlTiming.EpochChanged(kind, epoch, update.Epoch, Stopwatch.GetElapsedTime(epochAt, now).TotalSeconds);
                    changed = update.Error != 0 || !Equals(update.External, external) || update.Lifetime + 2d < lifetime - Stopwatch.GetElapsedTime(grantedAt, now).TotalSeconds;
                }
            } else {
                var address = PortControlProtocol.ParsePmp(packet.Span, [0, 0], null);
                if (address is not { Error: 0, External: not null }) return;
                reboot = PortControlTiming.EpochChanged(kind, epoch, address.Epoch, Stopwatch.GetElapsedTime(epochAt, now).TotalSeconds);
                changed = !address.External.Address.Equals(external!.Address);
            }
            if (!changed && !reboot) return;
            // One coalesced hint per lease; at most one revalidation per five
            // seconds even if the trusted local gateway keeps sending updates.
            notifications++; noticePending = true; state = "GatewayRevalidating";
            double cooldown = lastRevalidation == 0 ? 0 : Math.Max(0, 5 - Stopwatch.GetElapsedTime(lastRevalidation, now).TotalSeconds);
            double jitter = reboot ? Random.Shared.NextDouble() * 5 : 0;
            notificationDue = now + (long)(Math.Max(cooldown, jitter) * Stopwatch.Frequency);
            if (noticeWake.CurrentCount == 0) noticeWake.Release();
        }
    }

    async Task<bool> RevalidateNotification(CancellationToken token)
    {
        long due;
        lock (sync) { if (!noticePending) return false; noticePending = false; due = notificationDue; }
        Changed?.Invoke(Snapshot);
        double delay = (due - Stopwatch.GetTimestamp()) / (double)Stopwatch.Frequency;
        if (delay > 0) await Task.Delay(TimeSpan.FromSeconds(delay), token);
        using var window = CancellationTokenSource.CreateLinkedTokenSource(token); window.CancelAfter(TimeSpan.FromSeconds(8));
        bool entered = false;
        try {
            await operation.WaitAsync(window.Token); entered = true;
            lock (sync) { lastRevalidation = Stopwatch.GetTimestamp(); revalidations++; }
            PortControlReply reply;
            if (kind == PortControlKind.Pcp) {
                reply = await Exchange(PortControlProtocol.Pcp(route.Local, internalPort, protocol, nonce, RequestedLifetime, external!), kind, 4, null, window.Token);
            } else {
                var address = await Exchange([0, 0], kind, 9, null, window.Token); CheckError(address);
                reply = await Exchange(PortControlProtocol.Pmp(internalPort, protocol, RequestedLifetime, (ushort)external!.Port), kind, 9, address.External!.Address, window.Token);
            }
            Accept(reply, revalidated: true);
            return true;
        } catch (OperationCanceledException) when (!token.IsCancellationRequested) {
            lock (sync) state = "GatewayRevalidationFailed";
            throw new IOException("网关通知复核超过八秒，未重新发布旧候选");
        } finally { if (entered) operation.Release(); }
    }
}
