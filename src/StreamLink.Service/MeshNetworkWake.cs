using System.Net.NetworkInformation;

namespace StreamLink.Service;

internal interface IMeshNetworkWake : IDisposable
{
    bool Take(long now);
}

// OS callbacks only mark bounded local state; they never run socket I/O,
// start workers, close paths or reset control budgets on the callback thread.
internal sealed class MeshNetworkWake : IMeshNetworkWake
{
    static event Action? resumed;
    readonly object gate = new();
    readonly Func<long> clock;
    readonly bool watch;
    bool pending, resume, disposed, delivered;
    long firstSignal, lastSignal, lastTaken;
    internal MeshNetworkWake(bool watch = true, Func<long>? clock = null)
    {
        this.watch = watch; this.clock = clock ?? (() => Environment.TickCount64);
        resumed += OnResume;
        if (watch) try {
            NetworkChange.NetworkAddressChanged += OnAddress;
            NetworkChange.NetworkAvailabilityChanged += OnAvailability;
        } catch {
            NetworkChange.NetworkAddressChanged -= OnAddress;
            NetworkChange.NetworkAvailabilityChanged -= OnAvailability;
            resumed -= OnResume; throw;
        }
    }
    internal static void ResumeAll() => resumed?.Invoke();
    void OnResume() => Signal(true);
    void OnAddress(object? sender, EventArgs args) => Signal(false);
    void OnAvailability(object? sender, NetworkAvailabilityEventArgs args) => Signal(false);
    internal void Signal(bool isResume)
    {
        lock (gate) {
            if (disposed) return;
            long now = clock(); if (!pending) firstSignal = now;
            pending = true; resume |= isResume; lastSignal = now;
        }
    }
    public bool Take(long now)
    {
        lock (gate) {
            if (disposed || !pending || delivered && now - lastTaken < 2000) return false;
            if (!resume && now - lastSignal < 250 && now - firstSignal < 1000) return false;
            pending = resume = false; delivered = true; lastTaken = now; return true;
        }
    }
    public void Dispose()
    {
        lock (gate) { if (disposed) return; disposed = true; pending = resume = false; }
        if (watch) {
            NetworkChange.NetworkAddressChanged -= OnAddress;
            NetworkChange.NetworkAvailabilityChanged -= OnAvailability;
        }
        resumed -= OnResume;
    }
}
