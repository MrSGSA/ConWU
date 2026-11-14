using System.Net;
using StreamLink.Core;

static class StunObservationTests
{
    internal static async Task Run(Action<bool, string> check)
    {
        // Public literals are fixtures; injected probes never contact them.
        var local = new IPEndPoint(IPAddress.Parse("192.168.50.2"), 44693);
        var bad = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 3478);
        var actual = IPAddress.Parse("1.1.1.1");
        var witness = new IPEndPoint(IPAddress.Parse("9.9.9.9"), 3478);
        var suspicious = new StunResult("tcp", bad.ToString(), local, new(bad.Address, 41178));
        int probes = 0;
        Task<StunObservationValidation.Sample?> Sample(string name, IPAddress source, IPEndPoint excluded, CancellationToken token)
        {
            probes++;
            check(source.Equals(local.Address) && excluded.Equals(bad), "corroboration retains the physical source and identifies the suspect reflector");
            return Task.FromResult<StunObservationValidation.Sample?>(new(witness, new(actual, 1700)));
        }
        async Task<bool> Rejected(Func<Task> action)
        {
            try { await action(); return false; }
            catch (StunReflectionException) { return true; }
        }
        check(await Rejected(() => StunObservationValidation.Validate(suspicious, bad, ["owned:3478"], default, Sample)),
            "a reflector publishing its own address is rejected when a separate reflector confirms another public exit");
        check(probes == 1, "mismatching evidence stops promptly instead of scanning the full STUN catalogue");
        var healthy = suspicious with { Public = new(actual, 1915) };
        await StunObservationValidation.Validate(healthy, bad, ["unused:3478"], default, Sample);
        check(probes == 1 && healthy.Public.Port == 1915, "ordinary reflection incurs no extra requests and retains the exact observed port");

        await StunObservationValidation.Validate(suspicious, bad, ["separate:3478"], default,
            (_, _, _, _) => Task.FromResult<StunObservationValidation.Sample?>(new(witness, new(bad.Address, 9000))));
        check(suspicious.Public.Port == 41178, "a legitimate shared public address is accepted after independent corroboration without borrowing the probe port");
        check(await Rejected(() => StunObservationValidation.Validate(suspicious, bad, ["alias:3478"], default,
            (_, _, _, _) => Task.FromResult<StunObservationValidation.Sample?>(new(bad, new(actual, 1700))))),
            "another hostname for the same reflector is not independent evidence");
        check(await Rejected(() => StunObservationValidation.Validate(suspicious, bad, ["other-bad:3478"], default,
            (_, _, _, _) => Task.FromResult<StunObservationValidation.Sample?>(new(witness, new(witness.Address, 1700))))),
            "a second self-reporting reflector cannot validate the first");
        check(await Rejected(() => StunObservationValidation.Validate(suspicious, bad, ["offline:3478"], default,
            (_, _, _, _) => Task.FromException<StunObservationValidation.Sample?>(new IOException("offline")))),
            "unavailable independent evidence withdraws the suspect candidate instead of publishing it");
        check(await Rejected(() => StunObservationValidation.Validate(suspicious, bad, [], default, Sample)),
            "a single configured reflector never silently adds a third-party fallback");

        var direct = suspicious with { Local = new(bad.Address, 44693) };
        await StunObservationValidation.Validate(direct, bad, [], default, Sample);
        check(probes == 1, "a host using the reflector's actual public interface is not mistaken for a faulty NAT observation");
        var loopback = new IPEndPoint(IPAddress.Loopback, 3478);
        await StunObservationValidation.Validate(suspicious with { Public = loopback }, loopback, [], default, Sample);
        check(probes == 1, "local reflection fixtures and local-only services require no internet corroboration");
        using var stop = new CancellationTokenSource(); stop.Cancel();
        bool canceled = false;
        try { await StunObservationValidation.Validate(suspicious, bad, [], stop.Token, Sample); }
        catch (OperationCanceledException) { canceled = true; }
        check(canceled && probes == 1, "caller cancellation is preserved without probing or publishing a candidate");
        using var lateStop = new CancellationTokenSource();
        canceled = false;
        try {
            await StunObservationValidation.Validate(suspicious, bad, ["separate:3478"], lateStop.Token,
                (_, _, _, _) => {
                    lateStop.Cancel();
                    return Task.FromResult<StunObservationValidation.Sample?>(new(witness, new(bad.Address, 9000)));
                });
        } catch (OperationCanceledException) { canceled = true; }
        check(canceled, "a late corroborating result cannot publish an entry after its owning request was canceled");
        check(TcpMapping.HelperFailure(new StunReflectionException("unused")) == "UntrustedReflection",
            "maintenance reports an untrusted reflection separately from a socket failure");
    }
}
