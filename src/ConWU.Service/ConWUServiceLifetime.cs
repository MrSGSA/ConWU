using System.ServiceProcess;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;

namespace StreamLink.Service;

// SCM power notifications work without a logged-in desktop or a UI message
// loop. Host start/stop/shutdown behavior stays with WindowsServiceLifetime.
internal sealed class StreamLinkServiceLifetime : WindowsServiceLifetime
{
    public StreamLinkServiceLifetime(IHostEnvironment environment, IHostApplicationLifetime lifetime,
        ILoggerFactory logging, IOptions<HostOptions> options, IOptions<WindowsServiceLifetimeOptions> serviceOptions)
        : base(environment, lifetime, logging, options, serviceOptions) => CanHandlePowerEvent = true;
    protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
    {
        if (powerStatus is PowerBroadcastStatus.ResumeAutomatic or PowerBroadcastStatus.ResumeSuspend or PowerBroadcastStatus.ResumeCritical)
            MeshNetworkWake.ResumeAll();
        return base.OnPowerEvent(powerStatus);
    }
}
