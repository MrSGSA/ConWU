using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "StreamLink");
if (WindowsServiceHelpers.IsWindowsService())
    builder.Services.Replace(ServiceDescriptor.Singleton<IHostLifetime, StreamLinkServiceLifetime>());
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));
builder.Services.AddHostedService<ControlWorker>();
await builder.Build().RunAsync();
