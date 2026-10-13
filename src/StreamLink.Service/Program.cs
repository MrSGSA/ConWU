using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting.WindowsServices;

var builder = Host.CreateApplicationBuilder(args);
if(args.Length>=2&&args[0]=="--validation-instance"){
    if(!WindowsHost.IsAdmin)throw new UnauthorizedAccessException("Isolated backend still requires administrator/System privileges");
    WindowsInstance.ConfigureValidation(args[1]);
}
builder.Services.AddWindowsService(o => o.ServiceName = WindowsInstance.Name);
if (WindowsServiceHelpers.IsWindowsService())
    builder.Services.Replace(ServiceDescriptor.Singleton<IHostLifetime, StreamLinkServiceLifetime>());
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(45));
builder.Services.AddHostedService<ControlWorker>();
await builder.Build().RunAsync();
