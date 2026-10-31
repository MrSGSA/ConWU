using StreamLink.Core;
using StreamLink.Web;

if (args.Length >= 2 && args[0] == "--validation-instance") {
    WindowsInstance.ConfigureValidation(args[1]); args = args[2..];
}
if (args is not ["--controlled"]) return 2;
WebPanel started;
try { started=await WebPanel.Start(UiControlProtocol.Call, Path.Combine(AppContext.BaseDirectory, "wwwroot"),port:WindowsInstance.IsValidation?0:WebPanel.DefaultPort); }
catch(Exception ex) { Console.Error.WriteLine($"WebUI 无法监听 127.0.0.1:{WebPanel.DefaultPort}，请确认该端口未被其他程序占用。{ex.Message}");return 1; }
await using var panel=started;
// The desktop launches this process with redirected anonymous pipes. A short
// lived, one-use fragment is never written to a log, file or HTTP request URL.
while (await Console.In.ReadLineAsync() is {} command) {
    if (command == "open") { Console.WriteLine(panel.OpenLink()); await Console.Out.FlushAsync(); }
    else if (command == "quit") break;
}
return 0;
