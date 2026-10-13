using System.IO.Pipes;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

static class UiBoundaryTests
{
    public static async Task Run(ControlWorker worker,Action<bool,string> check)
    {
        const BindingFlags flags=BindingFlags.Instance|BindingFlags.NonPublic;
        string sid=WindowsIdentity.GetCurrent().User!.Value;var store=new ProfileStore();store.AuthorizeUiUser(sid);
        var created=await worker.Handle(new("mesh-create",Service:"https://example.com/"));check(created.Ok,"fixture creates a real protected mesh identity without starting networking");
        using var stop=new CancellationTokenSource();var server=(Task)typeof(ControlWorker).GetMethod("RunUiControl",flags)!.Invoke(worker,[stop.Token])!;
        async Task<UiControlReply> Request(UiControlRequest request){using var deadline=new CancellationTokenSource(5000);using var pipe=new NamedPipeClientStream(".",UiControlProtocol.PipeName,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);await pipe.ConnectAsync(3000,deadline.Token);await ServiceProtocol.Write(pipe,request,deadline.Token);return await ServiceProtocol.Read<UiControlReply>(pipe,deadline.Token);}
        try{
            var status=await Request(new("status"));string json=JsonSerializer.Serialize(status);
            check(status.Ok&&status.Status?.ServiceReady==true,"actual Windows UI pipe authenticates local SID and returns a separate status DTO");
            var secret=created.Profile!.Mesh!;check(!json.Contains(secret.Pair.Secret)&&!json.Contains(secret.SigningPrivate)&&!json.Contains(secret.ExchangePrivate)&&!json.Contains(secret.OwnerPrivate)&&!json.Contains("Profile")&&!json.Contains("Invite"),"UI status cannot receive profile, enrollment or any long-term credential");
            var patched=await Request(new("patch",new("ordinary UI name","error"),Guid.NewGuid()));var full=await worker.Handle(new("status"));
            check(patched.Ok&&full.Profile!.DeviceName=="ordinary UI name"&&full.Profile.LogLevel=="error"&&!full.Profile.Enabled,"restricted patch changes allowed metadata without enabling a driver/network");
            check(!(await Request(new("mesh-invite"))).Ok&&!(await Request(new("save"))).Ok,"restricted endpoint rejects full profile and private enrollment methods");
            bool denied=false;try{JsonSerializer.Deserialize<UiConfigPatch>("{\"LogDirectory\":\"C:/Windows\"}");}catch(JsonException){denied=true;}check(denied,"unmapped arbitrary log path/other settings are rejected by patch schema");
            var unauthorized=(Task<UiControlReply>)typeof(ControlWorker).GetMethod("HandleUi",flags)!.Invoke(worker,[new UiControlRequest("status"),"S-1-5-21-111-222-333-444",CancellationToken.None])!;
            check(!(await unauthorized).Ok&&(await unauthorized).Status==null,"method-level unauthorized SID is rejected without returning status");
        }finally{stop.Cancel();await server;}
    }
}
