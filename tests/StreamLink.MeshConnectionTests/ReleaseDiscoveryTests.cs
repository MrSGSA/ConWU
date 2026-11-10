using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    sealed class SelectedGateway:HttpMessageHandler
    {
        public readonly ConcurrentDictionary<string,byte[]> Packets=new();
        public readonly ConcurrentQueue<string> Requests=new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            string address=request.RequestUri!.AbsoluteUri;Requests.Enqueue(address);
            if(request.Method==HttpMethod.Put){Packets[address]=await request.Content!.ReadAsByteArrayAsync(token);return new(HttpStatusCode.NoContent);}
            return Packets.TryGetValue(address,out var packet)?new(HttpStatusCode.OK){Content=new ByteArrayContent(packet)}:new(HttpStatusCode.NotFound);
        }
    }
    static async Task ReleaseDiscovery()
    {
        WindowsInstance.ConfigureValidation(Guid.NewGuid().ToString("N"));
        string folder=Path.Combine(ProfileStore.Root,"release-discovery");
        var store=new ProfileStore(Path.Combine(folder,"identity"));
        var automatic=CoordinatorProvisioning.Enable(store,new());
        Check(automatic.Enabled&&automatic.ListenUrl=="https://0.0.0.0:47822"&&automatic.PublicCertificatePin.Length==64,"an untouched device provisions an independent HTTPS coordinator identity");
        using(var certificate=X509Certificate2.CreateFromPemFile(automatic.CertificateFile,automatic.CertificateKeyFile))
            Check(certificate.HasPrivateKey&&automatic.PublicCertificatePin==Convert.ToHexString(SHA256.HashData(certificate.RawData)),"the advertised coordinator pin matches its real certificate and key");
        var repeated=CoordinatorProvisioning.Enable(store,new());
        Check(repeated==automatic,"a repeated provisioning attempt keeps the same certificate identity");
        var proxy=new CoordinatorSettings(true,"http://127.0.0.1:1145",TrustCloudflare:true,PublicUrl:"https://coord.example.invalid/");
        Check(CoordinatorProvisioning.Enable(store,proxy)==proxy,"existing HTTPS reverse-proxy and origin-trust settings remain unchanged");

        using var gateway=new SelectedGateway();using var http=new HttpClient(gateway);
        string[] selected=["https://one.example.invalid"];
        using var client=new PkarrClient(http,selected,TimeSpan.FromSeconds(2),new PkarrCheckpoints(),()=>selected);
        string seed=PkarrPacket.NewSeed(),source=PkarrPacket.Source(seed);
        var announcement=new PkarrAnnouncement(1,"faketcp",DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds(),["203.0.113.71:44680"]);
        long sequence=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()*1000;
        byte[] first=PkarrPacket.Create(seed,sequence,announcement);
        Check(await client.Publish(seed,first,default)==1&&(await client.Resolve(source,"faketcp",default)).Single()=="203.0.113.71:44680","selected gateway carries real signed PKARR PUT and GET packets");
        int before=gateway.Requests.Count;selected=["https://two.example.invalid/","https://three.example.invalid/"];
        byte[] second=PkarrPacket.Create(seed,sequence+1,announcement with{Endpoints=["203.0.113.72:44681"]});
        Check(await client.Publish(seed,second,default)==2&&client.GatewayCount==2,"saving new gateways changes subsequent publication without replacing the client identity");
        Check((await client.Resolve(source,"faketcp",default)).Single()=="203.0.113.72:44681"&&gateway.Requests.Skip(before).All(v=>!v.StartsWith("https://one.example.invalid/")),"subsequent lookups use only the selected gateways and retain sequence validation");
        bool invalid=false;try{ConnectionSettings.Normalize(new(){DirectMode=true,DiscoveryMode="pkarr",PkarrPublish=true,PkarrGateways=["http://insecure.example.invalid"]});}catch(FormatException){invalid=true;}
        Check(invalid,"network settings reject insecure PKARR gateway URLs");
        Check(PkarrClient.NormalizeGateways(["https://one.example.invalid/","https://one.example.invalid"]).Length==1,"equivalent gateway addresses are deduplicated");

        string sid=OperatingSystem.IsLinux()?LinuxPlatform.UserIdentity:WindowsIdentity.GetCurrent().User!.Value;
        using var reservation=new TcpListener(IPAddress.Loopback,0);reservation.Start();int port=((IPEndPoint)reservation.LocalEndpoint).Port;reservation.Stop();
        var localStore=new ProfileStore(Path.Combine(folder,"automatic-role"));
        localStore.Save(new(){Coordinator=new(false,$"http://127.0.0.1:{port}",TrustCloudflare:true)});localStore.AuthorizeUiUser(sid);
        using(var worker=new ControlWorker(localStore,enableWorkspace:true)){
            worker.StartLocal();
            try{
                UiStatusDto? state=null;
                for(int i=0;i<200;i++){state=(await worker.HandleUi(new("status"),sid,default)).Status;if(state?.Coordinator?.Running==true)break;await Task.Delay(25);}
                Check(state?.Coordinator is {Enabled:true,Running:true}&&localStore.LoadForMaintenance().CoordinatorRoleVersion==1,"the installed-host path enables and persists the independent role automatically");
                Check(localStore.LoadForMaintenance().Coordinator.ListenUrl==$"http://127.0.0.1:{port}"&&localStore.LoadForMaintenance().Coordinator.TrustCloudflare,"automatic role migration preserves configured listener and proxy trust");
                Check(state!.Networks.Length==0&&state.ServiceReady&&state.NetworkDefaults!.TcpStun.SequenceEqual(Stun.TcpServers),"providing discovery creates no network and supplies authoritative UI defaults");
            }finally{await worker.StopLocal();}
        }
        var off=localStore.Load();off.Coordinator=off.Coordinator with{Enabled=false};localStore.Save(off);
        using(var worker=new ControlWorker(localStore,enableWorkspace:true)){
            worker.StartLocal();try{await Task.Delay(100);Check((await worker.HandleUi(new("status"),sid,default)).Status?.Coordinator?.Enabled==false,"an explicit advanced maintenance disable is not undone by every restart");}finally{await worker.StopLocal();}
        }
        await ReleaseConfigurationLifecycle(Path.Combine(folder,"configuration-lifecycle"));
        Console.WriteLine($"PASS {checks} release discovery and coordinator provisioning checks; no public gateway or business traffic");
    }
    static async Task ReleaseConfigurationLifecycle(string folder)
    {
        string draftId="",lastId="";
        using(var node=new WorkspaceNode(folder,"Lifecycle")){
            var template=(await node.State()).Configurations.Single();
            var draft=await node.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Uncreated draft",Settings:template.Settings,Independent:true)));
            Check(draft.Ok,"an independent uncreated draft can be saved");draftId=draft.ConfigurationId;
            for(int i=0;i<34;i++){
                var saved=await node.Ui(new("configuration",OperationId:Guid.NewGuid(),Configuration:new("save",Name:"Cycle "+i,Settings:template.Settings,Independent:true)));
                if(!saved.Ok)throw new Exception("network-owned settings accumulated at cycle "+i+": "+saved.Error);
                var created=await node.Action("",new("create-direct"){Name="Cycle "+i,ConfigurationId=saved.ConfigurationId,LocalEnrollment=true});
                if(!created.Ok)throw new Exception(created.Error);
                lastId=saved.ConfigurationId;
                var removed=await node.Action(created.Status!.SelectedNetworkId,new("remove-network",ExpectedNetwork:created.Status.NetworkId,ConfirmReplace:true));
                if(!removed.Ok)throw new Exception(removed.Error);
                if(i>0&&removed.Status!.Configurations.Length>3)throw new Exception("removed independent settings leaked into the hidden catalog");
            }
            var state=await node.State();
            Check(state.Configurations.Any(c=>c.Id==draftId)&&state.Configurations.Any(c=>c.Id==template.Id),"repeated create and remove preserves unused drafts and explicit legacy templates");
            Check(state.Networks.Length==0&&state.Configurations.Length<=3,"more than thirty-two creation cycles cannot exhaust the hidden settings catalog");
            await node.Worker.StopLocal();
        }
        using(var node=new WorkspaceNode(folder,"Lifecycle",reuseProfile:true)){
            var state=await node.State();
            Check(state.Networks.Length==0&&!state.Configurations.Any(c=>c.Id==lastId)&&state.Configurations.Any(c=>c.Id==draftId),"restart reclaims the final removed network settings while retaining the uncreated draft");
            await node.Worker.StopLocal();
        }
    }
}
