using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StreamLink.Core;
using StreamLink.Discovery;
using StreamLink.Service;

internal static class EntryBackupTests
{
    public static async Task Run(Action<bool,string> check)
    {
        void Invalid(Action action,string name){try{action();throw new Exception(name);}catch(CryptographicException){check(true,name);}}
        var owner=MeshIdentity.Create("","","faketcp",direct:true,pairwise:true);
        using var key=new PairKeyExchange();using var directHost=new DirectPairHost();
        var ticket=await directHost.Create(key,"Host",default);
        var entry=EntryLookup.Sign(owner,ticket,["203.0.113.42:44680"]);
        var record=new EntryLookupRecord(owner.OwnerKey,owner.Self,entry);EntryLookup.Validate(record,ticket.Code);
        Invalid(()=>EntryLookup.Validate(record with{Entry=entry with{Endpoints=["203.0.113.43:44680"]}},ticket.Code),"backup address tampering is rejected");
        Invalid(()=>EntryLookup.Validate(record,ticket.Code,entry.Expires+1),"expired backup advertisement is rejected");
        Invalid(()=>EntryLookup.Validate(record,"not-a-code"),"lookup does not substitute another pairing code");
        var other=MeshIdentity.Create("","","faketcp",direct:true,pairwise:true);
        Invalid(()=>EntryLookup.Validate(record with{OwnerKey=other.OwnerKey},ticket.Code),"lookup identity is bound to the network owner");
        var plan=new ExistingCoordinatorPlan();
        check(plan.Select(["203.0.113.1:1"],["203.0.113.2:2"],false,1000)=="203.0.113.1:1"&&!plan.UsingBackup,"configured address is attempted first");
        check(plan.Select(["203.0.113.1:1"],["203.0.113.2:2"],false,13000)=="203.0.113.2:2"&&plan.UsingBackup,"address fallback starts after the primary attempt window");
        check(plan.Select(["203.0.113.1:1"],["203.0.113.2:2"],false,21000)=="203.0.113.1:1","primary address is retried when the backup is also unreachable");
        check(plan.Select(["203.0.113.1:1"],["203.0.113.2:2"],true,30000)=="","healthy direct path is not replaced");

        var fake=new Backup();bool needBackup=false;
        using(var direct=new DirectMeshDiscovery(owner)){
            direct.UseCoordinatorBackup(fake,()=>needBackup,_=>{});
            await direct.SaveDirectory(owner.Directory!,default);
            var node=new MeshAnnouncement(1,owner.Self.Device,1,DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"","Host",null){ExistingEndpoints=entry.Endpoints,ExistingEntryOnly=true};
            await direct.Publish(node,default);await direct.Read(default);
            check(fake.Publishes==1&&fake.Reads==0,"backup receives current addresses but is not queried while the primary is healthy");
            needBackup=true;await direct.Read(default);check(fake.Reads==1,"failed primary allows coordinator lookup");
            needBackup=false;await direct.Read(default);check(fake.Reads==1,"recovered primary stops coordinator reads");
            fake.Fail=true;needBackup=true;await direct.Publish(node with{Revision=2},default);await direct.Read(default);
            check(direct.Synchronization.Read()!=null,"backup outage does not disable primary metadata");
        }
        check(fake.Disposed,"backup client lifetime follows the direct discovery owner");

        string root=Path.Combine(Path.GetTempPath(),"conwu-entry-backup-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        using var signing=RSA.Create(2048);
        var certRequest=new CertificateRequest("CN=localhost",signing,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var cert=certRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1));
        string certFile=Path.Combine(root,"cert.pem"),keyFile=Path.Combine(root,"key.pem");
        File.WriteAllText(certFile,cert.ExportCertificatePem());File.WriteAllText(keyFile,signing.ExportPkcs8PrivateKeyPem());
        await using var host=CoordinationHost.Create(new(root,"https://127.0.0.1:0",certFile,keyFile));await host.Start();
        string url=host.Addresses.Single()+"/",pin=Convert.ToHexString(SHA256.HashData(cert.RawData));
        using var client=new EntryLookupClient(url,pin);await client.Publish(owner,entry,default);
        var found=await client.Find(ticket.Code,default);check(found==record||found?.Entry.Signature==entry.Signature,"HTTPS backup returns the matching signed host advertisement");
        using var http=new HttpClient(new HttpClientHandler{ServerCertificateCustomValidationCallback=(_,c,_,_)=>c!=null&&Convert.ToHexString(SHA256.HashData(c.RawData))==pin}){BaseAddress=new(url)};
        using(var unauthorized=await http.PutAsJsonAsync($"v3/mesh/{owner.Pair.Network}/entry",entry))check(unauthorized.StatusCode==HttpStatusCode.Unauthorized,"unauthenticated address updates are rejected");
        using(var bad=new HttpRequestMessage(HttpMethod.Put,$"v3/mesh/{owner.Pair.Network}/entry"){Content=JsonContent.Create(entry with{Endpoints=["203.0.113.9:9"]})}){
            bad.Headers.Authorization=new("Bearer",owner.Pair.Auth);using var result=await http.SendAsync(bad);check(result.StatusCode==HttpStatusCode.BadRequest,"server verifies the address signature before storing");
        }
        try{await client.Publish(other,EntryLookup.Sign(other,ticket,["203.0.113.45:44680"]),default);throw new Exception("collision accepted");}catch(HttpRequestException ex){check(ex.StatusCode==HttpStatusCode.Conflict,"another network cannot overwrite a live short-code mapping");}
        var guest=MeshIdentity.Import(MeshIdentity.Export(MeshIdentity.Issue(owner)));
        using var publish=new MeshDiscoveryClient(owner,url,pin);using var receive=new MeshDiscoveryClient(guest,url,pin);
        await publish.SaveDirectory(owner.Directory!,default);
        await publish.Publish(new(1,owner.Self.Device,10,DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds(),"","Host",null){ExistingEndpoints=["203.0.113.46:44680"],ExistingEntryOnly=true},default);
        var snapshot=await receive.Read(default);var remote=MeshMetadata.Open(guest,owner.Self,snapshot!.Nodes.Single());
        check(remote.ExistingEndpoints!.Single()=="203.0.113.46:44680"&&guest.Pair.Direct&&guest.Pair.Service=="","paired backup metadata is encrypted/authenticated without changing the direct network identity");
    }
    sealed class Backup:IMeshDiscovery
    {
        public int Reads,Publishes;public bool Fail,Disposed;
        public Task SaveDirectory(MeshDirectory d,CancellationToken t)=>Fail?Task.FromException(new IOException("offline")):Task.CompletedTask;
        public Task Publish(MeshAnnouncement a,CancellationToken t){Publishes++;return Fail?Task.FromException(new IOException("offline")):Task.CompletedTask;}
        public Task<MeshSnapshot?> Read(CancellationToken t){Reads++;return Fail?Task.FromException<MeshSnapshot?>(new IOException("offline")):Task.FromResult<MeshSnapshot?>(null);}
        public void Dispose()=>Disposed=true;
    }
}
