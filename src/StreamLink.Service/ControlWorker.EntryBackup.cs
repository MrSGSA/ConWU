using System.Net;
using System.Security.Cryptography;
using StreamLink.Core;

namespace StreamLink.Service;
public sealed partial class ControlWorker
{
    EntryBackupPublisher? entryBackupPublisher;
    readonly List<Task> retiredEntryPublishers=[];
    EntryLookupRecord? uiBackupExpected;
    void StopEntryBackupPublication()
    {
        if(entryBackupPublisher is {} prior){entryBackupPublisher=null;prior.Dispose();retiredEntryPublishers.RemoveAll(t=>t.IsCompleted);retiredEntryPublishers.Add(prior.Completion);}
    }
    void StartEntryBackupPublication(PairRoomTicket ticket)
    {
        StopEntryBackupPublication();var settings=PublicSettings(profile);
        if(profile.Mesh is {IsOwner:true,Pair.Direct:true}){
            var pairing=ConnectionSettings.PairingCoordinator(settings);
            if(profile.UsesExistingEntriesOnly&&pairing.Service.Length>0)settings=settings with{Service=pairing.Service,CertificatePin=pairing.Pin,CoordinatorBackup=true};
            if(settings.CoordinatorBackup)entryBackupPublisher=new(ProfileChanges.Copy(profile).Mesh!,ticket,settings,profile.TransportMode,Log,disposing.Token);
        }
    }
    async Task JoinUiDirectShort(UiNetworkAction action,Operation operation)
    {
        var token=operation.Stop.Token;RequireUiNetwork(action.ExpectedNetwork);
        if((profile.Mesh!=null||profile.Pair!=null)&&!action.ConfirmReplace)throw new IOException("替换网络需要明确确认");
        if(action.Mode is not ("faketcp" or "udp"))throw new FormatException("网络承载无效");
        RequireSavedProtocol(action.Mode);
        var settings=PublicSettings(profile);
        var entries=settings.ExistingEntries.Where(e=>e.PeerSlot is ExistingEntry.Network or ExistingEntry.NetworkOwner||e.PeerSlot==1&&profile.Mesh?.IsOwner!=true).ToArray();
        if(entries.Length==0&&!settings.CoordinatorBackup)throw new IOException("短配对码需要目标主机入口，请先在设置中填写；也可启用备用协调查询主机入口");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);deadline.CancelAfter(settings.CoordinatorBackup?55000:30000);
        await CloseUiPair(token);uiPairOwner=false;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;uiPairKey=new(profile.NodeSigningPrivate,profile.AutoConfigureJoin);
        var temporary=MeshIdentity.Create("","",action.Mode,direct:true);
        var folder=Path.Combine(store.DirectoryPath,"sessions","pair-"+Guid.NewGuid().ToString("N"));
        Exception? last=null;
        async Task<bool> TryEndpoints(string[] endpoints,CancellationToken budget,EntryLookupRecord? expected=null)
        {
            foreach(var endpoint in endpoints){
                budget.ThrowIfCancellationRequested();
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(budget);attempt.CancelAfter(endpoints.Length==1?12000:4000);
                SetOperation(operation,expected==null?"检查已配置入口，匹配配对码":"验证备用协调提供的主机入口，匹配设备身份",true);
                var client=new DirectPairClient(local=>(meshRuntime??MeshRuntimeServices.Default).Transport(new(folder,temporary,IPEndPoint.Parse(endpoint),false,0,null,"error")),targetNetwork:expected?.Entry.Network??"");
                try{
                    uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,action.Code,uiPairKey);
                    var ticket=await client.Join(action.Code,uiPairKey,profile.DeviceName,attempt.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    if(expected!=null&&(ticket.HostCommitment!=expected.Entry.HostCommitment||ticket.Identity?.DeviceId!=expected.Host.Device))throw new CryptographicException("备用入口的配对会话或主机身份不符");
                    uiPairClient=client;uiRoom=ticket;uiBackupExpected=expected;return true;
                }catch(Exception ex)when(!token.IsCancellationRequested&&ex is IOException or OperationCanceledException){last=ex;client.Dispose();}
                catch{client.Dispose();throw;}
            }
            return false;
        }
        try{
            bool joined=false;
            using(var primary=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token)){
                if(settings.CoordinatorBackup)primary.CancelAfter(20000);
                try{
                    SetOperation(operation,"解析已配置的主机入口",true);
                    var resolved=await uiEntryResolver.Value.Resolve(entries,action.Mode,primary.Token);
                    joined=await TryEndpoints(resolved.SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray(),primary.Token);
                }catch(Exception ex)when(settings.CoordinatorBackup&&!token.IsCancellationRequested&&ex is IOException or OperationCanceledException){last=ex;}
            }
            if(!joined&&settings.CoordinatorBackup){
                SetOperation(operation,"已配置入口未完成配对，向备用协调查询主机最新地址",true);
                Log("主机入口未完成配对，正在查询备用协调；只获取地址，不启动自主打洞");
                using var lookup=new EntryLookupClient(settings.Service,settings.CertificatePin);
                EntryLookupRecord? found=null;
                for(int query=0;query<16&&found==null;query++){
                    if(query>0)await Task.Delay(Math.Min(1000,500*query),deadline.Token);
                    SetOperation(operation,$"等待配对协调登记主机入口（{query+1}/16）",true);
                    found=await lookup.Find(action.Code,deadline.Token);
                }
                if(found==null)throw new IOException("备用协调没有此配对码的有效主机入口，请确认主机也已启用备用协调并重新生成配对码");
                joined=await TryEndpoints(found.Entry.Endpoints,deadline.Token,found);
                if(!joined)throw new IOException("备用协调已返回地址，但主机入口仍未通过双向认证；请检查映射、协议和目标是否在线",last);
            }
            if(!joined)throw new IOException("主机入口未回应，请检查地址、协议和目标是否在线",last);
            PairSnapshot("正在等待主机同意，请核对双方校验码");
        }catch(OperationCanceledException)when(!token.IsCancellationRequested){ResetUiPair("主机入口配对超时");throw new IOException("主机入口验证超时，请查看入口与备用协调状态后重试");}
        catch{ResetUiPair("主机入口配对未完成");throw;}
    }
}
