using StreamLink.Core;

namespace StreamLink.Service;

public sealed partial class ControlWorker
{
    readonly DirectPairHost entryAdmissionHost=new(entryAdmission:true);
    PairKeyExchange? entryAdmissionKey;
    PairRoomTicket? entryAdmissionRoom;
    string entryAdmissionNetwork="";
    CancellationTokenSource? entryAdmissionStop;
    Task? acceptingEntries;
    bool uiEntryAdmission;
    ExistingEntry[] uiEntrySources=[];

    byte[]? HandleDirectPairing(ReadOnlyMemory<byte> packet)
    {
        DirectPairRequest request;
        try{request=DirectPairWire.Decode<DirectPairRequest>(packet.Span);}catch{return null;}
        return (request.EntryAdmission?entryAdmissionHost:uiDirectHost).Handle(packet);
    }
    void StartEntryAdmission()
    {
        if(acceptingEntries is {IsCompleted:false})return;
        entryAdmissionStop?.Dispose();entryAdmissionStop=CancellationTokenSource.CreateLinkedTokenSource(disposing.Token);
        acceptingEntries=Task.Run(()=>RunEntryAdmission(entryAdmissionStop.Token),CancellationToken.None);
    }
    void ClearEntryAdmission()
    {
        entryAdmissionHost.Clear();entryAdmissionKey?.Dispose();entryAdmissionKey=null;
        entryAdmissionRoom=null;entryAdmissionNetwork="";
    }
    async Task RunEntryAdmission(CancellationToken token)
    {
        long nextError=0;
        try{
            while(!token.IsCancellationRequested){
                // Passive local observation must never queue ahead of a user's
                // save/leave/approve operation. An idle explicit room has only
                // the existing bounded cleanup before yielding to this request.
                if(await requests.WaitAsync(0,token)){
                    try{
                        MeshProfile? mesh;bool enabled;string name;
                        lock(sync){mesh=profile.Mesh;enabled=profile.Enabled;name=profile.DeviceName;}
                        if(!enabled||mesh?.CanManage!=true||mesh.Directory?.Closed==true){
                            if(uiPairClient==entryAdmissionHost)ResetUiPair("本机不再接收入网申请");
                            ClearEntryAdmission();
                        }else{
                            if(entryAdmissionNetwork!=mesh.Pair.Network){ClearEntryAdmission();entryAdmissionNetwork=mesh.Pair.Network;}
                            if(uiPairClient is DirectPairHost&&uiPairOwner){await PollUiPair(null,token);}
                            if(uiPairClient!=entryAdmissionHost){
                                if((entryAdmissionRoom==null||entryAdmissionRoom.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds())&&entryAdmissionHost.CanCreate){
                                    entryAdmissionKey?.Dispose();entryAdmissionKey=new();
                                    try{entryAdmissionRoom=await entryAdmissionHost.Create(entryAdmissionKey,name,token);}
                                    catch(IOException){entryAdmissionKey.Dispose();entryAdmissionKey=null;entryAdmissionRoom=null;}
                                }
                                if(entryAdmissionRoom!=null){
                                    var pending=await entryAdmissionHost.Poll(entryAdmissionRoom,true,token);
                                    if(pending.Candidate.Length>0&&(uiRoom==null||uiPairOwner&&uiRoomState?.Candidate.Length is not >0)){
                                        // Leave an explicit in-flight request intact. An idle
                                        // manually generated code yields to the arriving device.
                                        await CloseUiPair(token);
                                        uiPairOwner=true;uiEntryAdmission=true;uiPairService=uiPairPin="";
                                        uiExpectedNetwork=mesh.Pair.Network;uiRejoinLocator=DirectPairWire.EntryLocator;
                                        uiPairClient=entryAdmissionHost;uiPairKey=entryAdmissionKey;uiRoom=entryAdmissionRoom;
                                        entryAdmissionKey=null;entryAdmissionRoom=null;
                                        await PollUiPair(null,token);
                                    }
                                }
                            }
                        }
                    }catch(OperationCanceledException)when(token.IsCancellationRequested){throw;}
                    catch(Exception ex){if(Environment.TickCount64>=nextError){nextError=Environment.TickCount64+15000;Log("入口申请状态暂未更新："+ex.GetType().Name);}}
                    finally{requests.Release();}
                }
                await Task.Delay(250,token);
            }
        }catch(OperationCanceledException)when(token.IsCancellationRequested){}
        finally{ClearEntryAdmission();}
    }
    async Task StopEntryAdmission()
    {
        entryAdmissionStop?.Cancel();
        try{if(acceptingEntries!=null)await acceptingEntries;}
        finally{acceptingEntries=null;entryAdmissionStop?.Dispose();entryAdmissionStop=null;}
    }
    ExistingEntry[] ApprovalEntryHints(MeshProfile mesh)=>profile.ExistingEntries.Where(e=>e.PeerSlot==0)
        .Select(e=>e with{PeerSlot=mesh.Self.Slot}).Distinct().ToArray();

    async Task JoinUiEntry(UiNetworkAction action,Operation operation)
    {
        RequireUiNetwork(action.ExpectedNetwork);
        if(profile.Mesh!=null||profile.Pair!=null)throw new IOException("请先退出当前网络，再申请加入");
        if(action.Entry is not {Length:>0 and <=2048}||action.Entry.Any(char.IsControl))throw new FormatException("请填写一个有效的设备地址或订阅链接");
        if(action.Mode is not ("faketcp" or "udp"))throw new FormatException("网络承载无效");
        RequireSavedProtocol(action.Mode);
        var sources=new[]{new ExistingEntry(ExistingEntry.Network,action.Entry.Trim())};
        ExistingEntryResolver.Validate(sources);
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(operation.Stop.Token);deadline.CancelAfter(60000);
        SetOperation(operation,"解析设备入口",true);
        var resolved=await uiEntryResolver.Value.Resolve(sources,action.Mode,deadline.Token);
        var endpoints=resolved.SelectMany(r=>r.Endpoints).Distinct().Take(8).ToArray();
        if(endpoints.Length==0)throw new IOException("未取得可用入口。"+string.Join("；",resolved.Select(r=>r.Error).Where(e=>e.Length>0).Distinct().Take(2)));
        await CloseUiPair(operation.Stop.Token);
        uiPairOwner=false;uiEntryAdmission=true;uiPairService=uiPairPin="";uiExpectedNetwork=action.ExpectedNetwork;
        uiPairKey=new();uiEntrySources=sources;
        var temporary=MeshIdentity.Create("","",action.Mode,direct:true);
        var folder=Path.Combine(ProfileStore.Root,"sessions","entry-pair-"+Guid.NewGuid().ToString("N"));
        try{
            IOException? last=null;
            for(int index=0;index<endpoints.Length;index++){
                SetOperation(operation,$"联系入口（{index+1}/{endpoints.Length}），等待设备回应",true);
                using var attempt=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);attempt.CancelAfter(endpoints.Length>1?6000:12000);
                uiPairClient=new DirectPairClient(local=>(meshRuntime??MeshRuntimeServices.Default).Transport(new(folder,temporary,System.Net.IPEndPoint.Parse(endpoints[index]),false,0,null,"error")),entryAdmission:true);
                try{
                    uiExpectedRejoin=MeshRejoin.Create(profile.RejoinCredential,DirectPairWire.EntryLocator,uiPairKey);
                    uiRoom=await uiPairClient.Join(DirectPairWire.EntryLocator,uiPairKey,profile.DeviceName,attempt.Token,profile.RequestedVirtualIp,uiExpectedRejoin);
                    PairSnapshot("申请已送达，等待设备同意；请核对双方校验码");return;
                }catch(OperationCanceledException)when(!deadline.IsCancellationRequested){last=new IOException("入口未及时回应，请确认设备已创建网络并使用相同协议");}
                catch(IOException ex){last=ex;}
                uiPairClient.Dispose();uiPairClient=null;
            }
            throw last??new IOException("入口未回应，请检查地址是否通向对方 ConWU 接收端口");
        }catch(OperationCanceledException)when(!operation.Stop.IsCancellationRequested){ResetUiPair("入口联系超时");throw new IOException("设备入口未及时回应；请检查对方是否在线、地址是否可达以及双方协议是否相同");}
        catch{ResetUiPair("加入申请未完成");throw;}
    }
}
