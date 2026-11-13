using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using StreamLink.Core;

namespace ConWU.Mobile;

public sealed record MobileNetwork(MeshProfile Mesh,UiNetworkSettings Settings,string BootstrapEndpoint)
{
    public bool Enabled {get;init;}=true;
    public string Id=>Mesh.Pair.Network;
    public string Name {get;init;}="";
    public string HostName {get;init;}="";
    public string HostIp=>MeshAddressing.Address(Mesh.Pair.Network,Mesh.Directory!.Members.Single(m=>m.Slot==Mesh.IntroducerSlot));
    public override string ToString()=>"MobileNetwork (credentials hidden)";
    public void Validate(string deviceId)
    {
        if(Mesh==null||Settings==null)throw new FormatException("保存的网络记录不完整");
        Mesh.Validate();
        if(Mesh.Directory?.Pairwise!=true||Mesh.IsOwner||Mesh.Self.Device!=deviceId||Mesh.Directory.Members.Length!=2)
            throw new FormatException("手机仅支持加入属于本设备的双机网络");
        MobileEnrollment.RequireProtocol(Mesh.Pair.Mode);
        if(Settings.PathSelection!=TransportModes.Policy(Mesh.Pair.Mode)||Settings.ConnectionSource is not ("existing" or "custom"))throw new FormatException("保存的主机配置与配对身份不符");
        ExistingEntryResolver.ParseEndpoint(BootstrapEndpoint);
    }
}
public sealed class MobileDeviceState
{
    [JsonRequired] public int Version {get;set;}=1;
    [JsonRequired] public string DeviceName {get;set;}="手机";
    [JsonRequired] public string SigningPrivate {get;set;}=NodeIdentityProof.GeneratePrivate();
    [JsonRequired] public MobileNetwork[] Networks {get;set;}=[];
    public string DeviceId=>MeshIdentity.NetworkId(MeshIdentity.PublicSigning(SigningPrivate));
    public void Validate()
    {
        if(Version!=1||DeviceName is not {Length:>0 and <=64}||DeviceName.Any(char.IsControl)||Networks is not {Length:<=8})throw new FormatException("手机配置无效或版本不受支持，原文件已保留");
        string device=DeviceId;
        foreach(var network in Networks){if(network==null)throw new FormatException("保存的网络记录为空");network.Validate(device);}
        if(Networks.Select(n=>n.Id).Distinct().Count()!=Networks.Length||Networks.SelectMany(n=>new[]{n.Mesh.LocalIp,n.HostIp}).Distinct().Count()!=Networks.Length*2)
            throw new FormatException("网络身份或虚拟 IP 冲突，不能合并到同一手机 VPN");
        if(Networks.Select(n=>MeshAddressing.Prefix(n.Mesh.LocalIp)).Distinct().Count()!=Networks.Length)throw new FormatException("多个网络虚拟网段冲突，请在主机重新分配地址");
    }
    public override string ToString()=>"MobileDeviceState (credentials hidden)";
}
public sealed record MobilePairingProgress(string State,string HostName="",string Verification="");

public static class MobileEnrollment
{
    public static void RequireProtocol(string mode)
    {
        if(mode is not ("tcp" or "https"))throw new NotSupportedException("手机首版支持 HTTPS 和纯 TCP。请在主机为手机创建相应协议的网络；现有 FakeTCP、Phantun、Mimic、TCPRAW 网络保持不变。");
    }
    public static async Task<MobileNetwork> Join(string code,string signingPrivate,string deviceName,
        Action<MobilePairingProgress> progress,CancellationToken token,
        Func<MeshProfile,IPEndPoint,IMeshTransport>? transportFactory=null)
    {
        var compact=CompactDirectCode.Import(code);RequireProtocol(compact.Mode);
        string deviceId=MeshIdentity.NetworkId(MeshIdentity.PublicSigning(signingPrivate));
        var temporary=MeshIdentity.Create("","",compact.Mode,direct:true);
        var parsed=ExistingEntryResolver.ParseEndpoint(compact.Endpoint);
        var target=new IPEndPoint(IPAddress.Parse(parsed.Host),parsed.Port);
        using var key=new PairKeyExchange(signingPrivate,receiveNetworkSettings:true);
        using var client=new DirectPairClient(_=>transportFactory?.Invoke(temporary,target)??new StreamMeshTransport(temporary,target,false,0,pairingBootstrap:true));
        progress(new("正在向主机申请加入"));
        PairRoomTicket? room=null;
        byte[]? shared=null;
        try{
            room=await client.Join(compact.RoomCode,key,deviceName,token);
            if(!NodeIdentityProof.Valid(room.Identity,room.HostCommitment))throw new CryptographicException("主机未提供有效设备身份，请更新主机后重新生成直连码");
            PairRoomState? previous=null;bool revealed=false;
            while(true){
                token.ThrowIfCancellationRequested();
                if(room.Expires<=DateTimeOffset.UtcNow.ToUnixTimeSeconds())throw new IOException("直连码已过期，请在主机重新生成");
                var state=await client.Poll(room,false,token);
                if(state.Outcome.Length>0)throw new IOException(state.Outcome=="Rejected"?"主机已拒绝本次加入申请":"配对会话已取消");
                PairKeyExchange.ValidateState(room,previous,state,key,false);previous=state;
                if(!revealed&&state.HostPublic.Length>0){
                    state=await client.Reveal(room,false,key,token);
                    PairKeyExchange.ValidateState(room,previous,state,key,false);previous=state;revealed=true;
                }
                if(shared==null&&state.HostPublic.Length>0&&state.GuestPublic.Length>0)shared=key.Derive(state.HostPublic,room.HostCommitment,room.Room,state.Candidate,false);
                progress(new(shared==null?"正在交换配对信息":"请核对双方校验码，等待主机批准",room.HostName,shared==null?"":PairKeyExchange.Verification(shared)));
                if(state.Approved&&shared!=null){
                    string plain=PairKeyExchange.DecryptInvitation(shared,state.Ciphertext,room.Room,state.Candidate,DirectPairWire.MaximumCipher);
                    var (mesh,_,approved)=NetworkEntryEnrollment.ImportSettings(plain);
                    if(mesh.Pair.Mode!=compact.Mode||mesh.Directory?.Pairwise!=true||mesh.Self.Device!=deviceId||mesh.IsOwner||
                        mesh.Directory.Members.Single(m=>m.Slot==mesh.IntroducerSlot).Device!=room.Identity!.DeviceId)
                        throw new CryptographicException("获准网络与本次配对的设备或协议不符");
                    if(compact.Mode=="https"&&(mesh.Pair.TransportKeyPin is not {Length:64} pin||!pin.Equals(client.PeerCertificatePin,StringComparison.OrdinalIgnoreCase)))
                        throw new CryptographicException("主机批准的证书与本次实际 HTTPS 连接不符，授权尚未保存");
                    if(approved==null)throw new IOException("主机未提供网络配置，请更新主机后重试");
                    var settings=approved.ForGuest(mesh,new());
                    var result=new MobileNetwork(mesh,settings,compact.Endpoint){Name=approved.NetworkName.Length>0?approved.NetworkName:room.HostName,HostName=room.HostName};
                    result.Validate(deviceId);progress(new("主机已批准，正在准备 VPN",room.HostName));return result;
                }
                await Task.Delay(650,token);
            }
        }finally{
            if(shared!=null)CryptographicOperations.ZeroMemory(shared);
            if(token.IsCancellationRequested&&room!=null){using var grace=new CancellationTokenSource(TimeSpan.FromSeconds(2));try{await client.Finish(room,false,grace.Token);}catch(Exception ex)when(ex is IOException or OperationCanceledException or ObjectDisposedException){} }
        }
    }
}
