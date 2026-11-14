using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed record NetworkDepartureDelivery(NetworkDeparture Notice,string Owner,string Name,string Mode,string Pin,ExistingEntry[] Sources,string[] Endpoints,MeshProfile? Discovery,string[] PkarrGateways)
{
    public static NetworkDepartureDelivery Create(DeviceProfile profile,string name,string[] endpoints)
    {
        var mesh=profile.Mesh??throw new IOException("网络尚未配对");
        var entries=MeshRunner.EntrySources(profile,mesh).Where(e=>e.PeerSlot==mesh.IntroducerSlot||e.PeerSlot==ExistingEntry.NetworkOwner||e.PeerSlot==ExistingEntry.Network)
            .Concat(profile.JoinedEntrySources.Select(e=>e with{PeerSlot=mesh.IntroducerSlot})).Distinct().Take(12).ToArray();
        return new(NetworkDeparture.Create(mesh),mesh.OwnerKey,name,profile.TransportMode,mesh.Pair.TransportKeyPin??"",entries,endpoints,
            mesh.Pair.Direct?null:ProfileChanges.Copy(profile).Mesh,profile.SavedNetworkSettings?.PkarrGateways??[]);
    }
    public static async Task Deliver(NetworkDepartureDelivery item,string root,MeshRuntimeServices runtime,CancellationToken token)
    {
        item.Notice.Validate(item.Owner);
        var candidates=new List<string>();
        if(item.Sources.Length>0){
            using var resolver=new ExistingEntryResolver(()=>new PkarrClient(gateways:item.PkarrGateways));
            using var lookup=CancellationTokenSource.CreateLinkedTokenSource(token);lookup.CancelAfter(3500);
            try{var resolved=runtime.ResolveEntries is {} resolve?await resolve(item.Sources,item.Mode,lookup.Token):await resolver.ResolveRecovering(item.Sources,item.Mode,lookup.Token);candidates.AddRange(resolved.SelectMany(r=>r.Endpoints));}
            catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or HttpRequestException or OperationCanceledException or FormatException){}
        }
        if(item.Discovery is {} mesh){
            using var discovery=new MeshDiscoveryClient(mesh);
            using var lookup=CancellationTokenSource.CreateLinkedTokenSource(token);lookup.CancelAfter(2000);
            try{if(await discovery.Read(lookup.Token) is {} state){var host=state.Directory.Members.FirstOrDefault(m=>m.Slot==mesh.IntroducerSlot);if(host!=null)foreach(var envelope in state.Nodes.Where(n=>n.Slot==host.Slot)){var node=MeshMetadata.Open(mesh,host,envelope);candidates.AddRange(node.ExistingEndpoints??[]);if(node.Endpoint.Length>0)candidates.Add(node.Endpoint);}}}
            catch(Exception error)when(!token.IsCancellationRequested&&error is IOException or HttpRequestException or OperationCanceledException or System.Security.Cryptography.CryptographicException){}
        }
        candidates.AddRange(item.Endpoints);
        if(candidates.Count==0)throw new IOException("退出通知暂未取得主机入口");
        var temporary=MeshIdentity.Create("","",item.Mode,direct:true);
        if(item.Pin.Length>0)temporary.Pair=temporary.Pair with{TransportKeyPin=item.Pin};
        string folder=Path.Combine(root,"departure-delivery",item.Notice.Nonce);
        foreach(string endpoint in candidates.Distinct().Take(8)){
            token.ThrowIfCancellationRequested();
            if(!IPEndPoint.TryParse(endpoint,out var remote))continue;
            using var attempt=CancellationTokenSource.CreateLinkedTokenSource(token);attempt.CancelAfter(4500);
            try{
                using var client=new DirectPairClient(_=>runtime.Transport(new(folder,temporary,remote,false,0,null,"error"){PairingBootstrap=true}),targetNetwork:item.Notice.Network);
                await client.Depart(item.Notice,item.Owner,attempt.Token);return;
            }catch(Exception)when(!token.IsCancellationRequested){}
        }
        throw new IOException("退出通知暂未得到主机确认");
    }
    public override string ToString()=>"NetworkDepartureDelivery (credentials hidden)";
}
