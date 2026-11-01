using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

// Membership and signed endpoint announcements travel through authenticated
// direct links, never an HTTP service or a traffic relay. A joining device has
// the initial directory and owner ingress in its signed invitation.
public sealed class DirectMeshDiscovery : IMeshDiscovery
{
    const int Chunk=1200,Maximum=49152,Header=24;
    readonly MeshProfile profile;
    MeshDirectory directory;
    readonly Dictionary<int,MeshEnvelope> nodes=[];
    readonly Dictionary<int,Assembly> incoming=[];
    readonly Dictionary<int,Outbound> outgoing=[];
    readonly Dictionary<int,long> nextSend=[];
    MeshRouter? router;
    sealed class Assembly(Guid id,int length,long expires)
    {
        public readonly Guid Id=id;
        public readonly byte[] Data=new byte[length];
        public readonly bool[] Seen=new bool[(length+Chunk-1)/Chunk];
        public readonly long Expires=expires;
        public int Count;
    }
    sealed class Outbound(byte[][] frames,long expires)
    {
        public readonly byte[][] Frames=frames;
        public readonly long Expires=expires;
        public int Index;
    }
    public DirectMeshDiscovery(MeshProfile profile)
    {
        profile.Validate();if(!profile.Pair.Direct||profile.Directory==null)throw new IOException("直连网络缺少签名成员表");
        this.profile=profile;directory=profile.Directory;
    }
    public void Attach(MeshRouter value)=>router=value;
    public Task SaveDirectory(MeshDirectory value,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();MeshIdentity.ValidateDirectory(value,profile.Pair.Network,profile.OwnerKey,directory.Revision);
        if(value.Revision>directory.Revision){directory=value;nextSend.Clear();outgoing.Clear();}
        return Task.CompletedTask;
    }
    public Task Publish(MeshAnnouncement announcement,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();nodes[profile.Self.Slot]=MeshMetadata.Seal(profile,announcement);return Task.CompletedTask;
    }
    public Task<MeshSnapshot?> Read(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();return Task.FromResult<MeshSnapshot?>(new(directory,FreshNodes()));
    }
    MeshEnvelope[] FreshNodes()
    {
        var result=new List<MeshEnvelope>();
        foreach(var member in directory.Members)if(nodes.TryGetValue(member.Slot,out var envelope))
            try{MeshMetadata.Open(profile,member,envelope);result.Add(envelope);}catch(Exception ex)when(ex is FormatException or CryptographicException or JsonException){}
        return result.ToArray();
    }
    public void Tick(long now)
    {
        if(router==null)return;
        foreach(var slot in incoming.Where(p=>p.Value.Expires<now).Select(p=>p.Key).ToArray())incoming.Remove(slot);
        foreach(var frame in router.DrainSynchronization()) {
            if(!directory.Members.Any(m=>m.Slot==frame.Slot))continue;
            try {Receive(frame,now);}catch(Exception ex)when(ex is FormatException or CryptographicException or JsonException or ArgumentException) {incoming.Remove(frame.Slot);}
        }
        var live=directory.Members.Where(m=>m.Slot!=profile.Self.Slot).Select(m=>m.Slot).ToHashSet();
        foreach(var slot in outgoing.Keys.Where(s=>!live.Contains(s)).ToArray()){outgoing.Remove(slot);nextSend.Remove(slot);incoming.Remove(slot);nodes.Remove(slot);}
        foreach(int slot in live){
            if(!router.HasHealthyPath(slot)){outgoing.Remove(slot);nextSend.Remove(slot);continue;}
            if(outgoing.TryGetValue(slot,out var pending)&&pending.Expires<now){outgoing.Remove(slot);pending=null;}
            if(pending==null&&now>=nextSend.GetValueOrDefault(slot)){
                var data=JsonSerializer.SerializeToUtf8Bytes(new MeshSnapshot(directory,FreshNodes()));
                if(data.Length>Maximum)throw new IOException("直连成员同步超过大小限制");
                outgoing[slot]=pending=new(Split(data),now+10000);nextSend[slot]=now+10000;
            }
            if(pending!=null&&router.SendSynchronization(slot,pending.Frames[pending.Index])&&++pending.Index==pending.Frames.Length)outgoing.Remove(slot);
        }
    }
    static byte[][] Split(byte[] data)
    {
        var id=Guid.NewGuid();int count=(data.Length+Chunk-1)/Chunk;var result=new byte[count][];
        for(int i=0;i<count;i++){
            int size=Math.Min(Chunk,data.Length-i*Chunk);var frame=new byte[Header+size];id.TryWriteBytes(frame);
            BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(16),data.Length);BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(20),i);
            data.AsSpan(i*Chunk,size).CopyTo(frame.AsSpan(Header));result[i]=frame;
        }
        return result;
    }
    public static byte[][] DirectoryFrames(MeshDirectory directory)
    {
        var data=JsonSerializer.SerializeToUtf8Bytes(new MeshSnapshot(directory,[]));
        if(data.Length>Maximum)throw new FormatException("成员目录超出同步限制");
        return Split(data);
    }
    void Receive(MeshSyncFrame frame,long now)
    {
        var bytes=frame.Payload;var id=new Guid(bytes.AsSpan(0,16));int length=BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(16)),index=BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(20));
        if(id==Guid.Empty||length is <1 or >Maximum||index<0||index>=(length+Chunk-1)/Chunk||bytes.Length!=Header+Math.Min(Chunk,length-index*Chunk))return;
        if(!incoming.TryGetValue(frame.Slot,out var assembly)||assembly.Id!=id)incoming[frame.Slot]=assembly=new(id,length,now+10000);
        if(assembly.Data.Length!=length||assembly.Seen[index])return;
        bytes.AsSpan(Header).CopyTo(assembly.Data.AsSpan(index*Chunk));assembly.Seen[index]=true;
        if(++assembly.Count!=assembly.Seen.Length)return;
        incoming.Remove(frame.Slot);
        var snapshot=JsonSerializer.Deserialize<MeshSnapshot>(assembly.Data)??throw new FormatException("同步内容为空");
        if(snapshot.Directory==null||snapshot.Nodes is not {Length:<=8}||snapshot.Nodes.Any(n=>n==null))throw new FormatException("同步成员无效");
        MeshIdentity.ValidateDirectory(snapshot.Directory,profile.Pair.Network,profile.OwnerKey,directory.Revision);
        // Validate everything before installing a newer signed directory.
        var accepted=new List<MeshEnvelope>();
        foreach(var envelope in snapshot.Nodes){
            var member=snapshot.Directory.Members.FirstOrDefault(m=>m.Slot==envelope.Slot);
            if(member==null)continue;
            try{MeshMetadata.Open(profile,member,envelope);accepted.Add(envelope);}catch(Exception ex)when(ex is FormatException or CryptographicException or JsonException){}
        }
        if(snapshot.Directory.Revision>directory.Revision){directory=snapshot.Directory;nextSend.Clear();outgoing.Clear();}
        foreach(var envelope in accepted)if(envelope.Slot!=profile.Self.Slot&&envelope.Revision>(nodes.GetValueOrDefault(envelope.Slot)?.Revision??0))nodes[envelope.Slot]=envelope;
    }
    public void Dispose(){incoming.Clear();outgoing.Clear();nodes.Clear();router=null;}
}
