using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace StreamLink.Core;

public sealed record MeshMutation(string Id, string Parent, int Actor, string Action, int Target, MeshMember? Added, string Signature);
public sealed record MeshHistory(MeshDirectory Genesis, string Authorization, MeshMutation[] Changes);

// Equal authorized members sign with their own device keys. The retained
// coordinator serializes edits by compare-and-set; it cannot grant membership.
// Complete signed history allows every replica to verify authorization without
// trusting a server signature or sharing the creator's private key.
public static class MeshGovernance
{
    public const int MaximumChanges = 512, MaximumProofBytes = 524288, MaximumDirectoryBytes = 786432;
    public const int MaximumTicket = 1048576, MaximumCipher = 1500000;
    static readonly object cacheGate = new();
    static readonly HashSet<string> verified = [];
    static readonly Queue<string> cacheOrder = [];
    static readonly Dictionary<string,byte[]> replayCache=[];
    static readonly Queue<string> replayOrder=[];
    static byte[] Data(object value) => JsonSerializer.SerializeToUtf8Bytes(value);
    static string Digest(object value) => Convert.ToHexString(SHA256.HashData(Data(value)));
    static byte[] Authorization(MeshDirectory genesis) => Data(new { domain = "streamlink-equal-members-v1", genesis.Network, genesis.OwnerKey, genesis = Digest(genesis) });
    static byte[] MutationData(string network, MeshMutation value) => Data(new { domain = "streamlink-membership-change-v1", network, value.Id, value.Parent, value.Actor, value.Action, value.Target, value.Added });
    static string Anchor(MeshHistory history) => Digest(new { history.Genesis, history.Authorization });
    public static string Head(MeshDirectory directory)
    {
        if (directory.Governance == null) return Digest(directory);
        var history = Unpack(directory.Governance);
        return history.Changes.Length == 0 ? Anchor(history) : Digest(history.Changes[^1]);
    }
    public static string Pack(MeshHistory history)
    {
        byte[] bytes = Data(history);
        if (bytes.Length > MaximumProofBytes) throw new IOException("网络授权历史已达到容量上限，请导出配置并新建网络");
        using var output = new MemoryStream();
        using (var writer = new BrotliStream(output, CompressionLevel.SmallestSize, true)) writer.Write(bytes);
        return Convert.ToBase64String(output.ToArray());
    }
    public static MeshHistory Unpack(string proof)
    {
        if (proof is not { Length: > 0 and <= MaximumDirectoryBytes }) throw new CryptographicException("网络授权证明长度无效");
        try {
            using var input = new MemoryStream(Convert.FromBase64String(proof));
            using var reader = new BrotliStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192]; int read;
            while ((read = reader.Read(buffer)) > 0) {
                if (output.Length + read > MaximumProofBytes) throw new CryptographicException("网络授权证明超出限制");
                output.Write(buffer, 0, read);
            }
            var history = JsonSerializer.Deserialize<MeshHistory>(output.ToArray()) ?? throw new CryptographicException("网络授权证明为空");
            if (history.Genesis == null || history.Genesis.Governance != null || history.Genesis.Closed || history.Changes is not { Length: <= MaximumChanges } || history.Changes.Any(c => c == null))
                throw new CryptographicException("网络授权历史结构无效");
            return history;
        } catch (Exception ex) when (ex is InvalidDataException or FormatException or JsonException or ArgumentException) { throw new CryptographicException("网络授权证明无效", ex); }
    }
    public static void Enable(MeshProfile profile)
    {
        profile.Validate();
        if(profile.Directory?.Pairwise==true)throw new IOException("双机网络不启用成员平等管理");
        if (profile.IsDecentralized) return;
        if (!profile.IsOwner || profile.Pair.Direct || profile.Directory == null) throw new IOException("请由原创建者在协调网络中启用成员平等管理");
        var genesis = profile.Directory;
        var history = new MeshHistory(genesis, MeshIdentity.Sign(profile.OwnerPrivate, Authorization(genesis)), []);
        profile.Directory = Replay(history) with { Governance = Pack(history) };
    }
    public static MeshDirectory Change(MeshProfile profile, string action, int target = 0, MeshMember? added = null)
    {
        profile.Validate();
        if (!profile.IsDecentralized || !profile.CanManage) throw new IOException("本机不是当前网络的有效成员");
        var history = Unpack(profile.Directory!.Governance!);
        if (history.Changes.Length >= MaximumChanges) throw new IOException("网络授权历史已达到容量上限，请新建网络");
        var change = new MeshMutation(Guid.NewGuid().ToString("N"), Head(profile.Directory), profile.Self.Slot, action, target, added, "");
        change = change with { Signature = MeshIdentity.Sign(profile.SigningPrivate, MutationData(profile.Pair.Network, change)) };
        history = history with { Changes = [..history.Changes, change] };
        return Replay(history) with { Governance = Pack(history) };
    }
    static MeshDirectory Replay(MeshHistory history)
    {
        // Cache immutable serialized replay results by the entire history hash.
        // A head-only cache could accept tampered prefixes; never use one here.
        string key=Digest(history);byte[]? cached;MeshDirectory? prefix=null;
        lock(cacheGate)replayCache.TryGetValue(key,out cached);
        if(cached!=null)return JsonSerializer.Deserialize<MeshDirectory>(cached)!;
        if(history.Changes.Length>0){
            string parent=Digest(history with{Changes=history.Changes[..^1]});
            lock(cacheGate)replayCache.TryGetValue(parent,out cached);
            if(cached!=null)prefix=JsonSerializer.Deserialize<MeshDirectory>(cached)!;
        }
        var result=ReplayRemaining(history,prefix);
        lock(cacheGate){
            if(replayCache.TryAdd(key,Data(result)))replayOrder.Enqueue(key);
            while(replayOrder.Count>64)replayCache.Remove(replayOrder.Dequeue());
        }
        return result;
    }
    static MeshDirectory ReplayRemaining(MeshHistory history,MeshDirectory? validatedPrefix)
    {
        var genesis = history.Genesis;
        MeshIdentity.ValidateDirectory(genesis, genesis.Network, genesis.OwnerKey);
        if (!MeshIdentity.Verify(genesis.OwnerKey, Authorization(genesis), history.Authorization)) throw new CryptographicException("成员平等管理未获得原网络授权");
        var initial=validatedPrefix??genesis;
        var members = initial.Members.ToDictionary(m => m.Slot);
        var reserved = new HashSet<string>(initial.ReservedAddresses ?? Enumerable.Range(1, initial.NextSlot - 1).Select(i => MeshIdentity.Address(genesis.Network, i)));
        foreach (var member in members.Values) reserved.Add(MeshAddressing.Address(genesis.Network, member));
        string prefix = MeshAddressing.Prefix(MeshAddressing.Address(genesis.Network, genesis.Members[0]));
        int nextSlot = initial.NextSlot; bool closed = initial.Closed;
        int start=validatedPrefix==null?0:history.Changes.Length-1;
        string head = start==0?Anchor(history):Digest(history.Changes[start-1]), signature = validatedPrefix?.Signature??history.Authorization;
        var ids = history.Changes.Take(start).Select(c=>c.Id).ToHashSet();
        int index=start;
        foreach (var change in history.Changes.Skip(start)) {
            if (closed || !Guid.TryParseExact(change.Id, "N", out _) || !ids.Add(change.Id) || change.Parent != head || !members.TryGetValue(change.Actor, out var actor) ||
                !MeshIdentity.Verify(actor.SigningKey, MutationData(genesis.Network, change), change.Signature)) throw new CryptographicException("网络变更签名、授权或顺序无效");
            if (change.Action is "add" or "replace" or "readmit") {
                MeshMember? previous = null;
                if (change.Action == "replace") {
                    if (change.Target == actor.Slot || !members.TryGetValue(change.Target, out previous)) throw new CryptographicException("被替换成员无效");
                } else if(change.Action=="readmit"){
                    previous=ReleasedMember(history,change.Target,index);
                    if(previous==null||members.ContainsKey(change.Target)||change.Target==actor.Slot)throw new CryptographicException("重新加入的旧身份并非主动退出");
                } else if (change.Target != 0) throw new CryptographicException("加入目标无效");
                var added = change.Added ?? throw new CryptographicException("新成员为空");
                MeshIdentity.ValidateMemberKeys(added);
                if (added.Slot != nextSlot || nextSlot > 254 || members.Values.Any(m => m.Device == added.Device) ||
                    !MeshIdentity.Verify(actor.SigningKey, MeshIdentity.MemberData(genesis.Network, added), added.Signature)) throw new CryptographicException("新成员授权无效");
                string ip = MeshAddressing.Address(genesis.Network, added);
                if (MeshAddressing.Prefix(ip) != prefix || reserved.Contains(ip) && (previous == null || ip != MeshAddressing.Address(genesis.Network, previous))) throw new CryptographicException("成员地址冲突或网段不符");
                if (previous != null) members.Remove(previous.Slot);
                if (members.Count >= MeshIdentity.MaxMembers) throw new CryptographicException("网络成员已满");
                members.Add(added.Slot, added); reserved.Add(ip); nextSlot++;
            } else {
                if (change.Added != null) throw new CryptographicException("网络变更包含无关成员");
                switch (change.Action) {
                    case "remove":
                        if (change.Target == actor.Slot || !members.Remove(change.Target)) throw new CryptographicException("移除目标无效");
                        break;
                    case "leave":
                        if (change.Target != actor.Slot) throw new CryptographicException("只能退出本机成员身份");
                        members.Remove(actor.Slot); closed = members.Count == 0;
                        break;
                    case "close":
                        if (change.Target != 0) throw new CryptographicException("解散目标无效");
                        members.Clear(); closed = true;
                        break;
                    default: throw new CryptographicException("未知网络变更");
                }
            }
            head = Digest(change); signature = change.Signature;index++;
        }
        return new(genesis.Network, genesis.OwnerKey, checked(genesis.Revision + 1 + history.Changes.Length), nextSlot, members.Values.OrderBy(m => m.Slot).ToArray(), signature) {
            ReservedAddresses = reserved.Order().ToArray(), Closed = closed
        };
    }
    public static void Validate(MeshDirectory directory, string network, string owner, long minimumRevision)
    {
        if (directory.Network != network || directory.OwnerKey != owner || directory.Revision < Math.Max(1, minimumRevision) || directory.Governance == null)
            throw new CryptographicException("网络授权身份无效或已回退");
        byte[] data = Data(directory);
        if (data.Length > MaximumDirectoryBytes) throw new CryptographicException("成员目录超过上限");
        string key = Convert.ToHexString(SHA256.HashData(data));
        lock (cacheGate) if (verified.Contains(key)) return;
        var expected = Replay(Unpack(directory.Governance));
        if (!Data(expected).AsSpan().SequenceEqual(Data(directory with { Governance = null }))) throw new CryptographicException("成员表与授权历史不一致");
        lock (cacheGate) {
            if (verified.Add(key)) cacheOrder.Enqueue(key);
            while (cacheOrder.Count > 64) verified.Remove(cacheOrder.Dequeue());
        }
    }
    public static bool ContainsCredential(MeshDirectory directory, MeshMember member)
    {
        Validate(directory, directory.Network, directory.OwnerKey, 0);
        var history = Unpack(directory.Governance!);
        return history.Genesis.Members.Contains(member) || history.Changes.Any(c => c.Added == member);
    }
    public static (MeshMember Former,MeshMember Current)? RejoinLineage(MeshDirectory directory,int slot,string device)
    {
        Validate(directory,directory.Network,directory.OwnerKey,0);
        var history=Unpack(directory.Governance!);
        var former=history.Genesis.Members.Concat(history.Changes.Where(c=>c.Added!=null).Select(c=>c.Added!))
            .FirstOrDefault(m=>m.Slot==slot&&m.Device==device);
        if(former==null)return null;
        var current=former;bool left=false;
        foreach(var change in history.Changes){
            if(change.Action is "replace" or "readmit"&&change.Target==current.Slot){current=change.Added!;left=false;}
            else if(change.Action=="close"||change.Action=="remove"&&change.Target==current.Slot)return null;
            else if(change.Action=="leave"&&change.Target==current.Slot)left=true;
        }
        return directory.Members.Contains(current)||left?(former,current):null;
    }
    static MeshMember? ReleasedMember(MeshHistory history,int slot,int through)
    {
        var member=history.Genesis.Members.FirstOrDefault(m=>m.Slot==slot);bool released=false;
        foreach(var change in history.Changes.Take(through)){
            if(change.Added?.Slot==slot)member=change.Added;
            if(change.Target==slot&&change.Action=="leave")released=true;
            if(change.Action=="close"||change.Target==slot&&change.Action is "remove" or "readmit")released=false;
        }
        return released?member:null;
    }
    public static bool VoluntarilyLeft(MeshDirectory directory,MeshMember member)
    {
        Validate(directory,directory.Network,directory.OwnerKey,0);
        var history=Unpack(directory.Governance!);
        return !directory.Closed&&!directory.Members.Contains(member)&&ReleasedMember(history,member.Slot,history.Changes.Length)==member;
    }
    public static int CurrentSlot(MeshDirectory directory,int slot)
    {
        if(directory.Members.Any(m=>m.Slot==slot))return slot;
        var history=Unpack(directory.Governance!);
        var original=history.Genesis.Members.Concat(history.Changes.Where(c=>c.Added!=null).Select(c=>c.Added!)).FirstOrDefault(m=>m.Slot==slot);
        var lineage=original==null?null:RejoinLineage(directory,slot,original.Device);
        return lineage is {} found&&directory.Members.Contains(found.Current)?found.Current.Slot:0;
    }
    public static void ValidateProgression(MeshDirectory next, MeshDirectory prior)
    {
        if (next.Governance == null) throw new CryptographicException("不能撤销成员平等管理或回退旧授权");
        var history = Unpack(next.Governance);
        if (prior.Governance == null) {
            MeshIdentity.ValidateSuccessor(history.Genesis, prior);
        } else {
            var old = Unpack(prior.Governance);
            if (Anchor(history) != Anchor(old) || history.Changes.Length < old.Changes.Length ||
                !history.Changes.Take(old.Changes.Length).SequenceEqual(old.Changes)) throw new CryptographicException("成员变更分支冲突，请重新同步协调状态");
        }
    }
}
