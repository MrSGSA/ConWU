using System.Net;
using System.Net.Http.Json;

namespace StreamLink.Core;

public sealed record MeshMembershipRequest(string ExpectedHead, MeshDirectory Directory);
public sealed class MeshMembershipConflictException(MeshDirectory current) : IOException("其他成员已更新网络；已刷新成员信息，请重新核对后操作")
{
    public MeshDirectory Current {get;} = current;
}

// Persisted inside the protected local profile before any remotely visible edit.
// The encrypted invitation can be delivered again without retaining the ephemeral
// exchange key, including after a process restart or a lost HTTP response.
public sealed record PendingMembershipChange(string ExpectedHead, MeshDirectory Proposed, string Action)
{
    public PairRoomTicket? Room {get;init;}
    public string Candidate {get;init;}="";
    public string Ciphertext {get;init;}="";
    public MeshRejoinHistory[] RejoinHistory {get;init;}=[];
}

public sealed partial class MeshDiscoveryClient
{
    public async Task<MeshDirectory> CommitMembership(MeshMembershipRequest change, CancellationToken token)
    {
        using var response=await http.PutAsJsonAsync($"v4/mesh/{profile.Pair.Network}/membership",change,token);
        if(response.StatusCode!=HttpStatusCode.Conflict)response.EnsureSuccessStatusCode();
        var current=await response.Content.ReadFromJsonAsync<MeshDirectory>(token)??throw new IOException("协调服务未返回成员确认");
        MeshIdentity.ValidateDirectory(current,profile.Pair.Network,profile.OwnerKey);
        if(response.StatusCode==HttpStatusCode.Conflict)throw new MeshMembershipConflictException(current);
        MeshIdentity.ValidateSuccessor(current,change.Directory);
        return current;
    }
}
