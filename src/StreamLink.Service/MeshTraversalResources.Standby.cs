using System.Net;
using StreamLink.Core;

namespace StreamLink.Service;

internal sealed partial class MeshCandidateFactory
{
    public Task<IMeshCandidateResource> GatherStandby(MeshMember peer,TraversalProfile profile,Guid attempt,bool allowIpv6,
        MeshTraversalCandidate? remote,CancellationToken token) => GatherCurrent(ct => GatherStandbyCurrent(peer,profile,attempt,allowIpv6,remote,ct), token);
    async Task<IMeshCandidateResource> GatherStandbyCurrent(MeshMember peer,TraversalProfile profile,Guid attempt,bool allowIpv6,
        MeshTraversalCandidate? remote,CancellationToken token)
    {
        if (!SupportsStandbyProfile(profile) || remote != null && (!remote.Standby || remote.Prediction != null || remote.PeerReflexive || remote.Exploration != null))
            throw new IOException("本机或对端没有授权独立备用候选");
        var resource = await GatherScoped(peer,profile,attempt,allowIpv6,remote == null ? null : IPEndPoint.Parse(remote.Endpoint),1,false,token,standby:true);
        return new StandbyResource(resource);
    }
    sealed class StandbyResource(IMeshCandidateResource inner):IMeshCandidateResource
    {
        public MeshTraversalCandidate Candidate => inner.Candidate with{Standby=true};
        public Task<IPreparedMeshPath> Prepare(TraversalAttemptContext context,IPEndPoint remote,CancellationToken token)
        {
            if (!context.Standby) throw new IOException("备用资源不能升级为未协商的普通自动提名");
            return inner.Prepare(context,remote,token);
        }
        public Task<IPreparedMeshPath> PrepareCandidate(TraversalAttemptContext context,MeshTraversalCandidate remote,CancellationToken token)
        {
            if (!remote.Standby) throw new IOException("备用候选对不一致");return Prepare(context,IPEndPoint.Parse(remote.Endpoint),token);
        }
        public ValueTask DisposeAsync()=>inner.DisposeAsync();
    }
}
