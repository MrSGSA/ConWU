using System.Net;

namespace StreamLink.Core;
public sealed record UdpEmpiricalEvidence(Guid SocketResourceId,Guid NetworkGeneration,string EvidenceLevel,int Training,int Holdout,bool MappingStable,bool ExperimentalAdmission,string Reason)
{
    public bool IsStrongPeerPortProof=>false;
}
internal static class UdpEmpiricalEvidenceProvider
{
    internal static UdpEmpiricalEvidence Evaluate(UdpTraversal owner,Guid generation,NatObservation[] training,NatObservation[] holdout,bool explicitlyEnabled)
    {
        string reason="";var all=training.Concat(holdout).ToArray();
        if(training.Length<4||holdout.Length<2)reason="InsufficientIndependentSamples";
        else if(all.Any(o=>o.SocketId!=owner.SocketId||o.NetworkGeneration!=generation||o.Protocol!="udp"||!o.Local.Equals(owner.Local)||DateTimeOffset.UtcNow-o.ObservedAt>TimeSpan.FromSeconds(12)||o.ObservedAt>DateTimeOffset.UtcNow))reason="ResourceGenerationOrFreshnessMismatch";
        else if(training.Select(o=>o.Target.Address).Distinct().Count()<2||holdout.Any(o=>o.ProbeStartedAt<=training.Max(t=>t.ProbeStartedAt)))reason="HoldoutNotIndependent";
        else if(all.Select(o=>o.Mapped).Distinct().Count()!=1)reason="MappingChanged";
        bool stable=reason.Length==0;
        return new(owner.SocketId,generation,"EmpiricalEimOnly",training.Length,holdout.Length,stable,stable&&explicitlyEnabled,stable?(explicitlyEnabled?"ExperimentalOnlyNotPeerProof":"Disabled"):reason);
    }
}
