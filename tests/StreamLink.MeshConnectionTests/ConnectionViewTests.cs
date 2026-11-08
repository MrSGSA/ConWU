using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static void ConnectionView()
    {
        var feedback=new MeshConnectionFeedback(_=>{});
        var peer=new MeshPeerStatus(2,"10.171.139.2","peer",true,15,"connected"){Liveness=new("Healthy",0,0)};
        Check(feedback.Observe(peer,null,true,1000).Connection!.ElapsedMs==0,"connected duration starts at confirmed bilateral health");
        Check(feedback.Observe(peer,null,true,86464100).Connection!.ElapsedMs==86463100,"connected duration keeps full day/hour/minute/second precision across status reads");
        Check(feedback.Observe(peer with{Name="renamed",RttMs=24},null,true,86465100).Connection!.ElapsedMs==86464100,"metadata and RTT changes do not restart the connected duration");
        var offline=peer with{Connected=false,Liveness=new("ReceiveTimedOut",13000,13000)};
        Check(feedback.Observe(offline,new("Offline","offline"),false,86466100).Connection!.Phase=="Offline","an actual liveness failure changes the connection state");
        Check(feedback.Observe(peer,null,true,86467100).Connection!.ElapsedMs==0,"a successful reconnection starts a fresh duration instead of inheriting the old one");
        var owner=MeshIdentity.Create("https://example.com/","","faketcp");var former=Guest(owner).Self;
        var saved=new ExistingEntry(former.Slot,"203.0.113.42:44680");
        var profile=new DeviceProfile{Mesh=owner,ConnectionSource="existing",SavedPeerEntryNetwork=owner.Pair.Network,SavedNetworkSettings=new(){ConnectionSource="existing",ExistingEntries=[saved]}};
        string original=System.Text.Json.JsonSerializer.Serialize(profile.SavedNetworkSettings);
        _=MeshIdentity.Replace(owner,former);var current=owner.Directory!.Members.Single(m=>m.Slot!=1);
        profile.RejoinHistory=MeshRejoin.Remember(owner,[],former,current);
        Check(ControlWorker.RuntimeEntries(profile).Single().PeerSlot==current.Slot&&System.Text.Json.JsonSerializer.Serialize(profile.SavedNetworkSettings)==original,"approved member replacement rebinds its runtime entry without changing user configuration");
        profile.Mesh=MeshIdentity.Create("https://other.example/","","faketcp");_=Guest(profile.Mesh);
        Check(ControlWorker.RuntimeEntries(profile).Length==0,"a new network cannot reuse a previous network's peer entry even when slot numbers coincide");
    }
}
