using System.Net;

namespace StreamLink.Core;

public sealed partial class MeshRouter
{
    sealed record EntryProbe(string Nonce,byte[] Frame,long Expires,int Slot=0);
    readonly Dictionary<IPEndPoint,EntryProbe> entryProbes=[];
    long nextEntryReply;
    public void ProbeNetworkEntry(IPEndPoint endpoint) {
        if(!IPAddress.IsLoopback(endpoint.Address))throw new ArgumentException("入口探测必须通过本机受管传输");
        lock(gate){
            long now=Environment.TickCount64;
            foreach(var old in entryProbes.Where(e=>e.Value.Expires<now).Select(e=>e.Key).ToArray())entryProbes.Remove(old);
            if(!entryProbes.TryGetValue(endpoint,out var probe)) {
                if(entryProbes.Count>=8)return;
                var request=MeshEntryHandshake.Request(profile);entryProbes[endpoint]=probe=new(request.Nonce,request.Frame,now+15000);
            }
            if(probe.Slot==0)Send(probe.Frame,endpoint);
        }
    }
    public int IdentifiedNetworkEntry(IPEndPoint endpoint) {
        lock(gate)return entryProbes.TryGetValue(endpoint,out var probe)&&probe.Expires>=Environment.TickCount64&&peers.ContainsKey(probe.Slot)?probe.Slot:0;
    }
    public void ForgetNetworkEntry(IPEndPoint endpoint){lock(gate)entryProbes.Remove(endpoint);}
    void ReceiveNetworkEntry(ReadOnlySpan<byte> bytes,IPEndPoint endpoint) {
        lock(gate){
            long now=Environment.TickCount64;
            if(entryProbes.TryGetValue(endpoint,out var probe)&&probe.Expires>=now) {
                int slot=MeshEntryHandshake.VerifyReply(profile,probe.Nonce,bytes);
                if(slot>0){entryProbes[endpoint]=probe with{Slot=slot};return;}
            }
            if(now<nextEntryReply)return;nextEntryReply=now+150;
            var reply=MeshEntryHandshake.Reply(profile,bytes);if(reply!=null)Send(reply,endpoint);
        }
    }
}
