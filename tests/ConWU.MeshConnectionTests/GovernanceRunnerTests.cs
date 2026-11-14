using System.Collections.Concurrent;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

namespace StreamLink.MeshConnectionTests;
static partial class Program
{
    static async Task GovernanceRunners()
    {
        var a=MeshIdentity.Create("https://coordinator.example/","","faketcp");MeshGovernance.Enable(a);
        var b=Guest(a);var hub=new ReplicaHub();hub.Install(a.Directory!);
        string folder=Path.Combine(Path.GetTempPath(),"streamlink-equal-runners-"+Guid.NewGuid().ToString("N"));
        var states=new ConcurrentDictionary<int,SessionStatus>();var saved=new ConcurrentDictionary<int,MeshProfile>();
        var nodes=new Dictionary<int,(Task Task,CancellationTokenSource Stop,MemoryAdapter Adapter)>();
        void Start(MeshProfile identity){
            int slot=identity.Self.Slot;var mesh=CopyMesh(identity);saved[slot]=CopyMesh(identity);var adapter=new MemoryAdapter();var mapping=new Mapping();
            var services=new MeshRuntimeServices(hub.Client,_=>Task.FromResult<IPacketAdapter>(adapter),(_,_,_)=>Task.FromResult<IMapping>(mapping),r=>{
                if(r.Server){mapping.Change(r.Target);return new StubTransport(null);}return new ForwardingTransport(r.Target,true);
            },(_,_,ct)=>Task.Delay(Timeout.Infinite,ct),(_,_,_)=>{},(_,_)=>{},folder){Candidates=(_,_,_,_)=>Task.FromResult<IMeshCandidateFactory?>(null),NetworkWake=()=>new MeshNetworkWake(false)};
            var runner=new MeshRunner(new(){Mesh=mesh,DeviceName="equal-"+slot},_=>{},s=>states[slot]=s,d=>{var p=CopyMesh(saved[slot]);p.Directory=d;saved[slot]=p;},_=>{},services);
            var stop=new CancellationTokenSource();nodes[slot]=(runner.Run(stop.Token),stop,adapter);
        }
        async Task Halt(int slot){var node=nodes[slot];node.Stop.Cancel();try{await node.Task.WaitAsync(TimeSpan.FromSeconds(8));}catch(OperationCanceledException){}catch(MeshRevokedException){}node.Stop.Dispose();nodes.Remove(slot);states.TryRemove(slot,out _);}
        bool Connected(int from,int to)=>states.TryGetValue(from,out var s)&&s.Peers?.Any(p=>p.Slot==to&&p.Connected)==true;
        async Task PacketArrives(int from,int to,string message){long before=states[to].Peers!.Single(p=>p.Slot==from).ReceivedBytes;nodes[from].Adapter.Outgoing.Add(Packet(saved[from].LocalIp,saved[to].LocalIp));await Until(()=>states[to].Peers!.Single(p=>p.Slot==from).ReceivedBytes>=before+1280,message);}
        try{
            Start(a);Start(b);await Until(()=>Connected(1,2)&&Connected(2,1),"equal network establishes authenticated data paths",25000);
            a.Directory=MeshGovernance.Change(a,"leave",1);hub.Install(a.Directory);await Halt(1);
            await Until(()=>saved[2].Directory!.Members.Length==1,"creator exit reaches surviving member without changing its identity",15000);
            b=CopyMesh(saved[2]);var c=Guest(b);hub.Install(b.Directory!);Start(c);
            await Until(()=>Connected(2,3)&&Connected(3,2),"surviving member approves and connects a new device after creator exit",25000);
            await PacketArrives(2,3,"new governance member receives a full-size encrypted packet");await PacketArrives(3,2,"new governance member sends a full-size encrypted packet");
            hub.Unavailable[2]=hub.Unavailable[3]=true;
            await PacketArrives(2,3,"coordinator outage leaves established direct business traffic running");
            hub.Unavailable.Clear();await Halt(2);await Halt(3);Start(saved[3]);Start(saved[2]);
            await Until(()=>Connected(2,3)&&Connected(3,2),"all devices restart on new loopback ports with creator permanently absent",25000);
            await PacketArrives(3,2,"retained equal membership restores actual packet delivery after restart");
            b=CopyMesh(saved[2]);MeshIdentity.Revoke(b,3);hub.Install(b.Directory!);
            await Until(()=>nodes[3].Task.IsFaulted,"non-creator revocation stops the removed runner",15000);
            Check(nodes[3].Task.Exception!.GetBaseException() is MeshRevokedException&&!saved[3].Directory!.Members.Contains(saved[3].Self),"revoked device persists the removal before its pumps stop");
        }finally{
            foreach(int slot in nodes.Keys.ToArray())await Halt(slot);
            if(Directory.Exists(folder))Directory.Delete(folder,true);
        }
    }
}
