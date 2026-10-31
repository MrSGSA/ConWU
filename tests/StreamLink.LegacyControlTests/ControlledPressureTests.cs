using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using StreamLink.Core;

static class ControlledPressureTests
{
    internal static async Task<object> Run(MeshRouter a,MeshRouter b,Adapter[] adapters,MeshProfile owner,MeshProfile guest,
        MeshTransport server,MeshTransport client,Action<bool,string> check,CancellationToken token,string output,Func<object> proxySnapshot)
    {
        byte[] Packet(string from,string to){
            var p=new byte[1280];p[0]=0x45;p[8]=64;p[9]=17;BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2),1280);
            IPAddress.Parse(from).GetAddressBytes().CopyTo(p,12);IPAddress.Parse(to).GetAddressBytes().CopyTo(p,16);
            uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);
            BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10),(ushort)~sum);
            for(int i=32;i<p.Length;i++)p[i]=(byte)(i*17);return p;
        }
        var templates=new[]{Packet(owner.LocalIp,guest.LocalIp),Packet(guest.LocalIp,owner.LocalIp)};
        var received=new[]{new HashSet<int>(),new HashSet<int>()};var last=new long[2];var gaps=new double[2];int sent=0;
        var before=new[]{a.Status().Single(),b.Status().Single()};var clock=Stopwatch.StartNew();int progress=10;
        void Drain(){
            for(int i=0;i<2;i++)while(adapters[1-i].Incoming.Reader.TryRead(out var packet)){
                if(packet.Length!=1280||!packet.AsSpan(0,28).SequenceEqual(templates[i].AsSpan(0,28))||!packet.AsSpan(32).SequenceEqual(templates[i].AsSpan(32)))throw new IOException("controlled pressure corrupted an IP payload");
                int sequence=BinaryPrimitives.ReadInt32BigEndian(packet.AsSpan(28));
                if(sequence<1||sequence>sent||!received[i].Add(sequence))throw new IOException("controlled pressure received an invalid or duplicate sequence");
                long now=Stopwatch.GetTimestamp();if(last[i]!=0)gaps[i]=Math.Max(gaps[i],Stopwatch.GetElapsedTime(last[i],now).TotalMilliseconds);last[i]=now;
            }
        }
        while(clock.Elapsed.TotalSeconds<60){
            for(int burst=0;burst<64;burst++){
                sent++;
                for(int i=0;i<2;i++){var packet=templates[i].ToArray();BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(28),sent);adapters[i].Outgoing.Add(packet);}
            }
            Drain();
            if(server.Exited||client.Exited||!a.Status().Single().Connected||!b.Status().Single().Connected)throw new IOException("controlled pressure lost a native owner or the unchanged round-trip proof");
            if(adapters.Any(x=>x.Outgoing.Count>512))throw new IOException("controlled pressure fixture cannot keep up with its offered load");
            if(clock.Elapsed.TotalSeconds>=progress){Console.WriteLine($"PROGRESS controlled native pressure {clock.Elapsed.TotalSeconds:F1}s, {sent} offered each direction");progress+=10;}
            await Task.Delay(10,token);
        }
        double offeredSeconds=clock.Elapsed.TotalSeconds;
        for(int i=0;i<100&&received.Any(r=>r.Count<sent);i++){Drain();await Task.Delay(10,token);}
        var after=new[]{a.Status().Single(),b.Status().Single()};
        var resources=LegacyTransportLedger.Shared.Snapshot().Resources.Where(r=>!r.RetirementRequested).ToArray();
        var routes=resources.Select(r=>r.Route!).ToArray();
        var report=new{durationSeconds=offeredSeconds,offeredPacketsPerDirection=sent,receivedPackets=received.Select(r=>r.Count).ToArray(),
            offeredMbpsPerDirection=sent*1280d*8/offeredSeconds/1e6,receivedMbps=received.Select(r=>r.Count*1280d*8/offeredSeconds/1e6).ToArray(),maximumReceiveGapMs=gaps,
            keepalive=after.Select(p=>p.Liveness!.Keepalive).ToArray(),before,after,resources,proxy=proxySnapshot(),
            scope="production MeshTransport/IPC/C++/MeshRouter; 1300ms advisory route observer, memory adapters and loopback raw carrier; no Wintun/WinDivert/WAN claim"};
        // Preserve measurements even when the quality assertion fails.
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true}),token);
        check(received.All(r=>r.Count==sent),"60s real controlled native traffic delivers every sequenced IP packet in both directions");
        check(after.Zip(before).All(p=>p.First.LocalDrops!.NoHealthyPath==p.Second.LocalDrops!.NoHealthyPath),"slow advisory routes cause no healthy-path drops under sustained traffic");
        check(after.Zip(before).All(p=>p.First.Liveness!.Keepalive!.FreshReplies-p.Second.Liveness!.Keepalive!.FreshReplies>=20),"ordinary authenticated keepalive continues across five unchanged health windows");
        check(routes.Length==2&&routes.All(r=>r.MaximumObservationMs>=1300),"both real MeshTransport owners observed OS-query delays longer than the native IPC deadline");
        return report;
    }
}
