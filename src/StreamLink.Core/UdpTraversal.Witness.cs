using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace StreamLink.Core;
public sealed partial class UdpTraversal
{
    sealed record WitnessQuery(IPEndPoint Target,TaskCompletionSource<IPEndPoint> Completion);
    readonly ConcurrentDictionary<string,WitnessQuery> witnesses=[];
    readonly Dictionary<string,long> witnessReplies=[];
    IPAddress? witnessPeer;
    long witnessStarted;
    // Explicit authenticated-attempt authorization. No selected data path is
    // required. A peer must still actually receive a valid packet to witness it.
    internal void AuthorizePeerWitness(IPAddress peer)
    {
        if(peer.AddressFamily!=AddressFamily.InterNetwork||!ValidEndpoint(new(peer,1)))throw new ArgumentException("IPv4 witness peer required");
        lock(gate){ObjectDisposedException.ThrowIf(resourceClosed||disposed!=0,this);if(witnessPeer!=null&&!witnessPeer.Equals(peer))throw new IOException("PeerPortWitnessScopeChanged");witnessPeer=peer;if(witnessStarted==0)witnessStarted=Stopwatch.GetTimestamp();}
    }
    TimeSpan WitnessRemaining
    {
        get{lock(gate){var own=TimeSpan.FromMilliseconds(UdpProbeGroup.DurationMs)-Stopwatch.GetElapsedTime(witnessStarted);var shared=group?.Remaining??explorationSeed?.Remaining;return shared is{} other&&other<own?other:own;}}
    }
    bool AdmitWitness()=>group!=null?group.Round.TrySend(96,false):explorationSeed!=null?explorationSeed.SendAdmission(96):resources.TrySend(96);
    byte[] WitnessPacket(byte kind,ReadOnlySpan<byte> nonce,ReadOnlySpan<byte> resourceGeneration,IPEndPoint? observed=null)
    {
        var frame=new byte[96];"SLW4"u8.CopyTo(frame);frame[4]=kind;frame[5]=localSlot;frame[6]=remoteSlot;attempt.CopyTo(frame,8);nonce.CopyTo(frame.AsSpan(24,16));resourceGeneration.CopyTo(frame.AsSpan(40,16));
        if(observed!=null){observed.Address.GetAddressBytes().CopyTo(frame,56);BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(60),checked((ushort)observed.Port));}
        // Domain separation prevents a normal probe MAC being reinterpreted.
        var material=new byte[80];"udp-witness-v1!!"u8.CopyTo(material);frame.AsSpan(0,64).CopyTo(material.AsSpan(16));HMACSHA256.HashData(key,material,frame.AsSpan(64));return frame;
    }
    bool ValidWitness(byte[] frame)
    {
        if(frame.Length!=96||frame[4] is not (1 or 2)||frame[5]!=remoteSlot||frame[6]!=localSlot||frame[7]!=0||!frame.AsSpan(8,16).SequenceEqual(attempt)||frame[62]!=0||frame[63]!=0)return false;
        var material=new byte[80];"udp-witness-v1!!"u8.CopyTo(material);frame.AsSpan(0,64).CopyTo(material.AsSpan(16));return CryptographicOperations.FixedTimeEquals(frame.AsSpan(64),HMACSHA256.HashData(key,material));
    }
    async Task ReceiveWitness(TraversalDatagram message)
    {
        byte[] frame=message.Data;
        lock(gate)if(witnessPeer==null||!message.Source.Address.Equals(witnessPeer)||WitnessRemaining<=TimeSpan.Zero||!ValidWitness(frame))return;
        string nonce=Convert.ToHexString(frame.AsSpan(24,16));
        if(frame[4]==2){
            if(witnesses.TryGetValue(nonce,out var query)&&query.Target.Equals(message.Source)&&new Guid(frame.AsSpan(40,16))==generation){
                var endpoint=new IPEndPoint(new IPAddress(frame.AsSpan(56,4)),BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(60)));
                if(ValidEndpoint(endpoint))query.Completion.TrySetResult(endpoint);
            }return;
        }
        // One-to-one small response, authenticated scope and bounded replay map.
        lock(gate){long now=Environment.TickCount64;if(witnessReplies.TryGetValue(nonce,out var prior)&&now-prior<650)return;if(witnessReplies.Count>=64&&!witnessReplies.ContainsKey(nonce))return;if(!AdmitWitness())return;witnessReplies[nonce]=now;}
        await socket.Send(WitnessPacket(2,frame.AsSpan(24,16),frame.AsSpan(40,16),message.Source),message.Source,stop.Token);
    }
    internal async Task<NatObservation> ObservePeerPort(IPEndPoint peer,CancellationToken token)
    {
        AuthorizePeerWitness(peer.Address);AcquireOperation();
        try{
            await observing.WaitAsync(token);
            try{
                if(!ValidEndpoint(peer)||witnesses.Count>=16)throw new IOException("PeerPortWitnessUnavailable: target/resource bound");
                var nonce=RandomNumberGenerator.GetBytes(16);string id=Convert.ToHexString(nonce);var reply=new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously);
                using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token,stop.Token);var remaining=WitnessRemaining;
                if(remaining<=TimeSpan.Zero)throw new IOException("PeerPortWitnessUnavailable: shared attempt deadline");
                deadline.CancelAfter(TimeSpan.FromMilliseconds(Math.Min(1800,remaining.TotalMilliseconds)));long at=Stopwatch.GetTimestamp();
                witnesses[id]=new(peer,reply);
                try{while(true){deadline.Token.ThrowIfCancellationRequested();if(AdmitWitness())await socket.Send(WitnessPacket(1,nonce,generation.ToByteArray()),peer,deadline.Token);
                    var completed=await Task.WhenAny(reply.Task,Task.Delay(700,deadline.Token));deadline.Token.ThrowIfCancellationRequested();
                    if(completed==reply.Task)return new(SocketId,generation,"udp",Local,peer,await reply.Task,DateTimeOffset.UtcNow,at);
                }}catch(OperationCanceledException)when(!token.IsCancellationRequested&&!stop.IsCancellationRequested){throw new IOException("PeerPortWitnessUnavailable: no authenticated packet reached this authorized peer port within remaining budget");}
                finally{witnesses.TryRemove(id,out _);}
            }finally{observing.Release();}
        }finally{await ReleaseReference();}
    }
}
