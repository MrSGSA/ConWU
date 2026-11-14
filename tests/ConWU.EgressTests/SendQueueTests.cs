using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using StreamLink.Core;

static class SendQueueTests
{
    public static async Task<object[]> Run(Action<bool,string> check, CancellationToken token)
    {
        var rows = new List<object> { await Ledger(check, token) };
        foreach (bool paced in new[]{false,true}) foreach(bool cancel in new[]{false,true})
            rows.Add(await UdpQueue(paced, cancel, check, token));
        return rows.ToArray();
    }
    static async Task Until(Func<bool> ready, CancellationToken token)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(5000);
        while(!ready()) await Task.Delay(1,timeout.Token);
    }
    static async Task<object> Ledger(Action<bool,string> check,CancellationToken token)
    {
        using var pacer=new EgressPacer(1);using var entered=new ManualResetEventSlim();using var release=new ManualResetEventSlim();
        using var heavy=pacer.Register("heavy",(_,_)=>{entered.Set();release.Wait(token);return true;});
        using var joining=pacer.Register("joining",(_,_)=>true);
        try {
            check(heavy.TrySend(new byte[1000],1000),"ledger accepts initial in-flight send");entered.Wait(token);
            check(heavy.TrySend(new byte[1000],1000)&&!heavy.TrySend(new byte[1000],1000),"bounded queue explicitly rejects excess data");
            check(joining.TrySend(new byte[1000],1000)&&joining.TrySend(new byte[400],400),"new peer evicts one queued tail without enlarging the queue");
            using var cancelled=new CancellationTokenSource();cancelled.Cancel();
            check(!joining.TrySend(new byte[100],100,token:cancelled.Token),"cancelled submissions are unavailable rather than accepted");
            await Task.Delay(30,token);var busy=pacer.Snapshot();var counts=busy.Accounting!;
            check(counts.Conserved&&counts.InFlight.Packets==1&&counts.Queued.Packets==2&&counts.Evicted.Packets==1&&
                counts.CapacityRejected.Packets==1&&counts.UnavailableRejected.Packets==1&&busy.OldestQueuedMs>=20,
                "blocked real sender snapshot accounts for queued, in-flight, rejected and evicted datagrams and current age");
            joining.Dispose();check(joining.SendQueue.Accounting.Conserved&&joining.SendQueue.Accounting.Cancelled.Packets==2,
                "closing another flow cancels exactly its queued references without joining the blocked sender");
            release.Set();await Until(()=>pacer.Snapshot().SentBytes==1000,token);
            using var failed=pacer.Register("failure",(_,_)=>false);var completion=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            check(failed.TrySend(new byte[200],200,completion:completion),"failing I/O still has a recorded accepted enqueue");
            bool rejected=false;try{await completion.Task.WaitAsync(token);}catch(IOException){rejected=true;}
            check(rejected&&failed.SendQueue.Accounting.Failed==new DatagramAmount(1,200),"send failure is terminal once and is distinct from queue overflow");
            heavy.Dispose();failed.Dispose();pacer.Dispose();var final=pacer.Snapshot();
            check(final.Accounting!.Conserved&&final.Accounting.Queued.Packets==0&&final.Accounting.InFlight.Packets==0&&
                final.Accounting.Sent.Bytes==final.SentBytes&&final.Accounting.Cancelled.Packets==final.Cancelled&&
                final.Accounting.CapacityRejected.Packets+final.Accounting.Evicted.Packets==final.OverflowDrops&&
                final.Accounting.Failed.Packets==final.SendFailures,"shutdown ledger conserves every accepted byte and agrees with legacy counters");
            return new{ledger=final};
        }finally{release.Set();}
    }
    static async Task<object> UdpQueue(bool paced,bool cancel,Action<bool,string> check,CancellationToken token)
    {
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(12000);token=timeout.Token;
        using var pacer=paced?new EgressPacer(1):null;
        var blocked=new BlockedUdpSocket();ITraversalSocket left=paced?new PacedTraversalSocket(blocked,pacer!,"sender"):blocked;
        var machine=new TraversalResources();var generation=Guid.NewGuid();var attempt=Guid.NewGuid();byte[] key=RandomNumberGenerator.GetBytes(32);
        await using var a=new UdpTraversal(left,generation,attempt,1,2,key,machine);
        await using var b=new UdpTraversal(new TraversalSocket(new(IPAddress.Loopback,0)),Guid.NewGuid(),attempt,2,1,key,machine);
        CryptographicOperations.ZeroMemory(key);
        var punch=await Task.WhenAll(a.Punch([b.Local],null,token),b.Punch([a.Local],null,token));
        check(punch.All(p=>p.Success),$"{paced}/{cancel}: actual Windows UDP source completes checks and DF/MTU before queue test");
        await using var path=a.RetainPath(generation,Guid.NewGuid());await a.DisposeAsync();
        var diagnostics=(IMeshSendDiagnostics)path;
        var before=diagnostics.SendQueue.Accounting;
        byte[] frame=new byte[1344];"SLM4"u8.CopyTo(frame);frame[4]=4;
        check(path.TrySend(frame),$"{paced}/{cancel}: first complete business datagram enters the retained source");
        await blocked.Entered.Task.WaitAsync(token);
        int accepted=1;for(int i=0;i<160;i++)if(path.TrySend(frame))accepted++;
        var during=diagnostics.SendQueue;
        check(during.Accounting.Conserved&&during.Accounting.InFlight.Packets==1&&during.Accounting.CapacityRejected.Packets>before.CapacityRejected.Packets,
            $"{paced}/{cancel}: retained path publishes real local backpressure and in-flight accounting");
        check(paced?accepted==2&&during.Owner=="SharedEgress"&&during.Accounting.Queued.Packets==1:
            accepted==128&&during.Owner=="UdpPath"&&during.Accounting.Queued.Bytes+during.Accounting.InFlight.Bytes<=during.ByteLimit,
            $"{paced}/{cancel}: paced path has no hidden 128-packet queue; unpaced path includes in-flight bytes in its bound");
        if(cancel)await path.DisposeAsync();
        else {
            blocked.Release.TrySetResult();
            await Until(()=>diagnostics.SendQueue.Accounting.Failed.Packets==before.Failed.Packets+1&&
                diagnostics.SendQueue.Accounting.Sent.Packets==before.Sent.Packets+accepted-1,token);
            var received=await b.ReceivePayload(token);
            check(received.Data.SequenceEqual(frame)&&received.Source.Equals(a.Local)&&!path.Failed,
                $"{paced}: transient pressure drops its datagram once, subsequent full payload uses the original socket without path failure");
            await path.DisposeAsync();
        }
        await b.DisposeAsync();pacer?.Dispose();var final=diagnostics.SendQueue.Accounting;
        check(final.Conserved&&final.Queued.Packets==0&&final.InFlight.Packets==0&&a.Closed&&b.Closed&&machine.Usage().OpenUdpResources==0,
            $"{paced}/{cancel}: all queue outcomes and exact socket references converge on shutdown");
        if(cancel)check(final.Cancelled.Packets-before.Cancelled.Packets==accepted,
            $"{paced}: cancellation accounts for the in-flight and every queued datagram without sending them");
        return new{paced,cancel,accepted,before,during,final,scope="real Windows UDP loopback; deliberate transient send/cancellation fixture, no Wintun/WAN"};
    }
    sealed class BlockedUdpSocket:ITraversalSocket
    {
        readonly TraversalSocket inner=new(new(IPAddress.Loopback,0));int intercepted;
        readonly CancellationTokenSource stopped=new();
        public readonly TaskCompletionSource Entered=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Guid Id=>inner.Id;public IPEndPoint Local=>inner.Local;public bool DontFragment=>inner.DontFragment;
        public async ValueTask Send(ReadOnlyMemory<byte> packet,IPEndPoint remote,CancellationToken token)
        {
            if(packet.Length>=MeshLink.Overhead&&packet.Span[..4].SequenceEqual("SLM4"u8)&&packet.Span[4]==4&&Interlocked.CompareExchange(ref intercepted,1,0)==0){
                Entered.TrySetResult();using var linked=CancellationTokenSource.CreateLinkedTokenSource(token,stopped.Token);
                await Release.Task.WaitAsync(linked.Token);throw new SocketException((int)SocketError.NoBufferSpaceAvailable);
            }
            await inner.Send(packet,remote,token);
        }
        public ValueTask<TraversalDatagram> Receive(CancellationToken token)=>inner.Receive(token);
        public void Dispose(){stopped.Cancel();inner.Dispose();stopped.Dispose();}
    }
}
