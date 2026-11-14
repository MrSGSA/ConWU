using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StreamLink.Core;

// Separates the original bounded authentication attempt from a continuously
// retained, authenticated standby and one later application-path selection.
// It never changes the transport's TCP ISS/ACK state or repeats business data.
internal sealed class StandbyNomination
{
    internal const int FrameSize = 96, HoldMs = 120000, SelectMs = 8000;
    readonly TraversalAttemptContext context;
    readonly Guid path;
    readonly long revision,began;
    readonly TimeProvider time;
    readonly TimeSpan remaining;
    readonly byte[] digest,challenge=RandomNumberGenerator.GetBytes(16);
    byte[]? peerChallenge;
    Guid selection;
    long heldAt,selectionAt,lastSent;
    bool held,selecting,sent,checkedPeer,peerChecked,mtu,allowed,everSwitch;
    int cancelSends;
    public NominationStage Stage {get;private set;}
    public bool Confirmed=>held&&Stage!=NominationStage.Cancelled;
    public bool NeedsResync=>Stage==NominationStage.Cancelled&&everSwitch;
    public TimeSpan TimeLeft=>selecting?TimeSpan.FromMilliseconds(SelectMs)-time.GetElapsedTime(selectionAt):
        held?TimeSpan.FromMilliseconds(HoldMs)-time.GetElapsedTime(heldAt):remaining-time.GetElapsedTime(began);
    public StandbyNomination(TraversalAttemptContext context,Guid path,long revision,TimeSpan remaining,bool mtu,TimeProvider time)
    {this.context=context;this.path=path;this.revision=revision;this.remaining=remaining;this.mtu=mtu;this.time=time;began=time.GetTimestamp();digest=PathNomination.ContextDigest(context);}
    public void QualifyMtu(){if(Stage!=NominationStage.Cancelled&&TimeLeft>TimeSpan.Zero)mtu=true;}
    void Prepare(){if(Stage==NominationStage.Checking&&checkedPeer&&peerChecked&&mtu)Stage=NominationStage.Standby;}
    public void AllowSelection(){if(Stage!=NominationStage.Standby||!Confirmed||TimeLeft<=TimeSpan.Zero)throw new InvalidOperationException("Standby not mutually authenticated");allowed=true;}
    public bool Select()
    {
        if(!context.Nominator||!allowed||!Confirmed||Stage!=NominationStage.Standby||TimeLeft<=TimeSpan.Zero)return false;
        selection=Guid.NewGuid();selectionAt=time.GetTimestamp();selecting=true;Stage=NominationStage.Nominating;sent=false;return true;
    }
    byte[] Frame(byte kind,bool echo=true)
    {
        var p=new byte[FrameSize];"SLN2"u8.CopyTo(p);p[4]=kind;BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(6),FrameSize);
        BinaryPrimitives.WriteInt64BigEndian(p.AsSpan(8),revision);digest.CopyTo(p,16);challenge.CopyTo(p,48);
        if(echo&&peerChallenge!=null)peerChallenge.CopyTo(p,64);selection.TryWriteBytes(p.AsSpan(80));return p;
    }
    public byte[][] Tick()
    {
        if(TimeLeft<=TimeSpan.Zero&&Stage is not(NominationStage.Selected or NominationStage.Cancelled))Cancel();
        if(Stage==NominationStage.Cancelled){if(cancelSends>=3||TimeLeft<TimeSpan.FromSeconds(-1))return [];}
        else if(TimeLeft<=TimeSpan.Zero)return [];
        int interval=Confirmed&&Stage==NominationStage.Standby?2000:250;
        if(sent&&time.GetElapsedTime(lastSent).TotalMilliseconds<interval)return [];
        sent=true;lastSent=time.GetTimestamp();Prepare();
        if(Stage==NominationStage.Cancelled){cancelSends++;return [Frame(7)];}
        return Stage switch{
            NominationStage.Checking=>[Frame(1,false)],NominationStage.Standby=>[Frame(8)],
            NominationStage.Nominating=>[Frame(3)],NominationStage.Confirming=>[Frame(4)],NominationStage.Committing=>[Frame(5)],
            NominationStage.Selected=>[Frame(context.Nominator?(byte)5:(byte)6)],_=>[]};
    }
    public void Cancel(){if(Stage==NominationStage.Cancelled)return;everSwitch|=Stage is NominationStage.Committing or NominationStage.Selected;Stage=NominationStage.Cancelled;sent=false;}
    public byte[][] Receive(Guid actualPath,ReadOnlySpan<byte> p)
    {
        if(actualPath!=path||p.Length!=FrameSize||!p[..4].SequenceEqual("SLN2"u8)||p[4] is <1 or >8||p[5]!=0||
            BinaryPrimitives.ReadUInt16BigEndian(p[6..])!=FrameSize||BinaryPrimitives.ReadInt64BigEndian(p[8..])!=revision||
            !CryptographicOperations.FixedTimeEquals(p.Slice(16,32),digest)||p.Slice(48,16).IndexOfAnyExcept((byte)0)<0||Stage==NominationStage.Cancelled)return [];
        byte kind=p[4];if(TimeLeft<=TimeSpan.Zero&&kind!=7)return [];
        var theirs=p.Slice(48,16);if(peerChallenge!=null&&!theirs.SequenceEqual(peerChallenge))return [];
        if(kind!=1&&!p.Slice(64,16).SequenceEqual(challenge))return [];
        var id=new Guid(p.Slice(80,16));
        if(kind is 1 or 2 or 8&&id!=Guid.Empty)return [];
        if(kind==7){if(TimeLeft>=TimeSpan.FromSeconds(-2)&&(selection==Guid.Empty||id==selection))Cancel();return [];}
        peerChallenge??=theirs.ToArray();
        if(kind==1){peerChecked=true;Prepare();return [Frame(2)];}
        if(kind==2){checkedPeer=true;Prepare();return [];}
        Prepare();if(Stage==NominationStage.Checking)return [];
        if(kind==8){
            if(Stage!=NominationStage.Standby)return [];
            if(!held){held=true;heldAt=time.GetTimestamp();sent=false;return [Frame(8)];}
            return [];
        }
        if(id==Guid.Empty)return [];
        if(kind==3&&!context.Nominator){
            if(Stage==NominationStage.Standby){if(!allowed||!Confirmed)return [];selection=id;selectionAt=time.GetTimestamp();selecting=true;Stage=NominationStage.Confirming;sent=false;}
            if(id!=selection)return [];
            return Stage==NominationStage.Confirming?[Frame(4)]:Stage==NominationStage.Selected?[Frame(6)]:[];
        }
        if(id!=selection)return [];
        if(kind==4&&context.Nominator&&Stage is NominationStage.Nominating or NominationStage.Committing or NominationStage.Selected){
            if(Stage!=NominationStage.Selected)Stage=NominationStage.Committing;everSwitch=true;return [Frame(5)];}
        if(kind==5&&!context.Nominator&&Stage is NominationStage.Confirming or NominationStage.Selected){Stage=NominationStage.Selected;everSwitch=true;return [Frame(6)];}
        if(kind==6&&context.Nominator&&Stage is NominationStage.Committing or NominationStage.Selected){Stage=NominationStage.Selected;return [];}
        return [];
    }
}
