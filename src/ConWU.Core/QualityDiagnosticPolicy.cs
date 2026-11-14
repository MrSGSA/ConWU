namespace StreamLink.Core;

// Membership is not measurement consent. All production endpoints use the
// device-wide diagnostic pool; no consent means no load session allocation.
public sealed class QualityDiagnosticPolicy
{
    readonly Func<bool> permitted;
    readonly PathDiagnosticResources resources;
    readonly object gate=new();
    long lastControl;
    public QualityDiagnosticPolicy(Func<bool> permitted):this(permitted,PathDiagnosticResources.Shared){}
    internal QualityDiagnosticPolicy(Func<bool> permitted,PathDiagnosticResources resources){this.permitted=permitted;this.resources=resources;}
    public bool Allowed=>permitted();
    internal PathDiagnosticPermit? Begin(Guid id)=>Allowed?resources.TryBeginManual(id):null;
    internal bool ControlReplyAllowed(int bytes=512){lock(gate){long now=Environment.TickCount64;if(now-lastControl<100||!TraversalResources.Shared.TrySend(bytes,maintenance:true))return false;lastControl=now;return true;}}
    public const string Profile="manual-v2";
    public const int MaximumSeconds=20,CooldownMs=90000,WireDebitPerPacket=1536;
}
