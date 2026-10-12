using System.Security.Cryptography;
using StreamLink.Core;

static class DiagnosticControlTests
{
    public static object Run(Action<bool,string> check)
    {
        byte[] scope=RandomNumberGenerator.GetBytes(32);Guid id=Guid.NewGuid();
        foreach(var step in Enum.GetValues<PathDiagnosticStep>()){
            PathDiagnosticSummary? source=step==PathDiagnosticStep.End?new(400,0,5000000,400,600000,0,4,12,1):null;
            PathDiagnosticReceipt? receipt=step==PathDiagnosticStep.Report?new(id,0,400,400,512000,0,0,0,0,0,2,0,1000,"ReportedAtCutoff"):null;
            var message=new PathDiagnosticMessage(step,id,0,1,source,receipt);byte[] frame=PathDiagnosticControl.Encode(message,scope);
            check(PathDiagnosticControl.TryParse(frame,scope,1,out var parsed)&&parsed!.Step==step&&parsed.Session==id&&parsed.Source==source&&parsed.Receipt==receipt,
                "typed diagnostic control round-trips bounded fields: "+step);
            foreach(int offset in new[]{0,4,7,24,56,60,64,68,72,191}){
                byte[] changed=(byte[])frame.Clone();changed[offset]^=128;
                check(!PathDiagnosticControl.TryParse(changed,scope,1,out _),"diagnostic parser rejects mutated scope/permissions/reserved field before state allocation");
            }
        }
        check(!PathDiagnosticControl.TryParse(PathDiagnosticControl.Encode(new(PathDiagnosticStep.Begin,id,0,1),scope),scope,2,out _),
            "same connection cannot override the receiver's configured target");
        byte[] header=PathDiagnosticControl.Encode(new(PathDiagnosticStep.Begin,id,0,1),scope);
        check(!PathDiagnosticControl.TryParse(header.AsSpan(0,191),scope,1,out _),"truncated diagnostic control does not cross a parser boundary");
        byte[] invalid=PathDiagnosticControl.Encode(new(PathDiagnosticStep.End,id,0,1,new(1,0,5000000,1,1500,0,1,1,1)),scope);
        System.Buffers.Binary.BinaryPrimitives.WriteDoubleBigEndian(invalid.AsSpan(124),double.NaN);
        check(!PathDiagnosticControl.TryParse(invalid,scope,1,out _),"NaN loaded RTT cannot become trusted quality evidence");
        return new{scope="bounded codec model; no session scheduling, transport or network proof"};
    }
}
