using System.Globalization;
using System.Net;

namespace StreamLink.Core;

public sealed record LegacyWireReport(long Sequence,string FirstObservedSource,long PacketsFromOtherSources,
    long HandshakePackets,long HandshakeBytes,long MaintenancePackets,long MaintenanceBytes,
    long BusinessPackets,long BusinessBytes,long CompletionPackets,long CompletionBytes,
    long DiagnosticPackets,long DiagnosticBytes,long SendFailures,long CapturedReceivePackets,long CapturedReceiveBytes,
    long CaptureQueueDrops,long SuppressedOutbound,bool CaptureWindowEnded)
{
    public string Scope=>"Native successful send API injections and captured receive headers, not physical NIC delivery or kernel peer overhead";
    public bool CompleteWireAudit=>false;
    internal long[] Counters()=>[PacketsFromOtherSources,HandshakePackets,HandshakeBytes,MaintenancePackets,MaintenanceBytes,
        BusinessPackets,BusinessBytes,CompletionPackets,CompletionBytes,DiagnosticPackets,DiagnosticBytes,SendFailures,
        CapturedReceivePackets,CapturedReceiveBytes,CaptureQueueDrops,SuppressedOutbound];
    internal static bool TryParse(string line,Guid resource,out LegacyWireReport? report)
    {
        report=null;if(line.Length>1024||resource==Guid.Empty)return false;
        var p=line.Split(' ',StringSplitOptions.RemoveEmptyEntries);
        if(p.Length!=21||p[0]!="SLW1"||p[1]!=resource.ToString("N")||
            !long.TryParse(p[2],NumberStyles.None,CultureInfo.InvariantCulture,out long seq)||seq<1||p[20] is not ("0" or "1"))return false;
        if(p[3]!="Unknown"&&(!IPEndPoint.TryParse(p[3],out var source)||source.Port==0||source.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork))return false;
        var n=new long[16];
        for(int i=0;i<n.Length;i++)if(!long.TryParse(p[4+i],NumberStyles.None,CultureInfo.InvariantCulture,out n[i]))return false;
        if(n.Any(value=>value>long.MaxValue/(LegacyTransportLedger.CompatibilityLimit*5)))return false;
        for(int i=1;i<=9;i+=2)if(n[i]>long.MaxValue/65535||n[i+1]<n[i]*28||n[i+1]>n[i]*65535)return false;
        report=new(seq,p[3],n[0],n[1],n[2],n[3],n[4],n[5],n[6],n[7],n[8],n[9],n[10],n[11],n[12],n[13],n[14],n[15],p[20]=="1");
        return true;
    }
}
