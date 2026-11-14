using System.Globalization;

namespace StreamLink.Core;
public sealed record LegacyBusinessHandoffReport(long Sequence,long Offered,long BusyDrops,long Submitted,long Injected,long InjectedBytes,long Refused,long Faults,long PeakOutstanding)
{
    internal long[] Counters()=>[Offered,BusyDrops,Submitted,Injected,InjectedBytes,Refused,Faults,PeakOutstanding];
    internal static bool TryParse(string line,Guid resource,out LegacyBusinessHandoffReport? value)
    {
        value=null;if(line.Length>512||resource==Guid.Empty)return false;var words=line.Split(' ',StringSplitOptions.RemoveEmptyEntries);
        if(words.Length!=11||words[0]!="SLGE1"||words[1]!=resource.ToString("N"))return false;
        var counts=new long[9];for(int i=0;i<9;i++)if(!long.TryParse(words[i+2],NumberStyles.None,CultureInfo.InvariantCulture,out counts[i])||counts[i]>long.MaxValue/(65535*16))return false;
        if(counts[0]<1||counts[8]>64||counts[4]>counts[3]||counts[6]>counts[3]||counts[5]<counts[4]*40||counts[5]>counts[4]*6144)return false;
        value=new(counts[0],counts[1],counts[2],counts[3],counts[4],counts[5],counts[6],counts[7],counts[8]);return true;
    }
}
