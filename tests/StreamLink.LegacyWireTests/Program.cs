using System.Text.Json;
using StreamLink.Core;

if(args.Length!=4||args[0]!="--native-report"||args[2]!="--output")throw new ArgumentException("--native-report cpp-json --output report-json");
int checks=0;void Check(bool yes,string why){if(!yes)throw new IOException(why);checks++;Console.WriteLine("PASS "+why);}
using var native=JsonDocument.Parse(await File.ReadAllTextAsync(args[1]));
Check(native.RootElement.GetProperty("status").GetString()=="Pass","actual C++ reporter input passed its independent loopback checks");
foreach(var row in native.RootElement.GetProperty("rows").EnumerateArray()){
 var p=row.GetProperty("latest").EnumerateArray().Select(x=>x.GetString()!).ToArray();Guid id=Guid.Parse(p[1]);
 string line=string.Join(' ',p);Check(LegacyWireReport.TryParse(line,id,out var parsed)&&parsed!=null&&parsed.FirstObservedSource!="Unknown","C# accepts the actual native cumulative record including exact source");
 Check(!LegacyWireReport.TryParse(line,Guid.NewGuid(),out _),"another resource cannot import the same local record");
 var changed=(string[])p.Clone();changed[5]="-1";Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"negative counters cannot enter status");
 changed=(string[])p.Clone();changed[6]="0";Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"nonzero packet count requires plausible actual IP bytes");
 changed=(string[])p.Clone();changed[4]="18446744073709551615";Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"overflow counter cannot corrupt signed aggregates");
 changed=(string[])p.Clone();changed[4]=long.MaxValue.ToString();Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"individually representable extreme counters cannot overflow the bounded compatibility aggregate");
 changed=(string[])p.Clone();changed[3]="127.0.0.1:0";Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"unknown/invalid source is not guessed from the configured UDP bridge");
 changed=(string[])p.Clone();changed[20]="2";Check(!LegacyWireReport.TryParse(string.Join(' ',changed),id,out _),"unrecognized capture-window flag is rejected");
 var ledger=new LegacyTransportLedger();using var resource=ledger.Acquire(row.GetProperty("mode").GetString()!,false,"","192.0.2.1:40001",Guid.Empty);
 p[1]=resource.ResourceId.ToString("N");resource.WireLine(string.Join(' ',p));var before=ledger.Snapshot().Resources.Single().Wire;
 Check(before!=null&&before.Sequence==parsed!.Sequence,"resource stores a parsed cumulative snapshot without retaining packet payload");
 Check(ledger.Snapshot().ActiveReportedResources==1&&ledger.Snapshot().ActiveUnreportedResources==0&&ledger.Snapshot().ActiveKnownInjectionPackets>0,
    "compact status retains known injection totals while detailed records can be omitted");
 changed=(string[])p.Clone();changed[2]=(before!.Sequence-1).ToString();resource.WireLine(string.Join(' ',changed));
 Check(ledger.Snapshot().Resources.Single().Wire==before,"older local report cannot roll counters back");
 changed=(string[])p.Clone();changed[2]=(before.Sequence+1).ToString();changed[4]="0";changed[5]="0";changed[6]="0";resource.WireLine(string.Join(' ',changed));
 Check(ledger.Snapshot().Resources.Single().Wire==before,"new sequence with reduced counters cannot replace established accounting");
}
var observed=new LegacyTransportLedger();using(var resource=observed.Acquire("faketcp",false,"","192.0.2.1:40001",Guid.Empty))
using(var job=new ChildJob()){
 string line="SLW1 "+resource.ResourceId.ToString("N")+" 1 127.0.0.1:40002 0 1 60 0 0 0 0 0 0 0 0 0 1 60 0 0 0";
 string shell=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell","v1.0","powershell.exe");
 var child=job.StartObserved(shell,["-NoProfile","-NonInteractive","-Command","Write-Output '"+line+"'"],null,null,null,resource.WireLine);resource.Started(child);
 if(!child.WaitForExit(10000))throw new IOException("owned test emitter did not exit");job.Dispose();
 Check(observed.Snapshot().Resources.Single().Wire?.HandshakePackets==1,"actual ChildJob stdout observer receives counters when file logging is disabled");
}
Check(!observed.Snapshot().CompleteWireAudit,"injection observations never claim NIC delivery or unknown kernel peer overhead");
string output=Path.GetFullPath(args[3]);Directory.CreateDirectory(Path.GetDirectoryName(output)!);
await File.WriteAllTextAsync(output,JsonSerializer.Serialize(new{status="Pass",checks,scope="native-record parser, lifecycle and actual harmless ChildJob stdout; C++ reports came from loopback carriage, no physical WinDivert/WAN",completeWireAudit=false},new JsonSerializerOptions{WriteIndented=true}));
Console.WriteLine($"PASS {checks} legacy native accounting checks");
