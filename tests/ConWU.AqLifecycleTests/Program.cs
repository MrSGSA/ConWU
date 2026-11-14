using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using StreamLink.Core;

if(args.Length!=2)throw new ArgumentException("components output");
string components=Path.GetFullPath(args[0]),output=Path.GetFullPath(args[1]);
if(File.Exists(output))throw new IOException("Fresh evidence required");
Directory.CreateDirectory(Path.GetDirectoryName(output)!);
var rows=new List<object>();string failure="";bool allPerformance=true,allPnp=true;int completed=0;
int attemptedRound=0;List<object> lastStages=[];
var mesh=MeshIdentity.Create("https://example.com/","","faketcp");
try {
 for(int round=1;round<=5;round++) {
  attemptedRound=round;var stages=new List<object>();lastStages=stages;object gate=new();var elapsed=Stopwatch.StartNew();
  void Trace(string phase){lock(gate)stages.Add(new{phase,ms=elapsed.Elapsed.TotalMilliseconds});}
  var adapter=new NativeAdapter(components,mesh.Pair.Network,1,Trace);
  ulong luid=adapter.InterfaceLuid??throw new IOException("Missing owned LUID");
  Guid guid=Pnp.GuidFor(luid);bool before=Pnp.Present(guid);
  if(!before)throw new IOException("Actual owned PnP instance absent before test");
  var cancel=new CancellationTokenSource();
  Task Start(Action action)=>Task.Factory.StartNew(action,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default);
  byte[] packet=new byte[20];packet[0]=0x45;packet[3]=20;packet[8]=64;packet[9]=253;
  IPAddress.Parse(MeshIdentity.Address(mesh.Pair.Network,2)).GetAddressBytes().CopyTo(packet,12);IPAddress.Parse(mesh.LocalIp).GetAddressBytes().CopyTo(packet,16);
  uint sum=0;for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(i));while(sum>65535)sum=(sum&65535)+(sum>>16);
  BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(10),(ushort)~sum);
  var read=Start(()=>{try{while(!cancel.IsCancellationRequested)adapter.Read(new byte[1280],cancel.Token);}catch(Exception e)when(e is OperationCanceledException or ObjectDisposedException){}});
  var write=Start(()=>{try{while(!cancel.IsCancellationRequested){adapter.Write(packet);if(cancel.Token.WaitHandle.WaitOne(2))break;}}catch(Exception e)when(e is OperationCanceledException or ObjectDisposedException){}});
  var stats=Start(()=>{try{while(!cancel.IsCancellationRequested){_=adapter.Statistics;if(cancel.Token.WaitHandle.WaitOne(2))break;}}catch(Exception e)when(e is OperationCanceledException or ObjectDisposedException){}});
  var warm=Stopwatch.StartNew();while(adapter.Statistics.WrittenPackets==0&&warm.ElapsedMilliseconds<1000)await Task.Delay(5);
  bool written=adapter.Statistics.WrittenPackets>0;
  var close=Stopwatch.StartNew();var all=Task.WhenAll(read,write,stats,Start(adapter.Dispose),Start(cancel.Cancel));bool performance=true;
  try{await all.WaitAsync(TimeSpan.FromSeconds(3));}catch(TimeoutException){performance=false;await all.WaitAsync(TimeSpan.FromSeconds(5));}
  double closeMs=close.Elapsed.TotalMilliseconds;performance&=closeMs<=3000;allPerformance&=performance;
  bool rejected=false;try{_=adapter.Statistics;}catch(ObjectDisposedException){rejected=true;}
  if(!all.IsCompletedSuccessfully||!rejected||!written)throw new IOException("I/O/resource safety not established; do not reopen");
  var watch=Stopwatch.StartNew();var samples=new List<object>();bool present;
  do {present=Pnp.Present(guid);samples.Add(new{ms=watch.Elapsed.TotalMilliseconds,pnpPresent=present,ipHelperRowPresent=Pnp.IpRow(luid)});if(!present)break;await Task.Delay(100);}while(watch.ElapsedMilliseconds<5000);
  bool pnp=!present&&watch.ElapsedMilliseconds<=5000;allPnp&=pnp;
  rows.Add(new{round,performanceGate=performance?"Pass":"Fail",closeMs,resourceSafety="Pass",written,pnpConvergence=pnp?"Pass":"Fail",samples,stages});completed++;
  File.WriteAllText(output+".partial.json",JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true}));
  if(!pnp)throw new IOException("Actual present SetupAPI device remains after 5s; no second owner");
  cancel.Dispose();Console.WriteLine($"ROUND {round}/5 close={closeMs:F1}ms performance={performance} actualPnP={pnp}");
 }
}catch(Exception e){failure=e.ToString();}
bool pass=failure.Length==0&&completed==5&&allPerformance&&allPnp;
File.WriteAllText(output,JsonSerializer.Serialize(new{status=pass?"Pass":"Fail",contract="AQ-1-observed-device-PnP",completedRounds=completed,requestedRounds=5,sameProcess=true,sameAdapterIdentity=true,performanceGate=allPerformance&&completed==5?"Pass":"FailOrPartial",resourceSafety=completed==5?"Pass":"Partial",pnpConvergence=allPnp&&completed==5?"Pass":"FailOrPartial",reopen=completed==5?"Pass":"NotProven",rows,failure,failedRound=failure.Length>0?new{round=attemptedRound,stages=lastStages}:null,
 scope="Actual official adapter with production managed owner and frozen native bundle; SetupAPI DIGCF_PRESENT + exact NetCfgInstanceId measures PnP, IPHelper cached row recorded separately. Original 3s close and 5s PnP thresholds unchanged; prior IPHelper-only Fail retained; not WAN or installed service full network. No forced termination counted as safety."},new JsonSerializerOptions{WriteIndented=true}));
Environment.ExitCode=pass?0:1;

static class Pnp {
 [StructLayout(LayoutKind.Sequential)]struct Device{public uint Size;public Guid ClassGuid;public uint Instance;public IntPtr Reserved;}
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr SetupDiGetClassDevs(ref Guid cls,string? enumerator,IntPtr window,uint flags);
 [DllImport("setupapi.dll",SetLastError=true)]static extern bool SetupDiEnumDeviceInfo(IntPtr set,uint index,ref Device device);
 [DllImport("setupapi.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool SetupDiGetDeviceRegistryProperty(IntPtr set,ref Device device,uint property,out uint type,byte[] data,uint length,out uint required);
 [DllImport("setupapi.dll")]static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
 [DllImport("iphlpapi.dll")]static extern uint ConvertInterfaceLuidToGuid(ref ulong luid,out Guid guid);
 [DllImport("iphlpapi.dll")]static extern uint GetIfEntry2Ex(int level,IntPtr row);
 public static Guid GuidFor(ulong luid){uint error=ConvertInterfaceLuidToGuid(ref luid,out var guid);if(error!=0)throw new Win32Exception((int)error);return guid;}
 public static bool IpRow(ulong luid){var row=Marshal.AllocHGlobal(4096);try{Marshal.Copy(new byte[4096],0,row,4096);Marshal.WriteInt64(row,(long)luid);uint result=GetIfEntry2Ex(2,row);return result switch{0=>true,2 or 1168=>false,_=>throw new Win32Exception((int)result)};}finally{Marshal.FreeHGlobal(row);}}
 public static bool Present(Guid expected){
  Guid cls=new("4d36e972-e325-11ce-bfc1-08002be10318");var set=SetupDiGetClassDevs(ref cls,null,IntPtr.Zero,2);
  if(set==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error());
  try{for(uint index=0;;index++){
   var device=new Device{Size=(uint)Marshal.SizeOf<Device>()};
   if(!SetupDiEnumDeviceInfo(set,index,ref device)){int error=Marshal.GetLastWin32Error();if(error==259)return false;throw new Win32Exception(error);}
   var data=new byte[4096];if(!SetupDiGetDeviceRegistryProperty(set,ref device,9,out _,data,(uint)data.Length,out var count)){int error=Marshal.GetLastWin32Error();if(error==13)continue;throw new Win32Exception(error);}
   string driver=Encoding.Unicode.GetString(data,0,(int)count).TrimEnd('\0');
   using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\"+driver);
   if(Guid.TryParse(key?.GetValue("NetCfgInstanceId") as string,out var actual)&&actual==expected)return true;
  }}finally{SetupDiDestroyDeviceInfoList(set);}
 }
}
