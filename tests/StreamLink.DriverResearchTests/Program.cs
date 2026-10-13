using System.Runtime.InteropServices;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.ResearchAdapters;

if(args.Length!=2)throw new ArgumentException("research user DLL, report.json");
int checks=0;void Check(bool ok,string reason){if(!ok)throw new Exception(reason);checks++;Console.WriteLine("PASS "+reason);}
bool rejected=false;try{using var adapter=new ResearchTunAdapter("file-that-does-not-exist.dll",1,"10.250.251.1",false);}catch(IOException){rejected=true;}
Check(rejected,"research admission rejected before loading any DLL or touching a NIC");
rejected=false;try{PacketAdapterProviders.RequireProduction(new(PacketAdapterProviders.NativeExperimental,2,1280,true,true,true));}catch(IOException){rejected=true;}
Check(rejected,"default production provider contract rejects the experimental driver");
IntPtr library=NativeLibrary.Load(Path.GetFullPath(args[0]));
try{
    T Api<T>(string name)where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
    Check(Api<Abi>("SLT_UserAbi")()==1,"actual built user DLL reports research ABI1");
    Check(Api<Open>("SLT_Open")(0)==0,"zero interface ID rejected without creating a device");
    Check(Api<Open>("SLT_Open")(uint.MaxValue)==0,"absent device does not fall back to an arbitrary NIC");
    Check(!Api<HandleCall>("SLT_Stop")(ulong.MaxValue)&&!Api<HandleCall>("SLT_Close")(ulong.MaxValue),"opaque unknown handles are rejected without dereferencing caller pointers");
    Check(Api<Read>("SLT_Read")(ulong.MaxValue,new byte[1280],1280)==-1,"unowned read cannot access a kernel session");
    Check(!Api<Write>("SLT_Write")(ulong.MaxValue,new byte[1280],1280),"unowned write cannot inject a packet");
}finally{NativeLibrary.Free(library);}
Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(args[1]))!);
File.WriteAllText(args[1],JsonSerializer.Serialize(new{status="Pass",checks,scope="Actual Windows user DLL ABI/invalid-handle tests, production admission refusal. No kernel driver installed, no NDIS I/O, no signed-driver/Verifier/HVCI claim."},new JsonSerializerOptions{WriteIndented=true}));

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate uint Abi();
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate ulong Open(uint index);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate bool HandleCall(ulong handle);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate int Read(ulong handle,byte[] bytes,uint length);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate bool Write(ulong handle,byte[] bytes,uint length);
