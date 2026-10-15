using System.Runtime.InteropServices;
using System.Text.Json;

static class BridgeOpenDiagnostics
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]delegate void Trace(uint phase);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Unicode)]delegate uint Open(string dll,string name,ref Guid guid,byte[] ip,out IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Unicode)]delegate uint TracedOpen(string dll,string name,ref Guid guid,byte[] ip,out IntPtr adapter,Trace trace);
    public static void Run(string bridge,string output){
        if(File.Exists(output))throw new IOException("Fresh evidence required");
        var library=NativeLibrary.Load(bridge);
        try{
            var legacy=Marshal.GetDelegateForFunctionPointer<Open>(NativeLibrary.GetExport(library,"sltun_open"));
            var traced=Marshal.GetDelegateForFunctionPointer<TracedOpen>(NativeLibrary.GetExport(library,"sltun_open_with_trace"));
            string missing=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString("N"),"wintun.dll");var id=Guid.NewGuid();var phases=new List<uint>();
            Trace callback=phases.Add;
            uint oldError=legacy(missing,"No-driver-diagnostic",ref id,[192,0,2,1],out var oldHandle);
            uint newError=traced(missing,"No-driver-diagnostic",ref id,[192,0,2,1],out var newHandle,callback);GC.KeepAlive(callback);
            if(oldError==0||newError!=oldError||oldHandle!=IntPtr.Zero||newHandle!=IntPtr.Zero||!phases.SequenceEqual(new uint[]{101,1,2,3,4,5,6,7,8}))
                throw new IOException("Traced open must preserve native error, null handle and exact rollback order");
            File.WriteAllText(output,JsonSerializer.Serialize(new{status="Pass",checks=4,oldError,newError,phases,scope="Actual bridge DLL missing-file refusal and rollback callbacks; no Wintun DLL or kernel driver loaded"}));
        }finally{NativeLibrary.Free(library);}
    }
}
