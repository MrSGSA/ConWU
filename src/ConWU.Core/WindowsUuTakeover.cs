using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace StreamLink.Core;

// No UU code is loaded, patched or injected. Only documented Windows socket
// events and packet headers are observed. Rules are scoped to verified images.
public sealed class WindowsUuTakeoverPlatform(string? components=null):IUuTakeoverPlatform
{
    public bool Supported=>OperatingSystem.IsWindows();
    readonly string dll=Path.Combine(components??Path.Combine(AppContext.BaseDirectory,"components"),"WinDivert.dll");
    static string[] Roots=>new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)}
        .Where(p=>p.Length>0).Select(p=>Path.GetFullPath(Path.Combine(p,"Netease","GameViewer","bin"))).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    public UuTakeoverProcess[] Processes()
    {
        if(!OperatingSystem.IsWindows())return [];
        var found=new List<UuTakeoverProcess>();
        foreach(string name in new[]{"GameViewer","GameViewerServer"})foreach(var process in Process.GetProcessesByName(name))using(process){
            try{using var pin=Pin.Open(process.Id);if(Allowed(pin.Image))found.Add(new(process.Id,pin.StartedAt,pin.Image));}
            catch(Exception ex)when(ex is Win32Exception or IOException or InvalidOperationException){}
        }
        return found.OrderBy(p=>p.Id).ToArray();
    }
    static bool Allowed(string path)=>Path.GetFileName(path) is var name&&
        (name.Equals("GameViewer.exe",StringComparison.OrdinalIgnoreCase)||name.Equals("GameViewerServer.exe",StringComparison.OrdinalIgnoreCase))&&
        Roots.Contains(Path.GetDirectoryName(Path.GetFullPath(path))!,StringComparer.OrdinalIgnoreCase);
    public IUuTakeoverGate Open(IReadOnlyList<UuTakeoverNetwork> networks,UuTakeoverProcess[] processes)
    {
        if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();
        return new Gate(dll,networks,processes);
    }

    [SupportedOSPlatform("windows")]
    sealed class Pin:IDisposable
    {
        public required SafeProcessHandle Handle;
        public required string Image;
        public long StartedAt;
        public static Pin Open(int id)
        {
            var handle=OpenProcess(0x1000|0x100000,false,id);
            if(handle.IsInvalid){handle.Dispose();throw new Win32Exception(Marshal.GetLastPInvokeError());}
            try{
                var image=new System.Text.StringBuilder(32768);uint count=(uint)image.Capacity;
                if(!QueryFullProcessImageName(handle,0,image,ref count)||!GetProcessTimes(handle,out long created,out _,out _,out _)||WaitForSingleObject(handle,0)!=258)
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                return new(){Handle=handle,Image=Path.GetFullPath(image.ToString()),StartedAt=created};
            }catch{handle.Dispose();throw;}
        }
        public bool Alive=>WaitForSingleObject(Handle,0)==258;
        public void Dispose()=>Handle.Dispose();
        [DllImport("kernel32.dll",SetLastError=true)]static extern SafeProcessHandle OpenProcess(uint access,bool inherit,int id);
        [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,System.Text.StringBuilder path,ref uint count);
        [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
        [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(SafeProcessHandle process,uint milliseconds);
    }

    [SupportedOSPlatform("windows")]
    sealed class Api
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi,SetLastError=true)]internal delegate nint OpenDelegate(string filter,int layer,short priority,ulong flags);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]internal delegate bool RecvDelegate(nint handle,nint packet,uint capacity,out uint length,[Out] byte[] address);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]internal delegate bool EndDelegate(nint handle);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]internal delegate bool ShutdownDelegate(nint handle,uint how);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl,SetLastError=true)]internal delegate bool ParamDelegate(nint handle,int key,ulong value);
        internal readonly OpenDelegate Open;
        internal readonly RecvDelegate Recv;
        internal readonly EndDelegate Close;
        internal readonly ShutdownDelegate Shutdown;
        internal readonly ParamDelegate Param;
        // Pin the verified bundled library until process exit, including any
        // receive task winding down after a driver fault. Never unload beneath it.
        static readonly Dictionary<string,Api> loaded=new(StringComparer.OrdinalIgnoreCase);
        internal static Api Load(string path){lock(loaded){path=Path.GetFullPath(path);if(!loaded.TryGetValue(path,out var api))loaded[path]=api=new(path);return api;}}
        Api(string path){
            nint library=LoadLibraryEx(path,0,0x1100);if(library==0)throw new Win32Exception(Marshal.GetLastPInvokeError(),"无法加载随 ConWU 安装的 WinDivert");
            T Get<T>(string name)where T:Delegate=>Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library,name));
            Open=Get<OpenDelegate>("WinDivertOpen");Recv=Get<RecvDelegate>("WinDivertRecv");Close=Get<EndDelegate>("WinDivertClose");Shutdown=Get<ShutdownDelegate>("WinDivertShutdown");Param=Get<ParamDelegate>("WinDivertSetParam");
        }
        [DllImport("kernel32.dll",EntryPoint="LoadLibraryExW",CharSet=CharSet.Unicode,SetLastError=true)]static extern nint LoadLibraryEx(string path,nint file,uint flags);
    }

    [SupportedOSPlatform("windows")]
    sealed class Gate:IUuTakeoverGate
    {
        readonly Api api;
        readonly Dictionary<string,UuTakeoverNetwork> networks;
        readonly HashSet<int> pids;
        readonly List<Pin> pins=[];
        readonly List<nint> handles=[];
        readonly List<Task> readers=[];
        readonly object counters=new();
        readonly Dictionary<long,long> buckets=[];
        sealed class NetworkCounters{public long Received,Sent;public readonly Dictionary<long,long> Buckets=[];}
        readonly Dictionary<string,NetworkCounters> byNetwork=[];
        HashSet<(byte Protocol,ushort Port)> ownerPorts=[];
        long received,sent,lastTraffic,bindings;
        string error="";
        int stopping;
        nint blocker;
        public Gate(string dll,IReadOnlyList<UuTakeoverNetwork> selected,UuTakeoverProcess[] processes)
        {
            networks=selected.ToDictionary(n=>n.VirtualIp,StringComparer.Ordinal);pids=processes.Select(p=>p.Id).ToHashSet();
            foreach(var network in selected)byNetwork[network.Id]=new();
            if(pids.Count is <1 or >32||pids.Count!=processes.Length)throw new IOException("UU 进程列表无效");
            // Verify each image again immediately before installing PID rules,
            // retain process handles and reject a PID whose creation time changed.
            api=Api.Load(dll);
            try{
                foreach(var process in processes){var pin=Pin.Open(process.Id);pins.Add(pin);
                    if(pin.StartedAt!=process.StartedAt||!Allowed(pin.Image)||!pin.Image.Equals(process.Image,StringComparison.OrdinalIgnoreCase))throw new IOException("UU 进程已改变，请等待重新识别");}
                UpdateOwners();
                string pid="("+string.Join(" or ",pids.Order().Select(p=>"processId == "+p))+")";
                string filter=pid+" and event == 3 and "+string.Join(" and ",networks.Keys.Select(ip=>"localAddr != "+ip))+" and localAddr != 0.0.0.0 and localAddr != 127.0.0.1 and localAddr != :: and localAddr != ::1";
                // SOCKET requires RECV_ONLY even for DROP. 3 is the public
                // SOCKET_BIND event value; the C enum name is not a filter token.
                nint watch=Open(filter,3,1000,1|4);Start(()=>ReadBindings(watch));
                blocker=Open(filter,3,0,2|4);
                foreach(bool outbound in new[]{false,true}){
                    string direction=outbound?"outbound":"inbound",field=outbound?"ip.SrcAddr":"ip.DstAddr";
                    string addresses="("+string.Join(" or ",networks.Keys.Select(ip=>field+" == "+ip))+")";
                    nint h=Open($"{direction} and ip and (tcp or udp) and {addresses}",0,(short)(outbound?-30000:30000),1|4);
                    Start(()=>ReadPackets(h,outbound));
                }
            }catch{Dispose();throw;}
        }
        nint Open(string filter,int layer,short priority,ulong flags)
        {
            // Explicit feature enable may load the already bundled signed
            // driver even when TCP/HTTPS itself has not needed WinDivert yet.
            nint h=api.Open(filter,layer,priority,flags);
            if(h==new nint(-1))throw new Win32Exception(Marshal.GetLastPInvokeError(),"无法启用 UU 临时选路规则");
            handles.Add(h);
            if((flags&2)==0)foreach(var setting in new[]{(0,4096UL),(1,2000UL),(2,32UL<<20)})
                if(!api.Param(h,setting.Item1,setting.Item2))throw new Win32Exception(Marshal.GetLastPInvokeError());
            return h;
        }
        void Start(Action action)=>readers.Add(Task.Factory.StartNew(action,CancellationToken.None,TaskCreationOptions.LongRunning,TaskScheduler.Default));
        void Failed(){if(Volatile.Read(ref stopping)==0)Volatile.Write(ref error,"流量观察中断（Win32 "+Marshal.GetLastPInvokeError()+"）");}
        void ReadBindings(nint h){byte[] address=new byte[80];while(Volatile.Read(ref stopping)==0){if(!api.Recv(h,0,0,out _,address)){Failed();break;}Interlocked.Increment(ref bindings);}}
        void ReadPackets(nint h,bool outbound)
        {
            nint packet=Marshal.AllocHGlobal(65535);byte[] head=new byte[96],address=new byte[80];
            try{while(Volatile.Read(ref stopping)==0){
                if(!api.Recv(h,packet,65535,out uint n,address)){Failed();break;}
                int length=(int)Math.Min(n,96);if(length<28)continue;Marshal.Copy(packet,head,0,length);
                int ihl=(head[0]&15)*4;if(head[0]>>4!=4||ihl<20||length<ihl+8||(BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(6))&0x1fff)!=0)continue;
                byte protocol=head[9];if(protocol is not(6 or 17))continue;
                ushort port=BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(ihl+(outbound?0:2)));
                if(!Volatile.Read(ref ownerPorts).Contains((protocol,port)))continue;
                // Only a directly connected approved peer counts as this
                // network. No broadcast, gateway or arbitrary IP is attributed.
                var remote=new IPAddress(head.AsSpan(outbound?16:12,4));
                string local=new IPAddress(head.AsSpan(outbound?12:16,4)).ToString();
                if(!networks.TryGetValue(local,out var network))continue;
                if(!network.PeerVirtualIps.Contains(remote.ToString(),StringComparer.Ordinal))continue;
                bool stun=protocol==17&&length>=ihl+16&&BinaryPrimitives.ReadUInt32BigEndian(head.AsSpan(ihl+12))==0x2112a442;
                int transport=protocol==17?8:length>=ihl+20?(head[ihl+12]>>4)*4:0;
                long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                lock(counters){var row=byNetwork[network.Id];if(outbound){sent+=n;row.Sent+=n;}else{received+=n;row.Received+=n;}
                    if(!stun&&transport>=8&&n>=ihl+transport+800){
                        lastTraffic=now;long second=now/1000;buckets[second]=buckets.GetValueOrDefault(second)+n;
                        row.Buckets[second]=row.Buckets.GetValueOrDefault(second)+n;
                        foreach(long old in buckets.Keys.Where(k=>k<second-5||k>second+1).ToArray())buckets.Remove(old);
                        foreach(long old in row.Buckets.Keys.Where(k=>k<second-5||k>second+1).ToArray())row.Buckets.Remove(old);
                    }
                }
            }}catch(Exception ex){if(Volatile.Read(ref stopping)==0)Volatile.Write(ref error,"流量观察异常："+ex.GetType().Name);}
            finally{Marshal.FreeHGlobal(packet);}
        }
        public UuTakeoverTraffic Observe(DateTimeOffset now)
        {
            if(pins.Any(pin=>!pin.Alive))return new(Error:"UU 已重启，正在重新识别进程");
            if(readers.Any(reader=>reader.IsCompleted))return new(Error:"UU 流量观察已停止，正在释放临时限制");
            UpdateOwners();long second=now.ToUnixTimeSeconds();
            lock(counters){long a=buckets.GetValueOrDefault(second-1),b=buckets.GetValueOrDefault(second-2);
                var rows=networks.Values.Select(n=>{var row=byNetwork[n.Id];long x=row.Buckets.GetValueOrDefault(second-1),y=row.Buckets.GetValueOrDefault(second-2);
                    return new UuTakeoverNetworkStatus(n.Id,n.Name,n.VirtualIp,x>=16384&&y>=16384,row.Received,row.Sent,(x+y)/2);}).ToArray();
                return new(received,sent,(a+b)/2,rows.Any(r=>r.TrafficObserved),lastTraffic,Interlocked.Read(ref bindings),Volatile.Read(ref error)){Networks=rows};}
        }
        void UpdateOwners()
        {
            var owned=new HashSet<(byte,ushort)>();var foreign=new HashSet<(byte,ushort)>();
            foreach(bool tcp in new[]{false,true}){
                uint size=0;uint code=Table(0,ref size,tcp);if(code is not(0 or 122))throw new Win32Exception((int)code);
                nint buffer=0;
                try{
                    for(int i=0;i<3;i++){if(buffer!=0)Marshal.FreeHGlobal(buffer);buffer=Marshal.AllocHGlobal((int)size);code=Table(buffer,ref size,tcp);if(code!=122)break;}
                    if(code!=0)throw new Win32Exception((int)code);
                    int count=Marshal.ReadInt32(buffer),width=tcp?24:12,pidOffset=tcp?20:8,portOffset=tcp?8:4;
                    if(count<0||4L+(long)count*width>size)throw new IOException("套接字归属表无效");
                    for(int i=0;i<count;i++){
                        nint row=buffer+4+i*width;int pid=Marshal.ReadInt32(row,pidOffset);
                        ushort port=BinaryPrimitives.ReverseEndianness((ushort)Marshal.ReadInt32(row,portOffset));
                        var key=((byte)(tcp?6:17),port);
                        (pids.Contains(pid)?owned:foreign).Add(key);
                    }
                }finally{if(buffer!=0)Marshal.FreeHGlobal(buffer);}
            }
            // Shared-port ownership is ambiguous: skip it rather than label
            // another application's traffic as UU traffic.
            owned.ExceptWith(foreign);Volatile.Write(ref ownerPorts,owned);
        }
        static uint Table(nint buffer,ref uint size,bool tcp)=>tcp?GetExtendedTcpTable(buffer,ref size,false,2,5,0):GetExtendedUdpTable(buffer,ref size,false,2,1,0);
        [DllImport("iphlpapi.dll")]static extern uint GetExtendedTcpTable(nint table,ref uint size,bool order,uint family,int kind,uint reserved);
        [DllImport("iphlpapi.dll")]static extern uint GetExtendedUdpTable(nint table,ref uint size,bool order,uint family,int kind,uint reserved);
        public void Dispose()
        {
            if(Interlocked.Exchange(ref stopping,1)!=0)return;
            // Remove DROP first. A slow/faulted observation worker must never
            // keep a traffic restriction in place after disable or shutdown.
            if(blocker!=0){api.Shutdown(blocker,3);api.Close(blocker);handles.Remove(blocker);blocker=0;}
            foreach(nint h in handles.AsEnumerable().Reverse())api.Shutdown(h,3);
            foreach(nint h in handles.AsEnumerable().Reverse())api.Close(h);
            handles.Clear();
            try{Task.WaitAll(readers.ToArray(),TimeSpan.FromSeconds(2));}catch(AggregateException){}
            foreach(var pin in pins)pin.Dispose();pins.Clear();
        }
    }
}
