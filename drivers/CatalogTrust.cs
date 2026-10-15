using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
#pragma warning disable CS8625 // Classic C# for PowerShell: a null hash requests its size.

namespace StreamLink.ResearchAdapters
{
    // Explicit-catalog membership verification. Never searches an unrelated
    // installed catalog or accepts an embedded signature instead of this CAT.
    // Compatible with Windows PowerShell Add-Type and the product assembly.
    public static class CatalogTrust
    {
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct CatalogInfo {
            public uint Size,Version;
            [MarshalAs(UnmanagedType.LPWStr)]public string Catalog,Tag,Member;
            public IntPtr File,Hash;public uint HashLength;public IntPtr CatalogContext,Admin;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct TrustData {
            public uint Size;public IntPtr Policy,Sip;public uint Ui,Revocation,Choice;public IntPtr Info;
            public uint StateAction;public IntPtr State,Url;public uint Flags,UiContext;public IntPtr SignatureSettings;
        }
        [DllImport("wintrust.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)]static extern bool CryptCATAdminAcquireContext2(out IntPtr admin,IntPtr subsystem,string algorithm,IntPtr policy,uint flags);
        [DllImport("wintrust.dll",SetLastError=true)]
        [return:MarshalAs(UnmanagedType.Bool)]static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin,IntPtr file,ref uint size,byte[] hash,uint flags);
        [DllImport("wintrust.dll")]
        [return:MarshalAs(UnmanagedType.Bool)]static extern bool CryptCATAdminReleaseContext(IntPtr admin,uint flags);
        [DllImport("wintrust.dll",ExactSpelling=true)]static extern int WinVerifyTrust(IntPtr window,ref Guid action,ref TrustData data);
        public static void RequirePackage(string package) {
            string root=Path.GetFullPath(package),catalog=Path.Combine(root,"StreamLinkTun.cat");
            RequireMember(catalog,Path.Combine(root,"StreamLinkTun.sys"));
            RequireMember(catalog,Path.Combine(root,"StreamLinkTun.inf"));
        }
        public static void RequireMember(string catalog,string member) {
            catalog=Path.GetFullPath(catalog);member=Path.GetFullPath(member);
            if(!File.Exists(catalog)||!File.Exists(member))throw new IOException("Exact catalog/member missing");
            int last=unchecked((int)0x800B0100);
            // Inf2Cat and older packages may use different catalog hash algorithms.
            foreach(string algorithm in new[]{"SHA256","SHA1"}) {
                IntPtr admin;
                if(!CryptCATAdminAcquireContext2(out admin,IntPtr.Zero,algorithm,IntPtr.Zero,0))throw new Win32Exception(Marshal.GetLastWin32Error());
                try {
                    using(FileStream input=new FileStream(member,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                        uint size=0;CryptCATAdminCalcHashFromFileHandle2(admin,input.SafeFileHandle.DangerousGetHandle(),ref size,null,0);
                        if(size==0||size>128)throw new IOException("Catalog hash size unavailable");
                        byte[] hash=new byte[size];
                        if(!CryptCATAdminCalcHashFromFileHandle2(admin,input.SafeFileHandle.DangerousGetHandle(),ref size,hash,0))throw new Win32Exception(Marshal.GetLastWin32Error());
                        var info=new CatalogInfo{Size=(uint)Marshal.SizeOf(typeof(CatalogInfo)),Catalog=catalog,Tag=BitConverter.ToString(hash).Replace("-",""),Member=member,
                            File=input.SafeFileHandle.DangerousGetHandle(),HashLength=size,Admin=admin};
                        info.Hash=Marshal.AllocHGlobal((int)size);IntPtr native=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CatalogInfo)));
                        try {
                            Marshal.Copy(hash,0,info.Hash,(int)size);Marshal.StructureToPtr(info,native,false);
                            var data=new TrustData{Size=(uint)Marshal.SizeOf(typeof(TrustData)),Ui=2,Choice=2,Info=native,StateAction=1,
                                Flags=0x1000}; // cache-only certificate retrieval; never changes trust stores
                            var action=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
                            try { last=WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
                            finally { data.StateAction=2;WinVerifyTrust(new IntPtr(-1),ref action,ref data); }
                            if(last==0)return;
                        } finally { Marshal.DestroyStructure(native,typeof(CatalogInfo));Marshal.FreeHGlobal(native);Marshal.FreeHGlobal(info.Hash); }
                    }
                } finally {CryptCATAdminReleaseContext(admin,0);}
            }
            throw new IOException("Current member is not trusted in the exact catalog: "+Path.GetFileName(member)+"; trust=0x"+unchecked((uint)last).ToString("X8"));
        }
    }
}
