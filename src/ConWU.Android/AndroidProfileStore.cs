using Android.Content;
using Android.Security.Keystore;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using System.Security.Cryptography;
using System.Text.Json;
using ConWU.Mobile;
using CipherMode=Javax.Crypto.CipherMode;

namespace ConWU.Android;

sealed class AndroidProfileStore(Context context)
{
    const string Alias="conwu.mobile.profile.v1";
    readonly string file=Path.Combine(context.NoBackupFilesDir!.AbsolutePath,"networks.encrypted");
    static readonly byte[] Aad="ConWU Android profile v1"u8.ToArray();
    IKey Key(bool create)
    {
        using var store=KeyStore.GetInstance("AndroidKeyStore")!;store.Load(null);
        if(store.ContainsAlias(Alias))return store.GetKey(Alias,null)??throw new IOException("Android 密钥不可用，原凭据文件已保留");
        if(!create)throw new IOException("Android 密钥缺失，不能解密原配置；原文件已保留");
        using var generator=KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes,"AndroidKeyStore")!;
        using var builder=new KeyGenParameterSpec.Builder(Alias,KeyStorePurpose.Encrypt|KeyStorePurpose.Decrypt);
        using var spec=builder.SetBlockModes(KeyProperties.BlockModeGcm).SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone).SetKeySize(256).SetRandomizedEncryptionRequired(true).Build();
        generator.Init(spec);return generator.GenerateKey()!;
    }
    public MobileDeviceState Load()
    {
        if(!System.IO.File.Exists(file)){
            if(System.IO.File.Exists(file+".previous"))throw new IOException("当前配置文件缺失，已有加密备份已保留；请先恢复备份");
            var state=new MobileDeviceState{DeviceName=SanitizeName(global::Android.OS.Build.Model??"Android 手机")};Save(state);return state;
        }
        byte[] encrypted=System.IO.File.ReadAllBytes(file);
        if(encrypted.Length is <34 or >1048576||!encrypted.AsSpan(0,5).SequenceEqual("CWMA1"u8))throw new IOException("加密配置格式无效，原文件已保留");
        using var key=Key(false);using var cipher=Cipher.GetInstance("AES/GCM/NoPadding")!;
        using var parameters=new GCMParameterSpec(128,encrypted.AsSpan(5,12).ToArray());
        cipher.Init(CipherMode.DecryptMode,key,parameters);cipher.UpdateAAD(Aad);
        byte[] plain=cipher.DoFinal(encrypted.AsSpan(17).ToArray())!;
        try{var state=JsonSerializer.Deserialize<MobileDeviceState>(plain)??throw new IOException("保存的配置为空");state.Validate();return state;}
        finally{CryptographicOperations.ZeroMemory(plain);}
    }
    static string SanitizeName(string value){var name=new string(value.Where(c=>!char.IsControl(c)).Take(64).ToArray()).Trim();return name.Length==0?"Android 手机":name;}
    public void Save(MobileDeviceState state)
    {
        state.Validate();
        using var key=Key(!System.IO.File.Exists(file));using var cipher=Cipher.GetInstance("AES/GCM/NoPadding")!;
        cipher.Init(CipherMode.EncryptMode,key);cipher.UpdateAAD(Aad);
        byte[] plain=JsonSerializer.SerializeToUtf8Bytes(state);
        byte[] encrypted;
        try{encrypted="CWMA1"u8.ToArray().Concat(cipher.GetIV()!).Concat(cipher.DoFinal(plain)!).ToArray();}
        finally{CryptographicOperations.ZeroMemory(plain);}
        string temporary=file+".tmp";
        using(var output=new FileStream(temporary,FileMode.Create,FileAccess.Write,FileShare.None)){output.Write(encrypted);output.Flush(true);}
        if(System.IO.File.Exists(file))System.IO.File.Copy(file,file+".previous",true);
        System.IO.File.Move(temporary,file,true);
    }
}
