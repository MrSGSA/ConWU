using System.Security.Cryptography;
using System.Text.Json;
using StreamLink.Core;
using StreamLink.Service;

static class FixedTransportProfileTests
{
    public static void Run(Action<bool,string> check,Action<Action,string> reject)
    {
        var store=new ProfileStore();
        var initial=new DeviceProfile();
        check(initial.PathSelection=="faketcp-only" && !initial.Selection().Allows(TraversalProfile.UdpDirect),"new installation never permits UDP fallback");
        foreach(var mode in new[]{"faketcp","udp"}) {
            var original=new DeviceProfile {Mesh=MeshIdentity.Create("https://example.com/","",mode),TransportMode=mode,
                Enabled=true,PathSelection="prefer-faketcp",AllowUdpFallback=true};
            string identity=JsonSerializer.Serialize(original.Mesh);
            string file=Path.Combine(ProfileStore.Root,"profile.dpapi");
            // Write the old encrypted format directly, as an installed rc.3 would.
            File.WriteAllBytes(file,ProtectedData.Protect(JsonSerializer.SerializeToUtf8Bytes(original),"StreamLink-profile-v2"u8.ToArray(),DataProtectionScope.LocalMachine));
            int backups=Directory.GetFiles(ProfileStore.Root,"profile-before-fixed-transport-*.dpapi").Length;
            var migrated=store.Load();migrated.RequireFixedTransport();
            check(migrated.PathSelection==mode+"-only" && !migrated.AllowUdpFallback && migrated.Enabled && JsonSerializer.Serialize(migrated.Mesh)==identity,
                mode+": migration preserves network identity and connection intent while fixing protocol");
            var reopened=store.Load();
            check(reopened.PathSelection==migrated.PathSelection && reopened.MigrationNotice.Length>0 && Directory.GetFiles(ProfileStore.Root,"profile-before-fixed-transport-*.dpapi").Length==backups+1,
                mode+": migration persists and creates exactly one encrypted original backup");
            string opposite=mode=="faketcp"?"udp-only":"faketcp-only";
            reopened.SelectTransport(opposite);reopened.Enabled=false;store.Save(reopened);
            var changed=store.Load();
            check(changed.PathSelection==opposite && JsonSerializer.Serialize(changed.Mesh)==identity,"mode change survives reopen without re-pairing even when legacy network mode differs");
            var enhanced=PersonalFeature.EnhancedPreset(changed);
            check(enhanced.PathSelection==opposite && !enhanced.AllowUdpFallback,"enhancement cannot override the explicitly selected mode");
            var invalid=ProfileChanges.Copy(changed);invalid.PathSelection="prefer-faketcp";invalid.AllowUdpFallback=true;
            reject(()=>store.Save(invalid),"production persistence rejects automatic fallback even from privileged callers");
            check(store.Load().PathSelection==opposite,"rejected automatic policy cannot overwrite the saved choice");
        }
        store.Save(initial);
    }
}
