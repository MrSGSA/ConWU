using System.Text.Json;

namespace StreamLink;

sealed class DesktopSettings
{
    public string Server { get; set; } = "";
    public string Pin { get; set; } = "";
    public bool Tray { get; set; } = true;
    public bool CloseToTray { get; set; } = true;
    static string FileName => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "StreamLink", "desktop.json");
    public static DesktopSettings Load()
    {
        try { if (File.Exists(FileName)) return JsonSerializer.Deserialize<DesktopSettings>(File.ReadAllText(FileName)) ?? new(); } catch { }
        return new();
    }
    public void Save() { Directory.CreateDirectory(Path.GetDirectoryName(FileName)!); File.WriteAllText(FileName, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true })); }
}
