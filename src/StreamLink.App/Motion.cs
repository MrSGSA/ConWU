using System.Runtime.InteropServices;

namespace StreamLink;

static class Motion
{
    public static bool Enabled { get; set; } = true;
    [DllImport("user32.dll", SetLastError = true)] static extern bool SystemParametersInfo(uint action, uint param, out int value, uint flags);
    public static bool Allowed => Enabled && !SystemInformation.HighContrast && SystemParametersInfo(0x1042, 0, out int value, 0) && value != 0;
    public static Color Blend(Color a, Color b, double fraction) => Color.FromArgb(
        (int)Math.Round(a.R + (b.R - a.R) * fraction), (int)Math.Round(a.G + (b.G - a.G) * fraction), (int)Math.Round(a.B + (b.B - a.B) * fraction));
}
