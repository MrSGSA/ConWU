using System.Diagnostics;
using System.Drawing.Imaging;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using StreamLink;

static class Program
{
    const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    static T Field<T>(object target, string name) => (T)target.GetType().GetField(name, Private)!.GetValue(target)!;
    static int checks;
    static void Check(bool ok, string message) { if (!ok) throw new Exception(message); checks++; }
    static string Hash(Bitmap image) { using var data = new MemoryStream(); image.Save(data, ImageFormat.Png); return Convert.ToHexString(SHA256.HashData(data.ToArray())); }
    [STAThread] static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        string output = Path.GetFullPath(args.Length > 0 ? args[0] : "rendering.json");
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        bool baseline = args.Contains("--baseline");
        using var window = new MainWindow(true) { StartPosition = FormStartPosition.Manual, Location = new(-30000, -30000), ShowInTaskbar = false };
        window.Show(); window.PreviewPage("settings"); Application.DoEvents();
        var viewport = Field<Panel>(window, "content");
        var background = window.Controls[0];
        var mouseWheel = typeof(Control).GetMethod("OnMouseWheel", Private)!;
        var scroll = typeof(ScrollableControl).GetMethod("OnScroll", Private)!;
        using var frame = new Bitmap(viewport.Width, viewport.Height, PixelFormat.Format32bppPArgb);
        void Draw() => viewport.DrawToBitmap(frame, new(0, 0, frame.Width, frame.Height));
        for (int i = 0; i < 3; i++) Draw();
        var times = new List<double>();
        int extent = Math.Max(0, viewport.DisplayRectangle.Height - viewport.ClientSize.Height);
        Check(extent > 0, "Settings page does not scroll");
        int invalidated = 0; viewport.Invalidated += (_, _) => invalidated++;
        for (int i = 0; i < 32; i++) {
            int delta = i < 16 ? -120 : 120;
            var watch = Stopwatch.StartNew();
            mouseWheel.Invoke(viewport, [new HandledMouseEventArgs(MouseButtons.None, 0, 10, 10, delta)]);
            Draw(); watch.Stop(); times.Add(watch.Elapsed.TotalMilliseconds);
        }
        Check(viewport.AutoScrollPosition.Y == 0, "Wheel roundtrip did not return to top");
        if (!baseline) {
            Check(viewport.BackColor.A == 255 && viewport.Controls[0].BackColor.A == 255, "Scrolling content still repaints transparent ancestors");
            Check(invalidated > 0, "Mouse wheel does not invalidate stale viewport pixels");
            int before = invalidated; scroll.Invoke(viewport, [new ScrollEventArgs(ScrollEventType.ThumbTrack, 0, 120, ScrollOrientation.VerticalScroll)]);
            Check(invalidated > before, "Scrollbar dragging does not invalidate stale pixels");
            var cache = Field<Bitmap>(background, "cachedBackground");
            Draw(); Draw();
            Check(ReferenceEquals(cache, Field<Bitmap>(background, "cachedBackground")), "Repeated painting rebuilds the gradient cache");
            int oldWidth = window.Width; window.Width = oldWidth - 100; Application.DoEvents();
            using var resized = new Bitmap(window.Width, window.Height); window.DrawToBitmap(resized, new(0, 0, resized.Width, resized.Height));
            var rebuilt = Field<Bitmap>(background, "cachedBackground");
            Check(!ReferenceEquals(cache, rebuilt) && rebuilt.Size == background.ClientSize, "Resize did not rebuild the gradient at its new size");
            window.Width = oldWidth; Application.DoEvents();
        }
        viewport.AutoScrollPosition = new(0, Math.Min(480, extent)); Draw(); string beforeRefresh = Hash(frame);
        viewport.Invalidate(true); viewport.Update(); Application.DoEvents(); Draw();
        Check(beforeRefresh == Hash(frame), "Scrolled rendering differs after a full repaint");
        frame.Save(Path.ChangeExtension(output, ".png"), ImageFormat.Png);
        window.PreviewPage("join"); Application.DoEvents();
        Check(viewport.AutoScrollPosition.Y == 0, "Page switch retained the previous scroll offset");
        var nav=Field<System.Collections.IDictionary>(window,"nav");
        Check(nav.Keys.Cast<string>().Order().SequenceEqual(new[]{"overview","devices","diagnostics","settings"}.Order()),"primary navigation does not match product information architecture");
        foreach(string page in new[]{"overview","devices","diagnostics","settings","join","create"}){
            window.PreviewPage(page);Application.DoEvents();
            Check(viewport.Controls[0].Height>100,"page is blank: "+page);
            IEnumerable<Control> Descendants(Control root)=>root.Controls.Cast<Control>().SelectMany(c=>new[]{c}.Concat(Descendants(c)));
            var buttons=Descendants(viewport).OfType<Button>().Where(b=>b.Visible).ToArray();
            Check(buttons.Length>0&&buttons.All(b=>b.Height>=30*window.DeviceDpi/96),"dynamic action buttons were not DPI scaled: "+page);
            using var screen=new Bitmap(window.Width,window.Height);window.DrawToBitmap(screen,new Rectangle(Point.Empty,screen.Size));
            screen.Save(Path.Combine(Path.GetDirectoryName(output)!,"ui-"+page+".png"),ImageFormat.Png);
            Check(window.Width<=Screen.FromControl(window).WorkingArea.Width&&window.Height<=Screen.FromControl(window).WorkingArea.Height,"actual DPI window exceeds work area");
        }
        times.Sort();
        var report = new { checks, baseline, dpi = window.DeviceDpi, viewport = new { frame.Width, frame.Height }, frames = times.Count, medianDrawMs = times[times.Count / 2], p95DrawMs = times[(int)(times.Count * .95)], description = "Off-screen settings viewport scroll + DrawToBitmap timing; not screen FPS or a physical-display ghosting test. Preview mode does not start a network or service." };
        File.WriteAllText(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(report)); window.Close();
    }
}
