using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace StreamLink;

static class Design
{
    public static readonly Color Ink = Color.FromArgb(31, 42, 67), Muted = Color.FromArgb(102, 116, 142), Accent = Color.FromArgb(91, 94, 224), Border = Color.FromArgb(228, 232, 242);
    public static readonly Color Surface = Color.FromArgb(248, 249, 253);
    public static Font Font(float size = 10, FontStyle style = FontStyle.Regular) => new("Microsoft YaHei UI", size, style);
    public static Label Label(string text, float size = 10, bool bold = false) => new() { Text = text, AutoSize = true, Font = Font(size, bold ? FontStyle.Bold : FontStyle.Regular), ForeColor = bold ? Ink : Muted, BackColor = Color.Transparent, Margin = new(0, 0, 0, 8) };
    public static RoundedButton Button(string text, bool primary = false) => new() { Text = text, Primary = primary, Width = 140, Height = 42, Margin = new(0, 0, 10, 0) };
    public static FlowLayoutPanel Row(params Control[] controls) { var row = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, WrapContents = true, Margin = new(0, 8, 0, 8), BackColor = Color.Transparent }; row.Controls.AddRange(controls); return row; }
    public static TableLayoutPanel Stack() => new() { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new(0), BackColor = Color.Transparent, GrowStyle = TableLayoutPanelGrowStyle.AddRows };
    public static GraphicsPath Round(Rectangle bounds, int radius)
    {
        var path = new GraphicsPath(); int d = radius * 2;
        path.AddArc(bounds.X, bounds.Y, d, d, 180, 90); path.AddArc(bounds.Right-d, bounds.Y,d,d,270,90); path.AddArc(bounds.Right-d,bounds.Bottom-d,d,d,0,90); path.AddArc(bounds.X,bounds.Bottom-d,d,d,90,90); path.CloseFigure(); return path;
    }
}

sealed class RoundedButton : Button
{
    [System.ComponentModel.DefaultValue(false)] public bool Primary { get; set; }
    [System.ComponentModel.DefaultValue(false)] public bool Selected { get; set; }
    bool hover;
    public RoundedButton() { FlatStyle = FlatStyle.Flat; FlatAppearance.BorderSize = 0; Font = Design.Font(10, FontStyle.Bold); Cursor = Cursors.Hand; DoubleBuffered = true; BackColor = Color.White; }
    protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias; Color background = Parent?.BackColor ?? Color.White; e.Graphics.Clear(background.A < 255 ? Color.White : background);
        using var path = Design.Round(new(1,1,Width-3,Height-3),10);
        Color fill = !Enabled ? Color.FromArgb(236,239,246) : Primary ? Design.Accent : Selected ? Color.FromArgb(232,234,255) : hover ? Color.FromArgb(244,245,255) : Color.White;
        using var brush = new SolidBrush(fill); e.Graphics.FillPath(brush,path);
        if (!Primary) { using var pen = new Pen(Selected ? Color.FromArgb(195,199,247) : Design.Border); e.Graphics.DrawPath(pen,path); }
        TextRenderer.DrawText(e.Graphics,Text,Font,ClientRectangle,!Enabled ? Color.FromArgb(155,164,182) : Primary ? Color.White : Design.Ink,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(e.Graphics,Rectangle.Inflate(ClientRectangle,-6,-6));
    }
}

// Composite only the viewport, not the whole window or the tall page. Native
// textboxes/comboboxes and managed controls then finish painting in one frame.
sealed class ScrollViewport : Panel
{
    public ScrollViewport()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        BackColor = Design.Surface;
    }
    protected override CreateParams CreateParams
    {
        get { var parameters = base.CreateParams; parameters.ExStyle |= 0x02000000; return parameters; } // WS_EX_COMPOSITED
    }
    protected override void OnScroll(ScrollEventArgs e)
    {
        base.OnScroll(e);
        // ScrollWindowEx can retain partially exposed child pixels. Invalidate
        // asynchronously; do not force Refresh/Update for every wheel message.
        Invalidate(true);
    }
    protected override void OnMouseWheel(MouseEventArgs e)
    {
        Point previous = AutoScrollPosition;
        base.OnMouseWheel(e); // WinForms' wheel path does not raise OnScroll.
        if (AutoScrollPosition != previous) Invalidate(true);
    }
}

sealed class PearlPanel : Panel
{
    readonly Image? art;
    Bitmap? cachedBackground;
    public PearlPanel()
    {
        DoubleBuffered = true; SetStyle(ControlStyles.ResizeRedraw, true); BackColor = Color.FromArgb(249,250,254);
        using var stream = typeof(PearlPanel).Assembly.GetManifestResourceStream("StreamLink.Assets.pearl-background.png");
        if (stream != null) { using var source = Image.FromStream(stream); art = new Bitmap(source); }
    }
    void ClearCache() { cachedBackground?.Dispose(); cachedBackground = null; }
    protected override void OnSizeChanged(EventArgs e) { ClearCache(); base.OnSizeChanged(e); }
    protected override void OnDpiChangedAfterParent(EventArgs e) { ClearCache(); base.OnDpiChangedAfterParent(e); }
    protected override void OnPaintBackground(PaintEventArgs e)
    {
        if (ClientSize.Width <= 0 || ClientSize.Height <= 0) return;
        if (cachedBackground == null) {
            cachedBackground = new Bitmap(ClientSize.Width, ClientSize.Height, PixelFormat.Format32bppPArgb);
            using var graphics = Graphics.FromImage(cachedBackground);
            graphics.Clear(BackColor);
            graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
            if (art != null) graphics.DrawImage(art, ClientRectangle);
        }
        // Transparent header/nav controls may ask their parent to paint again.
        // Reuse a pixel-sized bitmap instead of rescaling the PNG on each call.
        e.Graphics.DrawImageUnscaled(cachedBackground, Point.Empty);
    }
    protected override void Dispose(bool disposing) { if (disposing) { ClearCache(); art?.Dispose(); } base.Dispose(disposing); }
}
