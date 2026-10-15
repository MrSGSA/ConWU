using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace StreamLink;

// A native accessible menu; no embedded browser or desktop business window.
public sealed class TrayMenu : ContextMenuStrip
{
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(nint window,int attribute,ref int value,int size);
    public TrayMenu(Action open,Action exit)
    {
        ShowImageMargin=false;ShowCheckMargin=false;ShowItemToolTips=true;
        Font=new Font("Microsoft YaHei UI",10f);Renderer=new MenuRenderer();
        Items.Add(new ToolStripMenuItem("打开 WebUI(&O)",null,(_,_)=>open()){Tag="open",AccessibleName="打开 WebUI"});
        Items.Add(new ToolStripSeparator());
        Items.Add(new ToolStripMenuItem("退出(&X)",null,(_,_)=>exit()){Tag="exit",AccessibleName="退出托盘，网络继续运行",ToolTipText="关闭托盘和本机面板，网络继续运行"});
        ApplyMetrics();
    }
    int Scale(int value)=> (int)Math.Round(value*DeviceDpi/96d);
    void ApplyMetrics()
    {
        AutoSize=false;Padding=new Padding(Scale(7));
        foreach(ToolStripItem item in Items){item.AutoSize=false;item.Size=new Size(Scale(230),Scale(item is ToolStripSeparator?9:43));item.Margin=Padding.Empty;}
        Size=new Size(Scale(244),Scale(109));
    }
    protected override void OnDpiChangedAfterParent(EventArgs e){base.OnDpiChangedAfterParent(e);ApplyMetrics();}
    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if(OperatingSystem.IsWindowsVersionAtLeast(10,0,22000)){int round=2;_=DwmSetWindowAttribute(Handle,33,ref round,sizeof(int));}
    }
    sealed class MenuRenderer : ToolStripProfessionalRenderer
    {
        public MenuRenderer(){RoundedEdges=false;}
        static bool Contrast=>SystemInformation.HighContrast;
        static Color Foreground=>Contrast?SystemColors.MenuText:Color.FromArgb(38,42,45);
        static float Factor(ToolStrip? strip)=>(strip?.DeviceDpi??96)/96f;
        static GraphicsPath Rounded(RectangleF r,float radius)
        {
            var p=new GraphicsPath();float d=radius*2;
            p.AddArc(r.X,r.Y,d,d,180,90);p.AddArc(r.Right-d,r.Y,d,d,270,90);p.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);p.AddArc(r.X,r.Bottom-d,d,d,90,90);p.CloseFigure();return p;
        }
        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            e.Graphics.Clear(Contrast?SystemColors.Menu:Color.FromArgb(250,250,250));
        }
        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            using var pen=new Pen(Contrast?SystemColors.WindowFrame:Color.FromArgb(216,219,220));
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
            using var border=Rounded(new RectangleF(.5f,.5f,e.ToolStrip.Width-1,e.ToolStrip.Height-1),7*Factor(e.ToolStrip));e.Graphics.DrawPath(pen,border);
        }
        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            float f=Factor(e.ToolStrip);bool active=e.Item.Selected&&e.Item.Enabled;
            if(active){using var brush=new SolidBrush(Contrast?SystemColors.Highlight:Color.FromArgb(231,238,235));using var shape=Rounded(new RectangleF(0,1,e.Item.Width-1,e.Item.Height-2),5*f);e.Graphics.FillPath(brush,shape);}
            using var pen=new Pen(active&&Contrast?SystemColors.HighlightText:Foreground,1.55f*f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round};
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
            float x=14*f,y=(e.Item.Height-18*f)/2;
            if((string?)e.Item.Tag=="open"){
                e.Graphics.DrawLines(pen,new PointF[]{new(x,y+8*f),new(x+8*f,y+f),new(x+16*f,y+8*f)});
                e.Graphics.DrawLines(pen,new PointF[]{new(x+3*f,y+7*f),new(x+3*f,y+17*f),new(x+13*f,y+17*f),new(x+13*f,y+7*f)});
                e.Graphics.DrawLines(pen,new PointF[]{new(x+7*f,y+17*f),new(x+7*f,y+11*f),new(x+10*f,y+11*f),new(x+10*f,y+17*f)});
            }else{
                e.Graphics.DrawArc(pen,x+f,y+3*f,16*f,15*f,-48,276);e.Graphics.DrawLine(pen,x+9*f,y,x+9*f,y+9*f);
            }
        }
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            int left=(int)(44*Factor(e.ToolStrip));
            e.TextRectangle=new Rectangle(left,0,e.Item.Width-left-8,e.Item.Height);
            e.TextColor=e.Item.Selected&&Contrast?SystemColors.HighlightText:Foreground;
            e.TextFormat=TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine;
            base.OnRenderItemText(e);
        }
        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            using var pen=new Pen(Contrast?SystemColors.GrayText:Color.FromArgb(225,228,226));
            int inset=(int)(10*Factor(e.ToolStrip));e.Graphics.DrawLine(pen,inset,e.Item.Height/2,e.Item.Width-inset,e.Item.Height/2);
        }
    }
}
