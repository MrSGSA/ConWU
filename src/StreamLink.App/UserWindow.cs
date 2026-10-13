using System.Diagnostics;
using StreamLink.Core;

namespace StreamLink;
// Ordinary-user daily surface. It never connects to the privileged full-profile
// pipe or opens ProfileStore. Pairing/driver/install management remains elevated.
sealed class UserWindow:Form
{
    readonly CancellationTokenSource stop=new();
    readonly System.Windows.Forms.Timer timer=new(){Interval=2500};
    readonly Label state=Design.Label("正在读取本机后台状态",18,true),detail=Design.Label("",10),notice=Design.Label("",9);
    readonly TextBox name=new(){Width=280,MaxLength=64,AccessibleName="本机设备名称"};
    readonly ComboBox level=new(){Width=160,DropDownStyle=ComboBoxStyle.DropDownList,AccessibleName="日志等级"};
    readonly FlowLayoutPanel peers=new(){AutoSize=true,Dock=DockStyle.Top,FlowDirection=FlowDirection.TopDown,WrapContents=false};
    readonly List<Button> actions=[];
    bool pending,polling;
    public UserWindow()
    {
        Text="StreamLink · 本机网络";Size=new(900,650);Font=Design.Font();AutoScaleDimensions=new(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        var surface=new PearlPanel{Dock=DockStyle.Fill};Controls.Add(surface);var scroll=new ScrollViewport{Dock=DockStyle.Fill,AutoScroll=true,Padding=new(24)};surface.Controls.Add(scroll);
        var stack=Design.Stack();scroll.Controls.Add(stack);stack.Controls.Add(Design.Label("StreamLink",26,true));stack.Controls.Add(Design.Label("设备直连 · 协调服务不转发业务",10));stack.Controls.Add(state);stack.Controls.Add(detail);stack.Controls.Add(peers);
        var start=Action("启动网络",()=>Call("start"));var end=Action("停止网络",()=>Call("stop"));stack.Controls.Add(Design.Row(start,end));
        stack.Controls.Add(Design.Label("日常设置",12,true));level.Items.AddRange(["off","error","info","debug"]);level.SelectedIndex=2;
        stack.Controls.Add(Design.Row(name,level,Action("保存",async()=>Apply(await UiControlProtocol.Call(new("patch",new(name.Text.Trim(),level.Text),Guid.NewGuid()),stop.Token)))));
        var manage=Design.Button("配对与高级管理");manage.Width=210;manage.Click+=(_,_)=>Elevate();stack.Controls.Add(Design.Row(manage));stack.Controls.Add(Design.Label("安装驱动、配对与高级连接设置需要管理员授权。日常状态与以上设置不读取密钥。",9));stack.Controls.Add(notice);
        timer.Tick+=async(_,_)=>await Poll();Shown+=async(_,_)=>{if(Width>Screen.FromControl(this).WorkingArea.Width)Width=Screen.FromControl(this).WorkingArea.Width;if(Height>Screen.FromControl(this).WorkingArea.Height)Height=Screen.FromControl(this).WorkingArea.Height;await Poll();timer.Start();};
        FormClosed+=(_,_)=>{stop.Cancel();timer.Stop();timer.Dispose();};
    }
    Button Action(string text,Func<Task> action){var button=Design.Button(text);button.AccessibleName=text;actions.Add(button);button.Click+=async(_,_)=>{if(pending)return;pending=true;foreach(var b in actions)b.Enabled=false;notice.Text="正在处理…";try{await action();notice.Text="已完成";}catch(Exception ex){notice.Text=ex.Message;}finally{pending=false;foreach(var b in actions)b.Enabled=true;}};return button;}
    async Task Call(string method)=>Apply(await UiControlProtocol.Call(new(method,OperationId:Guid.NewGuid()),stop.Token));
    async Task Poll(){if(polling||stop.IsCancellationRequested)return;polling=true;try{Apply(await UiControlProtocol.Call(new("status"),stop.Token));}catch(Exception ex){state.Text="后台尚未就绪或未授权本机用户";notice.Text=ex.Message;}finally{polling=false;}}
    void Apply(UiControlReply reply){if(!reply.Ok)throw new IOException(reply.Error);var s=reply.Status!;state.Text=s.State;detail.Text=$"本机 {s.VirtualIp} · 直连 {s.DirectPeers}/{s.TotalPeers} · {s.Version}";
        if(!name.Focused&&!pending)name.Text=s.DeviceName;if(!level.Focused&&!pending)level.SelectedItem=s.LogLevel;
        string text=string.Join("\n",s.Peers.Select(p=>$"{p.Name} · {p.VirtualIp} · {(p.Connected?p.Degraded?"UDP降级直连":"已直连":"等待连接")}"));
        if(peers.Tag as string!=text){foreach(Control c in peers.Controls.Cast<Control>().ToArray())c.Dispose();peers.Controls.Clear();foreach(string line in text.Split('\n'))peers.Controls.Add(Design.Label(line,10));peers.Tag=text;}
    }
    void Elevate(){try{ServiceInstaller.VerifyBundle(AppContext.BaseDirectory);Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"});}catch(Exception ex){notice.Text="管理窗口未启动："+ex.Message;}}
}
