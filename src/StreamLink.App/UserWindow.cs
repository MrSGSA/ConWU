using System.Diagnostics;
using StreamLink.Core;

namespace StreamLink;
// Ordinary-user daily surface. It never opens the privileged full-profile pipe
// or ProfileStore. Pairing/driver/install management remains elevated.
sealed class UserWindow:Form
{
    readonly CancellationTokenSource stop=new();
    readonly System.Windows.Forms.Timer timer=new(){Interval=2500};
    readonly Label state=Design.Label("正在读取本机后台状态",18,true),detail=Design.Label("",10),notice=Design.Label("",9),editState=Design.Label("",9);
    readonly TextBox name=new(){Width=280,MaxLength=64,AccessibleName="本机设备名称"};
    readonly ComboBox level=new(){Width=160,DropDownStyle=ComboBoxStyle.DropDownList,AccessibleName="日志等级"};
    readonly FlowLayoutPanel peers=new(){AutoSize=true,Dock=DockStyle.Top,FlowDirection=FlowDirection.TopDown,WrapContents=false};
    readonly List<Button> actions=[];
    readonly UiSettingsDraft draft=new();
    UiControlRequest? retrySave;
    bool pending,polling,applying;
    long statusGeneration;
    string virtualIp="";
    public UserWindow()
    {
        Text="StreamLink · 本机网络";Size=new(900,650);Font=Design.Font();AutoScaleDimensions=new(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        var surface=new PearlPanel{Dock=DockStyle.Fill};Controls.Add(surface);var scroll=new ScrollViewport{Dock=DockStyle.Fill,AutoScroll=true,Padding=new(24)};surface.Controls.Add(scroll);
        var stack=Design.Stack();scroll.Controls.Add(stack);stack.Controls.Add(Design.Label("StreamLink",26,true));stack.Controls.Add(Design.Label("设备直连 · 协调服务不转发业务",10));stack.Controls.Add(state);stack.Controls.Add(detail);stack.Controls.Add(peers);
        var start=Action("启动网络",()=>Call("start"));var end=Action("停止网络",()=>Call("stop"));
        var copy=Action("复制本机IP",()=>{if(virtualIp.Length==0)throw new IOException("当前没有可复制的虚拟IP");Clipboard.SetText(virtualIp);return Task.CompletedTask;});
        stack.Controls.Add(Design.Row(start,end,copy));
        stack.Controls.Add(Design.Label("日常设置",12,true));level.Items.AddRange(["off","error","info","debug"]);level.SelectedIndex=2;
        name.Enabled=level.Enabled=false;
        name.TextChanged+=(_,_)=>{if(!applying){draft.EditName(name.Text);UpdateEditState();}};
        level.SelectedIndexChanged+=(_,_)=>{if(!applying){draft.EditLevel(level.Text);UpdateEditState();}};
        stack.Controls.Add(Design.Row(name,level,Action("保存",Save),Action("撤销未保存",()=>{draft.Discard();retrySave=null;RenderDraft();return Task.CompletedTask;})));
        stack.Controls.Add(editState);
        var manage=Design.Button("配对与高级管理");manage.Width=210;manage.Click+=(_,_)=>Elevate();stack.Controls.Add(Design.Row(manage));stack.Controls.Add(Design.Label("安装驱动、配对与高级连接设置需要管理员授权。日常状态与以上设置不读取密钥。",9));stack.Controls.Add(notice);
        timer.Tick+=async(_,_)=>await Poll();Shown+=async(_,_)=>{if(Width>Screen.FromControl(this).WorkingArea.Width)Width=Screen.FromControl(this).WorkingArea.Width;if(Height>Screen.FromControl(this).WorkingArea.Height)Height=Screen.FromControl(this).WorkingArea.Height;await Poll();timer.Start();};
        FormClosed+=(_,_)=>{stop.Cancel();timer.Stop();timer.Dispose();};
    }
    Button Action(string text,Func<Task> action)
    {
        var button=Design.Button(text);button.AccessibleName=text;actions.Add(button);
        button.Click+=async(_,_)=>{
            if(pending)return;pending=true;statusGeneration++;
            foreach(var b in actions)b.Enabled=false;name.Enabled=level.Enabled=false;notice.Text="正在处理…";
            try{await action();if(!IsDisposed)notice.Text="已完成";}
            catch(Exception ex){if(!IsDisposed)notice.Text=ex.Message;}
            finally{pending=false;statusGeneration++;if(!IsDisposed){foreach(var b in actions)b.Enabled=true;name.Enabled=level.Enabled=draft.Initialized;UpdateEditState();}}
        };return button;
    }
    async Task Save()
    {
        if(!draft.Dirty)return;
        var patch=draft.CreatePatch();
        // A transport failure may occur after the server committed. Reuse the
        // original ID for an unchanged patch, rather than repeating a mutation.
        if(retrySave?.Patch!=patch)retrySave=new("patch",patch,Guid.NewGuid());
        var reply=await UiControlProtocol.Call(retrySave!,stop.Token);
        if(!reply.Ok){retrySave=null;if(reply.Status!=null)ApplyStatus(reply.Status);throw new IOException(reply.Error);}
        if(reply.Operation is {Completed:false})throw new IOException("保存仍在后台处理中，草稿已保留；再次保存将查询同一操作");
        retrySave=null;
        var current=reply.Status??throw new IOException("后台未返回设置状态");
        draft.Reset(current);ApplyStatus(current);
    }
    async Task Call(string method)
    {
        var reply=await UiControlProtocol.Call(new(method,OperationId:Guid.NewGuid()),stop.Token);
        if(!reply.Ok)throw new IOException(reply.Error);
        if(reply.Status!=null)ApplyStatus(reply.Status);
    }
    async Task Poll()
    {
        if(polling||pending||stop.IsCancellationRequested)return;
        polling=true;long generation=statusGeneration;
        try{
            var reply=await UiControlProtocol.Call(new("status"),stop.Token);
            if(IsDisposed||generation!=statusGeneration)return; // stale pre-save poll
            if(!reply.Ok)throw new IOException(reply.Error);
            if(reply.Status!=null)ApplyStatus(reply.Status);
        }catch(Exception ex){if(!IsDisposed&&generation==statusGeneration){state.Text="后台尚未就绪或未授权本机用户";notice.Text=ex.Message;}}
        finally{polling=false;}
    }
    void ApplyStatus(UiStatusDto s)
    {
        if(IsDisposed)return;
        state.Text=s.State;virtualIp=s.VirtualIp;detail.Text=$"本机 {s.VirtualIp} · 直连 {s.DirectPeers}/{s.TotalPeers} · {s.Version}";
        draft.Observe(s);RenderDraft();
        string text=string.Join("\n",s.Peers.Select(p=>$"{p.Name} · {p.VirtualIp} · {(p.Connected?p.Degraded?"UDP降级直连":"已直连":"等待连接")}"));
        if(peers.Tag as string!=text){foreach(Control c in peers.Controls.Cast<Control>().ToArray())c.Dispose();peers.Controls.Clear();foreach(string line in text.Split('\n'))peers.Controls.Add(Design.Label(line,10));peers.Tag=text;}
    }
    void RenderDraft()
    {
        applying=true;try{name.Text=draft.DeviceName;level.SelectedItem=draft.LogLevel;}finally{applying=false;}
        name.Enabled=level.Enabled=draft.Initialized&&!pending;UpdateEditState();
    }
    void UpdateEditState()=>editState.Text=draft.Conflict?"后台的同一字段已改变，未覆盖你的草稿。请先撤销并核对最新值，再重新编辑。":draft.Dirty?"有未保存修改；状态刷新不会覆盖草稿。":"设置已同步";
    void Elevate(){try{ServiceInstaller.VerifyBundle(AppContext.BaseDirectory);Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=true,Verb="runas"});}catch(Exception ex){notice.Text="管理窗口未启动："+ex.Message;}}
}
