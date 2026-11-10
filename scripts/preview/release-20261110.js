'use strict';

// All changes and connections in this standalone preview stay in memory.
const $ = id => document.getElementById(id);
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const clone = value => JSON.parse(JSON.stringify(value));
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const stunDefaults = __STUN_DEFAULTS__;
const labels = {overview:'概况',create:'创建网络',join:'加入网络',requests:'加入申请',logs:'日志',settings:'设置'};
const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const sampleCode = '6B7K4H9M2W8DX5R3';
const defaultConfig = {
  protocol:'faketcp',mode:'auto',discovery:'pkarr',entries:[''],refresh:60,
  server:'',automaticIp:true,virtualIp:'',port:44680,certificatePin:'',
  tcpStun:stunDefaults.tcp.join('\n'),udpStun:stunDefaults.udp.join('\n'),
  pkarrRelays:['https://pkarr.pubky.app','https://pkarr.pubky.org']
};
const deviceDefaults = {name:'Akane-Laptop',startup:true,level:'info',terminal:'auto'};
const model = {
  ...deviceDefaults,
  networks:[
    {id:'desktop',name:'游戏主机',role:'guest',ip:'10.166.94.2',peer:'Akane-Desktop',peerIp:'10.166.94.1',online:true,rtt:12.3,sent:42600000,received:4850000000,seconds:596,entry:'203.0.113.42:8436',config:{...clone(defaultConfig),mode:'existing',entries:['https://entry.example.com/current#streamlink1']}},
    {id:'phone',name:'笔记本—手机',role:'host',ip:'10.181.42.1',peer:'Akane-Phone',peerIp:'10.181.42.2',online:false,rtt:null,sent:1820000,received:780000,seconds:0,entry:'',config:clone(defaultConfig)}
  ],
  requests:[{id:'phone-rejoin',network:'phone',device:'Akane-Phone',ip:'10.181.42.2',verification:'381 629',rejoin:true}]
};
const codes = new Map([['phone', sampleCode]]);
let page='overview',createName='',createConfig=clone(defaultConfig),createdId='',creating=false;
let joinCode='',joinPhase='idle',joinTimer=0,joinGeneration=0,joinedId='';
let editor=null,editorSection='connection',deviceDraft=null,toastTimer=0,confirmCallback=null;
let chartRange=60,chartTick=0,logsPaused=false,entryTestGeneration=0;
const history = Array.from({length:3601}, (_, i) => ({
  up:Math.max(0,.13+.035*Math.sin(i*.09)+.02*Math.cos(i*.03)),
  down:Math.max(.4,11.9+1.3*Math.sin(i*.08)+.5*Math.cos(i*.2)-(i%431>400?4.3:0))
}));
const logs = [
  ['19:52:03','info','ConWU 已启动'],
  ['19:52:04','info','已恢复 2 个网络，本机设置保持不变'],
  ['19:52:05','info','游戏主机：已取得主机入口，正在验证设备身份'],
  ['19:52:05','success','游戏主机：身份验证通过，已建立 FakeTCP + HTTP 直连'],
  ['19:52:06','info','游戏主机：虚拟地址 10.166.94.2，延迟 12.3 ms'],
  ['19:54:18','info','笔记本—手机：对端未在线，已保留网络和成员信息'],
  ['20:01:32','info','已有入口更新检查完成，地址未变，保留当前连接'],
  ['20:02:41','info','Akane-Phone 请求重新加入“笔记本—手机”，等待本机批准']
];

function protocol(c) { return c.protocol==='tcp'?'纯 TCP':'FakeTCP + HTTP'; }
function strategy(c) { return c.mode==='existing'?'只使用已有入口':'自主打洞'; }
function discovery(c) { return c.mode==='existing'?'订阅更新':({pkarr:'PKARR 自动发现',server:'协调服务器',direct:'手动直连码'}[c.discovery]); }
function role(n) { return n.role==='host'?'主机':'从机'; }
function bytes(n) { return n>=1e9?(n/1e9).toFixed(2)+' GB':n>=1e6?(n/1e6).toFixed(1)+' MB':(n/1000).toFixed(1)+' KB'; }
function connectedTime(n) { return `${Math.floor(n/86400)} 天 ${String(Math.floor(n/3600)%24).padStart(2,'0')} 时 ${String(Math.floor(n/60)%60).padStart(2,'0')} 分 ${String(n%60).padStart(2,'0')} 秒`; }
function heading(title,text='',extra='') { return `<div class="page-heading"><div><h1>${title}</h1>${text?`<p>${text}</p>`:''}</div>${extra}</div>`; }
function toggle(key,value,label,scope='network') { return `<label class="switch"><input type="checkbox" data-scope="${scope}" data-key="${key}" ${value?'checked':''} aria-label="${label}"><span class="switch-track"></span></label>`; }
function kv(label,value,mono=false) { return `<div class="kv"><span>${esc(label)}</span><span class="${mono?'mono':''}">${esc(value)}</span></div>`; }
function notify(message,error=false) {
  clearTimeout(toastTimer);
  $('toast').className='toast show'+(error?' error-toast':'');
  $('toast').innerHTML=icon(error?'info':'check')+'<span>'+esc(message)+'</span>';
  toastTimer=setTimeout(()=>$('toast').classList.remove('show'),3600);
}
function updateSidebar() {
  $('sidebar-name').textContent=model.name;
  $('sidebar-avatar').textContent=model.name.split(/[-\s]/).filter(Boolean).map(x=>x[0]).slice(0,2).join('').toUpperCase();
  $('request-count').textContent=model.requests.length;
  $('request-count').hidden=!model.requests.length;
  const exit=document.querySelector('[data-action="exit-network"]');
  exit.disabled=!model.networks.length;
  exit.title=model.networks.length?'退出网络':'当前没有可退出的网络';
}
function navigate(next) {
  if(!(next in labels)) return;
  page=next;
  render();
  window.scrollTo({top:0,behavior:'instant'});
}
function render() {
  document.querySelectorAll('.nav[data-page]').forEach(b=>{
    b.classList.toggle('active',b.dataset.page===page);
    if(b.dataset.page===page)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');
  });
  document.title=labels[page]+' · ConWU · 界面预览';
  updateSidebar();
  $('content').innerHTML=({overview:overviewPage,create:createPage,join:joinPage,requests:requestsPage,settings:settingsPage,logs:logsPage}[page])();
  if(page==='overview'){drawChart();bindChart();}
  if(page==='join')bindJoinInput();
  if(page==='settings')deviceDirty();
  if(page==='logs')renderLogLines();
}

function overviewPage() {
  const ns=model.networks,online=ns.filter(n=>n.online).length;
  const sent=ns.reduce((a,n)=>a+n.sent,0),received=ns.reduce((a,n)=>a+n.received,0);
  return heading('概况','本机信息与所有网络的连接状态。')+`
  <div class="overview-top">
    <article class="card pad device-card">
      <div class="row device-heading"><div class="avatar">${icon('laptop')}</div><div class="grow"><h2 class="device-name">${esc(model.name)}</h2></div></div>
    </article>
    <article class="card chart-card">
      <div class="chart-head"><h2>实时流量</h2><div class="range" role="group" aria-label="流量图时间范围"><button data-range="60" aria-pressed="${chartRange===60}" class="${chartRange===60?'active':''}">一分钟</button><button data-range="3600" aria-pressed="${chartRange===3600}" class="${chartRange===3600?'active':''}">一小时</button></div></div>
      <div class="chart-metrics"><div><div class="metric-caption"><span class="dot" style="background:var(--green)"></span>上传</div><div class="metric-value" id="chart-up">—<small>MB/s</small></div><div class="metric-total">累计 ${bytes(sent)}</div></div><div><div class="metric-caption"><span class="dot" style="background:var(--accent)"></span>下载</div><div class="metric-value" id="chart-down">—<small>MB/s</small></div><div class="metric-total">累计 ${bytes(received)}</div></div></div>
      <div class="chart-wrap" id="chart-wrap"><svg class="traffic-chart" id="traffic-chart" viewBox="0 0 640 128" preserveAspectRatio="none" role="img"></svg><div class="chart-tooltip" id="chart-tooltip" hidden></div></div>
    </article>
  </div>
  <article class="card overview-devices">
    <div class="table-title"><h2>设备与网络</h2></div>
    <div class="table-scroll"><table>
      <colgroup><col style="width:18%"><col style="width:13%"><col style="width:10%"><col style="width:19%"><col style="width:22%"><col style="width:8%"><col style="width:10%"></colgroup>
      <thead><tr><th scope="col">设备</th><th scope="col">网络</th><th scope="col">角色</th><th scope="col">虚拟 IP</th><th scope="col">连接状态</th><th scope="col">延迟</th><th scope="col">流量</th></tr></thead>
      <tbody><tr class="local-row"><td><div class="row">${icon('laptop')}<strong class="peer-name">${esc(model.name)}</strong></div></td><td colspan="6" class="self-label">本机</td></tr>
      ${ns.map(n=>`<tr data-peer-row="${n.id}"><td><div class="row"><div class="avatar peer">${icon(n.peer.includes('Phone')?'link':'laptop')}</div><strong class="peer-name">${esc(n.peer)}</strong></div></td><td>${esc(n.name)}</td><td class="role-value"><div class="paired-values"><div class="paired-line"><span class="paired-label">本机</span><span data-value="local-role">${role(n)}</span></div><div class="paired-line"><span class="paired-label">对机</span><span data-value="peer-role">${n.role==='host'?'从机':'主机'}</span></div></div></td><td><div class="paired-values"><div class="paired-line"><span class="paired-label">本机</span><span class="mono" data-value="local-ip">${esc(n.ip)}</span></div><div class="paired-line"><span class="paired-label">对机</span><span class="mono" data-value="peer-ip">${esc(n.peerIp||'待分配')}</span></div></div></td><td><div class="cell-status"><span class="dot ${n.online?'good':''}"></span>${n.online?'已直连':n.peerIp==='待分配'?'等待加入':'未在线'}</div><div class="cell-sub">${protocol(n.config)}</div>${n.online?`<div class="cell-sub">已直连 <span data-duration="${n.id}">${connectedTime(n.seconds)}</span></div><div class="cell-sub entry">实际入口：<span class="mono">${esc(n.entry||'入站连接')}</span></div>`:'<div class="cell-sub">对端上线后恢复连接</div>'}</td><td class="mono">${n.online?n.rtt.toFixed(1)+'<span class="dim small"> ms</span>':'<span class="dim">—</span>'}</td><td><div class="traffic-cell"><div><span class="up">↑</span> ${bytes(n.sent)}<div class="rate">${n.online?'0.14':'0.00'} MB/s</div></div><div><span class="down">↓</span> ${bytes(n.received)}<div class="rate">${n.online?'12.80':'0.00'} MB/s</div></div></div></td></tr>`).join('')}
      </tbody></table></div>
    <div class="device-table-foot"><span class="dot ${online?'good':''}"></span><span>${ns.length} 个网络</span><span>·</span><span class="direct-total">与其余 ${online} 台设备直连</span></div>
  </article>`;
}

function chartPoints() {
  const values=history.slice(-(chartRange+1));
  const step=Math.max(1,Math.floor(chartRange/120));
  return values.filter((_,i)=>i%step===0||i===values.length-1).map((value,i,all)=>({...value,x:32+i*600/(all.length-1)}));
}
function drawChart() {
  const svg=$('traffic-chart');
  if(!svg)return;
  const values=chartPoints(),max=16,points=key=>values.map(p=>`${p.x},${104-p[key]/max*98}`).join(' ');
  let grid='';
  for(const value of [0,4,8,12,16]) {
    const y=104-value/max*98;
    grid+=`<line x1="32" y1="${y}" x2="632" y2="${y}" stroke="var(--line)" stroke-opacity=".55" stroke-dasharray="3 5"/><text x="22" y="${y+3}" fill="var(--dim)" text-anchor="end" font-size="8">${value}</text>`;
  }
  const times=chartRange===60?['1 分钟前','30 秒前','现在']:['1 小时前','30 分钟前','现在'];
  times.forEach((label,i)=>grid+=`<text x="${32+i*300}" y="123" text-anchor="${i===0?'start':i===2?'end':'middle'}" fill="var(--dim)" font-size="8">${label}</text>`);
  svg.setAttribute('aria-label',`最近${chartRange===60?'一分钟':'一小时'}的上传与下载速度折线图`);
  svg.innerHTML=`<defs><linearGradient id="down-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--accent)" stop-opacity=".2"/><stop offset="100%" stop-color="var(--accent)" stop-opacity=".015"/></linearGradient></defs>${grid}<polygon points="32,104 ${points('down')} 632,104" fill="url(#down-fill)"/><polyline data-series="down" points="${points('down')}" fill="none" stroke="var(--accent)" stroke-width="1.8" vector-effect="non-scaling-stroke" stroke-linejoin="round"/><polyline points="${points('up')}" fill="none" stroke="var(--green)" stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linejoin="round"/><line id="chart-cursor" x1="0" y1="4" x2="0" y2="104" stroke="var(--muted)" stroke-opacity=".5" stroke-dasharray="2 3" visibility="hidden"/>`;
  const current=history.at(-1),online=model.networks.some(n=>n.online);
  $('chart-up').innerHTML=(online?current.up:0).toFixed(2)+'<small>MB/s</small>';
  $('chart-down').innerHTML=(online?current.down:0).toFixed(2)+'<small>MB/s</small>';
}
function bindChart() {
  const wrap=$('chart-wrap');
  wrap.onpointermove=e=>{
    const rect=wrap.getBoundingClientRect(),svgX=(e.clientX-rect.left)/rect.width*640;
    const fraction=Math.max(0,Math.min(1,(svgX-32)/600));
    const ago=Math.round((1-fraction)*chartRange),value=history[history.length-1-ago];
    const tooltip=$('chart-tooltip'),cursor=$('chart-cursor');
    const time=ago>=60?`${Math.floor(ago/60)} 分 ${ago%60} 秒前`:ago?`${ago} 秒前`:'现在';
    tooltip.hidden=false;
    tooltip.innerHTML=`${time}<br><span style="color:var(--accent)">↓ ${value.down.toFixed(2)} MB/s</span> · <span style="color:var(--green)">↑ ${value.up.toFixed(2)} MB/s</span>`;
    tooltip.style.left=Math.max(0,Math.min(rect.width-190,e.clientX-rect.left-85))+'px';
    cursor.setAttribute('x1',32+fraction*600);cursor.setAttribute('x2',32+fraction*600);cursor.setAttribute('visibility','visible');
  };
  wrap.onpointerleave=()=>{$('chart-tooltip').hidden=true;$('chart-cursor').setAttribute('visibility','hidden');};
}

function settingsLaunch(id='') {
  const c=id?model.networks.find(n=>n.id===id).config:createConfig;
  return `<button class="settings-launch" type="button" data-action="open-network-settings" data-network="${id}" id="open-network-settings">${icon('settings')}<span class="grow"><strong>网络设置</strong><small>${protocol(c)} · ${strategy(c)} · ${c.automaticIp?'自动分配虚拟 IP':'自定义虚拟 IP'}</small></span><span class="open-label">打开设置${icon('chevron')}</span></button>`;
}
function networkList(kind) {
  const host=kind==='host',networks=model.networks.filter(n=>n.role===(host?'host':'guest'));
  const rows=networks.map(n=>`<div class="list-row ${host&&n.id===createdId?'selected':''}" data-network-row="${n.id}">
    <div class="grow">${host?`<button class="network-name-button" data-action="view-host-network" data-network="${n.id}" title="查看直连码">${esc(n.name)}</button>`:`<strong>${esc(n.name)}</strong>`}
      <div class="network-local-ip">本机虚拟 IP：<span class="mono">${esc(n.ip)}</span></div>
      <div class="network-peer"><span class="dot ${n.online?'good':''}"></span><span>${n.peerIp==='待分配'?'等待另一台设备加入':n.online?'已直连 '+esc(n.peer):'等待 '+esc(n.peer)+' 上线'}</span></div>
      <div class="network-peer-ip">对机虚拟 IP：<span class="mono">${esc(n.peerIp||'待分配')}</span></div>
    </div>
    <div class="network-row-actions"><button class="btn compact" data-action="open-network-settings" data-network="${n.id}">${icon(host?'settings':'info')}${host?'网络设置':'查看设置'}</button><button class="text-btn danger-text" data-action="${host?'delete-owned':'delete-joined'}" data-network="${n.id}">${host?'删除网络':'退出网络'}</button></div>
  </div>`).join('');
  return `<article class="card network-list-card" id="${host?'owned':'joined'}-networks"><div class="table-title"><h2>本机${host?'创建':'加入'}的网络</h2><span class="small">${networks.length} 个网络</span></div>${networks.length?rows:`<div class="empty">${icon(host?'create':'join')}<h2>还没有${host?'创建':'加入'}网络</h2><p>${host?'在左侧创建后，会在这里显示。':'通过主机审批后，会在这里显示。'}</p></div>`}</article>`;
}
function normalizeCode(value) {return value.toUpperCase().replace(/[\s\u2010-\u2015-]/g,'').replace(/O/g,'0').replace(/[IL]/g,'1');}
function formattedCode(value) {return value.match(/.{1,4}/g)?.join('-')||'';}
function codeGroups(value,placeholder=false) {
  return `<div class="direct-groups" aria-hidden="true">${Array.from({length:4},(_,group)=>`<div class="direct-group">${Array.from({length:4},(_,index)=>{const char=value[group*4+index];return `<span class="direct-digit ${char?'filled':placeholder?'placeholder':''}">${esc(char||(placeholder?'X':''))}</span>`;}).join('')}</div>`).join('')}</div>`;
}
function helpLink(kind) {return `<div class="form-help"><button class="help-link" type="button" data-action="help-${kind}">如何${kind==='create'?'创建':'加入'}网络？</button></div>`;}
function createPage() {
  const created=model.networks.find(n=>n.id===createdId&&n.role==='host');
  const form=created?`
    <div class="created-network-title"><h2>${esc(created.name)}</h2><span class="badge good">${icon('check')}网络已创建</span></div>
    ${kv('本机虚拟 IP',created.ip,true)}${settingsLaunch(created.id)}
    <div class="code-label-row"><h3>本机直连码</h3><span class="hint">16 位</span></div>
    <div class="code-control direct-code-control direct-code-readonly" role="group" aria-label="本机直连码：${formattedCode(codes.get(created.id)||sampleCode)}">${codeGroups(codes.get(created.id)||sampleCode)}</div>
    <div class="code-actions"><button class="btn compact" data-action="regenerate-code">${icon('refresh')}重新生成</button><button class="btn compact" data-action="copy-code">${icon('copy')}复制</button></div>
    <div class="form-operation"><button class="btn" data-action="new-create">${icon('plus')}再创建一个网络</button></div>${helpLink('create')}`:`
    <form id="create-form"><label class="field"><span>网络名称</span><input id="new-network-name" class="form-input-large" placeholder="例如：主机—笔记本" value="${esc(createName)}" maxlength="48" autocomplete="off"></label>
    ${settingsLaunch()}<div class="error" id="create-error" role="status"></div>
    <div class="form-operation"><button class="btn primary" id="create-network" type="submit" ${creating?'disabled':''}>${icon(creating?'refresh':'plus')}${creating?'正在创建…':'创建网络'}</button></div>${helpLink('create')}</form>`;
  return heading('创建网络','以本机为主机，创建网络')+`<div class="network-columns"><article class="card create-form"><div class="pad">${form}</div></article>${networkList('host')}</div>`;
}
function joinPage() {
  const done=model.networks.find(n=>n.id===joinedId),waiting=joinPhase!=='idle'&&joinPhase!=='done';
  let form;
  if(waiting) {
    const text={locating:['正在联系目标主机','正在读取直连码中的入口，核对目标网络。'],waiting:['等待主机同意','请在目标主机上核对并批准加入申请。'],applying:['主机已同意','正在获取连接设置并分配本机虚拟 IP。']}[joinPhase];
    form=`<div class="waiting-card"><div class="status-orbit">${icon(joinPhase==='waiting'?'clock':'refresh')}</div><h2>${text[0]}</h2><p>${text[1]}</p>${joinPhase==='waiting'?`<div class="kv-list">${kv('双方校验码','582 149',true)}</div>`:''}<div class="progress-track"><span></span></div><span class="hint">本机：${esc(model.name)}</span>${joinPhase!=='applying'?'<div><button class="btn" data-action="cancel-join">取消申请</button></div>':''}</div>`;
  } else if(done&&joinPhase==='done') {
    form=`<div class="waiting-card"><div class="status-orbit success">${icon('check')}</div><h2>已加入 ${esc(done.name)}</h2><div class="kv-list">${kv('本机虚拟 IP',done.ip,true)}${kv('目标设备',done.peer)}</div><div class="form-operation"><button class="btn primary" data-page="overview">查看概况</button><button class="btn" data-action="another-join">加入其他网络</button></div></div>`;
  } else {
    form=`<form id="join-form"><label class="pair-label" for="join-code">目标主机的直连码</label><div class="code-control direct-code-control">${codeGroups(normalizeCode(joinCode),true)}<input id="join-code" aria-label="目标主机的16位直连码" type="text" maxlength="19" spellcheck="false" autocomplete="off" autocapitalize="characters" value="${esc(formattedCode(joinCode))}"></div><div class="error" id="join-error" role="status"></div><div class="form-operation"><button type="submit" class="btn primary" id="join-submit">请求加入${icon('join')}</button></div>${helpLink('join')}</form>`;
  }
  return heading('加入网络','向目标主机发送申请，加入网络')+`<div class="network-columns"><article class="card pad" id="join-card">${form}</article>${networkList('guest')}</div>`;
}
function bindJoinInput() {
  const input=$('join-code');
  if(input) {
    // The model stores 16 symbols; the input contains exactly one display mask.
    const logicalOffset=offset=>normalizeCode(input.value.slice(0,offset||0)).length;
    const visibleOffset=offset=>Math.min(input.value.length,offset+Math.floor(offset/4));
    const updateSlots=()=>{
      const value=normalizeCode(input.value);
      const start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);
      document.querySelectorAll('#join-card .direct-digit').forEach((digit,index)=>{
        digit.textContent=value[index]||'X';
        digit.classList.toggle('filled',!!value[index]);digit.classList.toggle('placeholder',!value[index]);
        digit.classList.toggle('active',document.activeElement===input&&start===end&&index===Math.min(start,15));
        digit.classList.toggle('selected',document.activeElement===input&&index>=start&&index<end);
      });
    };
    const apply=(value,start,end=start)=>{
      joinCode=normalizeCode(value).slice(0,16);
      input.value=formattedCode(joinCode);
      input.setSelectionRange(visibleOffset(start),visibleOffset(end));
      $('join-error').textContent='';updateSlots();
    };
    const replaceSelection=text=>{
      const start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);
      const current=normalizeCode(input.value),room=16-(current.length-(end-start));
      const insertion=normalizeCode(text).slice(0,Math.max(0,room));
      apply(current.slice(0,start)+insertion+current.slice(end),start+insertion.length);
    };
    input.oninput=()=>apply(input.value,logicalOffset(input.selectionStart),logicalOffset(input.selectionEnd));
    input.onbeforeinput=event=>{
      if(!['deleteContentBackward','deleteContentForward'].includes(event.inputType))return;
      event.preventDefault();
      let start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);
      if(start===end){if(event.inputType==='deleteContentBackward')start=Math.max(0,start-1);else end=Math.min(16,end+1);}
      const current=normalizeCode(input.value);
      apply(current.slice(0,start)+current.slice(end),start);
    };
    input.onpaste=event=>{event.preventDefault();replaceSelection(event.clipboardData.getData('text/plain'));};
    input.oncopy=event=>{
      if(input.selectionStart===input.selectionEnd)return;
      event.preventDefault();
      event.clipboardData.setData('text/plain',formattedCode(normalizeCode(input.value.slice(input.selectionStart,input.selectionEnd))));
    };
    input.oncut=event=>{
      if(input.selectionStart===input.selectionEnd)return;
      event.preventDefault();
      event.clipboardData.setData('text/plain',formattedCode(normalizeCode(input.value.slice(input.selectionStart,input.selectionEnd))));
      replaceSelection('');
    };
    input.onfocus=input.onclick=input.onkeyup=input.onselect=updateSlots;
    input.onblur=()=>document.querySelectorAll('#join-card .direct-digit').forEach(d=>d.classList.remove('active','selected'));
  }
  if($('join-form'))$('join-form').onsubmit=e=>{e.preventDefault();startJoin();};
}

function requestsPage() {
  return heading('加入申请','核对设备和校验码，决定是否允许加入。',`<span class="badge ${model.requests.length?'amber':''}">${model.requests.length} 条待处理</span>`)+(model.requests.length?model.requests.map(r=>{
    const n=model.networks.find(n=>n.id===r.network);
    return `<article class="card pad request-card"><div class="request-top"><div class="row"><div class="avatar">AP</div><div><h2>${esc(r.device)}</h2><p class="hint" style="margin-top:4px">${r.rejoin?'请求重新加入':'请求加入'}“${esc(n.name)}”</p></div></div><span class="badge amber">等待批准</span></div><div class="request-meta"><div><span>目标网络</span><strong>${esc(n.name)}</strong></div><div><span>预分配虚拟 IP</span><strong class="mono">${esc(r.ip)}</strong></div><div><span>双方校验码</span><strong class="mono" style="letter-spacing:2px">${esc(r.verification)}</strong></div></div><div class="request-actions"><p class="hint">请与对端核对校验码一致后批准。</p><div class="row"><button class="btn positive" data-action="approve-request" data-request="${r.id}">${icon('check')}同意加入</button><button class="btn danger" data-action="reject-request" data-request="${r.id}">${icon('x')}拒绝</button></div></div></article>`;
  }).join(''):`<article class="card empty">${icon('shield')}<h2>没有待处理的加入申请</h2><p>收到新申请后，会在这里显示设备与校验信息。</p></article>`);
}
function pageSaveActions() {
  return `<div class="heading-actions"><div class="heading-action-buttons"><button class="btn" id="default-device" data-action="default-device">恢复默认设置</button><button class="btn" id="revert-device" data-action="revert-device">恢复刚才设置</button><button class="btn primary" id="save-device" data-action="save-device">${icon('save')}保存设置</button></div><span class="save-state" id="device-save-state" role="status">已保存</span></div>`;
}
function settingsPage() {
  if(!deviceDraft)deviceDraft=deviceValues();
  return heading('设置','',pageSaveActions())+`<article class="card settings-page">
    <section class="settings-section"><div><h2>启动与服务</h2><p class="intro">配置开机启动与服务</p></div><div><div class="switch-row"><div><h3>开机启动</h3><p>启动后台服务，登录后显示托盘。</p></div>${toggle('startup',deviceDraft.startup,'开机启动','device')}</div><div class="row between"><span class="small muted">后台服务</span><span class="badge good">${icon('check')}已注册 · 正在运行</span></div></div></section>
    <section class="settings-section"><div><h2>本机设备名</h2><p class="intro">所有网络统一使用这个设备名称。</p></div><label class="field"><span>设备名称</span><input id="device-name" data-scope="device" data-key="name" value="${esc(deviceDraft.name)}" maxlength="64" autocomplete="off"></label></section>
    <section class="settings-section"><div><h2>日志设置</h2><p class="intro">调整日志详细程度与终端外观</p></div><div><label class="field"><span>日志等级</span><select data-scope="device" data-key="level">${[['error','仅错误'],['warn','警告与错误'],['info','常规信息'],['debug','详细调试'],['off','关闭记录']].map(([v,t])=>`<option value="${v}" ${deviceDraft.level===v?'selected':''}>${t}</option>`).join('')}</select></label><label class="field"><span>终端外观</span><select data-scope="device" data-key="terminal">${[['auto','跟随界面'],['dark','深色'],['light','浅色']].map(([v,t])=>`<option value="${v}" ${deviceDraft.terminal===v?'selected':''}>${t}</option>`).join('')}</select></label><button class="text-btn" data-page="logs">打开日志${icon('chevron')}</button></div></section>
  </article>`;
}
function deviceValues() {return {name:model.name,startup:model.startup,level:model.level,terminal:model.terminal};}
function deviceDirty() {
  if(!$('save-device'))return;
  const changed=!equal(deviceDraft,deviceValues());
  $('save-device').disabled=$('revert-device').disabled=!changed;
  $('default-device').disabled=equal(deviceDraft,deviceDefaults);
  $('device-save-state').className='save-state'+(changed?' dirty':'');
  $('device-save-state').textContent=changed?'有未保存的更改':'已保存';
}
function logsPage() {
  const light=model.terminal==='light'||model.terminal==='auto'&&document.documentElement.dataset.theme==='light';
  return heading('日志','查看设备连接与网络运行记录。',`<button class="btn compact" data-action="export-logs">${icon('download')}导出日志</button>`)+`<article class="card"><div class="log-tools"><input id="log-search" aria-label="搜索日志" placeholder="搜索日志内容"><select id="log-filter" aria-label="筛选日志"><option value="all">全部等级</option><option value="info">常规信息</option><option value="warn">警告与错误</option></select><button class="btn compact" data-action="pause-logs" id="pause-logs">${logsPaused?'继续更新':'暂停更新'}</button></div><div class="terminal ${light?'light':''}" id="log-lines" role="log"></div><div class="log-foot"><span>${logsPaused?'已暂停更新':'正在显示最新记录'}</span><span>本机时间 · UTF-8</span></div></article>`;
}
function renderLogLines() {
  if(!$('log-lines'))return;
  const query=$('log-search').value.toLowerCase(),filter=$('log-filter').value;
  const found=logs.filter(l=>(filter==='all'||filter==='info'&&['info','success'].includes(l[1])||filter==='warn'&&['warn','error'].includes(l[1]))&&l[2].toLowerCase().includes(query));
  $('log-lines').innerHTML=found.map(l=>`<div class="log-line"><span class="log-time">${l[0]}</span><span class="${l[1]}">[${l[1]==='success'?'INFO':l[1].toUpperCase()}]</span> ${esc(l[2])}</div>`).join('')||'<span class="dim">没有匹配的日志。</span>';
}

function editorSections() {
  const d=editor.readOnly?editor.base:editor.draft;
  const sections=[['connection','连接方式','link']];
  if(d.mode==='existing')sections.push(['entry','已有入口','globe']);
  else {
    sections.push(['discovery','配对与发现方式','globe']);
  }
  sections.push(['virtual','虚拟 IP','laptop'],['ports','端口设置','port']);
  if(d.mode==='auto')sections.push(['stun','STUN 服务器','globe']);
  return sections;
}
function openNetworkSettings(id='') {
  const n=id?model.networks.find(n=>n.id===id):null;
  if(id&&!n)return;
  const readOnly=n?.role==='guest';
  editor={id,readOnly,base:clone(n?n.config:createConfig),draft:clone(n?n.config:createConfig)};
  editorSection='connection';
  $('network-dialog').classList.toggle('read-only',readOnly);
  $('network-dialog-title').textContent=readOnly?'主机提供的网络设置 · '+n.name:id?'网络设置 · '+n.name:'新网络设置';
  $('network-dialog-subtitle').textContent=readOnly?'由 '+n.peer+' 提供，仅供查看。':id?'仅应用于“'+n.name+'”。':'设置本次创建网络使用的连接方式与虚拟地址。';
  $('network-edit-actions').hidden=readOnly;
  $('network-readonly-close').hidden=!readOnly;
  renderEditor();
  $('network-dialog').showModal();
}
function readonlyRows(rows) {
  return `<dl class="readonly-values">${rows.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value||'未设置')}</dd></div>`).join('')}</dl>`;
}
function renderReadonlyEditor() {
  const d=editor.base,n=model.networks.find(n=>n.id===editor.id);
  const definitions={
    connection:['连接方式',[['连接协议',protocol(d)],['连接策略',strategy(d)]]],
    discovery:['配对与发现方式',[['发现方式',discovery(d)],['首次配对','使用主机生成的 16 位直连码'],...(d.discovery==='pkarr'?[['发现状态','已启用'],['发现网关',d.pkarrRelays.join('\n')],['入口更新','跟随主机发布的签名记录']]:d.discovery==='server'?[['HTTPS 协调服务器',d.server],['证书 SHA-256 指纹（可选）',d.certificatePin||'使用系统证书信任'],['用途','更新入口与交换连接信息']]:[['入口更新','入口变化后重新交换直连码']])]],
    entry:['目标主机入口',[['入口地址／订阅',d.entries.filter(Boolean).join('\n')],['订阅更新间隔',d.refresh+' 秒'],['当前实际入口',n.entry||'尚未建立连接']]],
    virtual:['此网络的虚拟 IP',[['本机虚拟 IP',n.ip],['主机虚拟 IP',n.peerIp],['分配方式','由主机授权分配']]],
    ports:['主机端口',[['主机接收端口',String(d.port)],['本机连接端口','由本机运行环境分配']]],
    stun:['主机提供的 STUN 设置',[['TCP STUN',d.tcpStun],['UDP STUN',d.udpStun]]]
  };
  const [title,rows]=definitions[editorSection];
  $('network-settings-body').innerHTML=`<div class="note readonly-intro">${icon('shield')}<span>以下设置由主机提供，本机仅供查看。</span></div><h3>${title}</h3>${readonlyRows(rows)}`;
}
function renderEditor() {
  if(!editor)return;
  entryTestGeneration++;
  const sections=editorSections();
  if(!sections.some(s=>s[0]===editorSection))editorSection='connection';
  $('network-settings-nav').innerHTML=sections.map(([id,name,ico])=>`<button class="${editorSection===id?'active':''}" data-editor-section="${id}" ${editorSection===id?'aria-current="page"':''}>${icon(ico)}${name}</button>`).join('');
  if(editor.readOnly){renderReadonlyEditor();editorDirty();return;}
  const d=editor.draft;
  let html='';
  if(editorSection==='connection') {
    html=`<h3>连接协议</h3><div class="radio-cards">${[['faketcp','FakeTCP + HTTP','适合高码率串流，默认使用。'],['tcp','纯 TCP','后续功能，暂不可选。']].map(([v,t,h])=>`<label class="radio-card ${v==='tcp'?'unavailable':''}" ${v==='tcp'?'aria-disabled="true"':''}><input type="radio" name="network-protocol" value="${v}" data-scope="network" data-key="protocol" ${d.protocol===v?'checked':''} ${v==='tcp'?'disabled':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div><h3>连接策略</h3><div class="radio-cards">${[['auto','自主打洞','由 ConWU 准备入口并尝试穿透。'],['existing','只使用已有入口','公网、端口转发或第三方已打通的入口。']].map(([v,t,h])=>`<label class="radio-card"><input type="radio" name="network-mode" value="${v}" data-scope="network" data-key="mode" ${d.mode===v?'checked':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div><div class="note strategy-note">${icon('info')}<span>${d.mode==='existing'?'仅通过已有入口连接。':'首次使用直连码配对；后续入口更新可在左侧“配对与发现方式”中设置。'}</span></div>`;
  }
  if(editorSection==='discovery') {
    const tips={pkarr:'首次通过直连码配对，之后经由 PKARR 发布和查询最新地址。',server:'使用你指定的协调服务器更新入口与交换连接信息；首次配对仍使用直连码。',direct:'只通过直连码配对连接；入口变化后，需要重新生成并输入直连码。'};
    let fields='';
    if(d.discovery==='pkarr')fields=`<section class="discovery-settings"><h3>PKARR 发现</h3><label class="field"><span>发现网关（每行一个）</span><textarea data-scope="network" data-key="pkarrRelays" spellcheck="false" class="pkarr-endpoints">${esc(d.pkarrRelays.join('\n'))}</textarea></label>${editor.id?`<div class="pkarr-status">${kv('发现状态','运行正常')}${kv('入口发布','已发布 · 示例数据')}${kv('最后更新','刚刚')}</div>`:''}</section>`;
    if(d.discovery==='server')fields=`<section class="discovery-settings"><h3>HTTPS 协调服务器</h3><label class="field"><span>协调服务器地址</span><input data-scope="network" data-key="server" value="${esc(d.server)}" placeholder="https://coord.example.com/" spellcheck="false"></label><label class="field"><span>证书 SHA-256 指纹（可选）</span><input class="mono" data-scope="network" data-key="certificatePin" spellcheck="false" value="${esc(d.certificatePin)}" placeholder="留空使用系统证书信任"></label></section>`;
    html=`<h3>配对与发现方式</h3><label class="field"><span>发现方式</span><select data-scope="network" data-key="discovery">${[['pkarr','PKARR 自动发现（默认）'],['server','自建协调服务器（高级）'],['direct','仅直连码 · 手动更新入口']].map(([v,t])=>`<option value="${v}" ${d.discovery===v?'selected':''}>${t}</option>`).join('')}</select></label><div class="note discovery-note">${icon('info')}<span>${tips[d.discovery]}</span></div>${fields}`;
  }
  if(editorSection==='entry') {
    html=`<h3>本机已有入口</h3><div class="entry-copy"><p class="hint">填写本机的公网 IP:端口、已打通的地址或 HTTPS/TXT 等订阅链接。</p><p class="hint">若填写的不是可更新的订阅链接，入口变化后需要重新填写新入口地址。</p></div><div id="editor-entry-rows">${d.entries.map((value,i)=>`<div class="entry-row"><input data-entry="${i}" value="${esc(value)}" spellcheck="false" aria-label="本机入口 ${i+1}" placeholder="IP:端口 或 HTTPS/TXT 等订阅链接"><button class="btn" data-action="${i===d.entries.length-1?'add-entry':'remove-entry'}" data-entry-index="${i}" aria-label="${i===d.entries.length-1?'添加入口':'移除此入口'}">${icon(i===d.entries.length-1?'plus':'x')}</button></div>`).join('')}</div><div class="entry-test"><button class="btn compact" data-action="test-entry">${icon('refresh')}测试地址</button><span class="hint" id="entry-test-state" role="status"></span></div><label class="field"><span>订阅更新间隔（秒）</span><input type="number" min="1" max="86400" data-scope="network" data-key="refresh" value="${d.refresh}"></label>`;
  }
  if(editorSection==='virtual')html=`<h3>本机在此网络中的虚拟 IP</h3><div class="radio-cards"><label class="radio-card"><input type="radio" name="ip-mode" data-scope="network" data-key="automaticIp" value="true" ${d.automaticIp?'checked':''}><strong>自动分配</strong><small>自动选择可用网段，避免与其他网络冲突。</small></label><label class="radio-card"><input type="radio" name="ip-mode" data-scope="network" data-key="automaticIp" value="false" ${!d.automaticIp?'checked':''}><strong>自定义地址</strong><small>指定本机在此网络使用的私有 IPv4 地址。</small></label></div>${!d.automaticIp?`<label class="field"><span>自定义虚拟 IP</span><input class="mono" data-scope="network" data-key="virtualIp" value="${esc(d.virtualIp)}" placeholder="10.171.139.1" spellcheck="false"></label>`:''}`;
  if(editorSection==='ports')html=`<h3>接收端口</h3><label class="field"><span>ConWU 接收端口</span><input type="number" data-scope="network" data-key="port" min="1024" max="65535" value="${d.port}"><span class="hint">已有入口应映射到这个端口。</span></label><div class="note">${icon('info')}<span>修改接收端口后，请同步核对公网转发或外部打洞工具的配置。</span></div>`;
  if(editorSection==='stun')html=`<h3>打洞 STUN 服务器</h3><div class="stun-columns">${[['tcpStun','TCP STUN'],['udpStun','UDP STUN']].map(([key,title])=>`<label class="field"><span>${title}<small>${d[key].split(/\n/).filter(v=>v.trim()).length} 个地址</small></span><textarea data-scope="network" data-key="${key}" spellcheck="false" wrap="off" aria-label="${title} 服务器列表">${esc(d[key])}</textarea></label>`).join('')}</div>`;
  $('network-settings-body').innerHTML=html+'<div class="error" id="network-settings-error" role="status"></div>';
  editorDirty();
}
function editorDirty() {
  if(!editor)return;
  if(editor.readOnly){$('network-save-state').textContent='主机设置 · 仅供查看';$('network-save-state').className='save-state';return;}
  const changed=!equal(editor.base,editor.draft);
  $('network-save-state').textContent=changed?'有未保存的更改':'没有未保存的修改';
  $('network-save-state').className='save-state'+(changed?' dirty':'');
  document.querySelector('[data-action="save-network-settings"]').disabled=!changed;
  document.querySelector('[data-action="revert-network-settings"]').disabled=!changed;
}
function privateIp(ip) {
  const parts=ip.split('.');
  if(parts.length!==4||parts.some(x=>!/^\d{1,3}$/.test(x)||Number(x)>255))return false;
  const a=parts.map(Number);
  return a[3]>0&&a[3]<255&&(a[0]===10||a[0]===172&&a[1]>=16&&a[1]<=31||a[0]===192&&a[1]===168);
}
function validateConfig(d,id='') {
  if(!Number.isInteger(d.port)||d.port<1024||d.port>65535)return ['ports','接收端口应为 1024～65535 之间的整数。'];
  if(d.mode==='existing'&&(!Number.isInteger(d.refresh)||d.refresh<1||d.refresh>86400))return ['entry','更新间隔应为 1 秒至 24 小时。'];
  if(!d.automaticIp&&!privateIp(d.virtualIp))return ['virtual','请填写有效的私有 IPv4 地址，例如 10.171.139.1。'];
  if(!d.automaticIp){const prefix=d.virtualIp.split('.').slice(0,3).join('.');if(model.networks.some(n=>n.id!==id&&n.ip.split('.').slice(0,3).join('.')===prefix))return ['virtual','此网段已用于其他网络，请选择其他网段。'];}
  if(d.mode==='auto'&&d.discovery==='server') {
    try{const u=new URL(d.server);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();}catch{return ['discovery','请填写有效的 HTTPS 协调服务器地址。'];}
    if(d.certificatePin&&!/^[a-f0-9]{64}$/i.test(d.certificatePin))return ['discovery','证书指纹应为 64 位十六进制字符。'];
  }
  if(d.mode==='auto')for(const key of ['tcpStun','udpStun'])if(!d[key].trim())return ['stun','请填写 STUN 服务器地址。'];
  if(d.mode==='auto'&&d.discovery==='pkarr') {
    try{if(!d.pkarrRelays.length)throw Error();for(const relay of d.pkarrRelays){const u=new URL(relay);if(u.protocol!=='https:'||u.username||u.password)throw Error();}}catch{return ['discovery','请填写有效的 HTTPS 发现网关。'];}
  }
  return null;
}
function saveNetworkSettings() {
  if(!editor||editor.readOnly)return;
  const error=validateConfig(editor.draft,editor.id);
  if(error){editorSection=error[0];renderEditor();$('network-settings-error').textContent=error[1];$('network-settings-error').scrollIntoView({block:'nearest'});return;}
  if(editor.id) {
    const n=model.networks.find(n=>n.id===editor.id);
    if(!n){notify('这个网络已被移除',true);return;}
    n.config=clone(editor.draft);
    if(!editor.draft.automaticIp)n.ip=editor.draft.virtualIp;
  } else createConfig=clone(editor.draft);
  $('network-dialog').close();editor=null;render();notify('预览：网络设置已保存');
}
function closeEditor() {
  if(editor&&!editor.readOnly&&!equal(editor.base,editor.draft)) {
    ask('放弃未保存的设置？','已保存的设置会保持不变。','放弃修改',()=>{$('network-dialog').close();editor=null;});return;
  }
  $('network-dialog').close();editor=null;
}
function ask(title,description,label,callback,extra='') {
  confirmCallback=callback;
  $('confirm-title').textContent=title;
  $('confirm-description').textContent=description;
  $('confirm-action').textContent=label;
  $('confirm-extra').innerHTML=extra;
  $('confirm-dialog').showModal();
}
function openHelp(kind) {
  const create=kind==='create';
  $('help-title').textContent=create?'如何创建网络？':'如何加入网络？';
  const steps=create?['首先输入“网络名称”与设置“网络设置”；','在本机生成16位“直连码”。']:['在“输入框”处填写目标主机所生成的16位“直连码”','等待目标主机通过“加入申请”批准本机加入'];
  $('help-content').innerHTML=steps.map((step,i)=>`<p class="help-step"><span>${i?'②':'①'}</span>${esc(step)}</p>`).join('');
  $('help-dialog').showModal();
}
function randomCode() {return Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>alphabet[n&31]).join('');}
function nextIp(host=true) {
  let subnet=36;
  while(model.networks.some(n=>n.ip.startsWith('10.188.'+subnet+'.')))subnet++;
  return '10.188.'+subnet+(host?'.1':'.2');
}
function createNetwork() {
  if(creating)return;
  const name=createName.trim();
  if(!name){$('create-error').textContent='请为这个网络起一个名称。';$('new-network-name').focus();return;}
  if(createConfig.mode==='existing'&&!createConfig.entries.some(s=>s.trim())){$('create-error').textContent='请在“网络设置”中填写本机的已有入口。';return;}
  const error=validateConfig(createConfig);
  if(error){$('create-error').textContent=error[1];return;}
  const snapshot=clone(createConfig);
  creating=true;render();
  setTimeout(()=>{
    const id='created-'+crypto.randomUUID();
    model.networks.push({id,name,role:'host',ip:snapshot.automaticIp?nextIp():snapshot.virtualIp,peer:'等待另一台设备',peerIp:'待分配',online:false,rtt:null,sent:0,received:0,seconds:0,entry:'',config:snapshot});
    codes.set(id,randomCode());createdId=id;creating=false;render();notify('预览：网络已创建，已生成示例直连码');
  },550);
}
function startJoin() {
  const code=normalizeCode(joinCode);
  if(!/^[0-9A-HJKMNP-TV-Z]{16}$/.test(code)){$('join-error').textContent='请输入完整的 16 位字母数字直连码。';$('join-code').focus();return;}
  const generation=++joinGeneration;
  joinCode=code;joinPhase='locating';render();
  joinTimer=setTimeout(()=>{
    if(generation!==joinGeneration)return;
    joinPhase='waiting';render();
    joinTimer=setTimeout(()=>{
      if(generation!==joinGeneration)return;
      joinPhase='applying';render();
      joinTimer=setTimeout(()=>{
        if(generation!==joinGeneration)return;
        const existing=model.networks.find(n=>n.id==='desktop');
        if(existing){existing.online=true;joinedId=existing.id;}
        else{joinedId='joined-'+crypto.randomUUID();model.networks.push({id:joinedId,name:'游戏主机',role:'guest',ip:nextIp(false),peer:'Akane-Desktop',peerIp:'10.188.36.1',online:true,rtt:12.3,sent:0,received:0,seconds:0,entry:'203.0.113.42:8436',config:{...clone(defaultConfig),mode:'existing',entries:['https://entry.example.com/current#streamlink1']}});}
        joinPhase='done';render();notify('预览：已演示主机批准与自动获取设置');
      },750);
    },3000);
  },650);
}
function handleRequest(id,approve) {
  const request=model.requests.find(r=>r.id===id);
  if(!request)return;
  const n=model.networks.find(n=>n.id===request.network);
  model.requests=model.requests.filter(r=>r.id!==id);
  if(approve&&n){n.online=true;n.rtt=19.6;n.seconds=0;n.entry='入站连接';}
  render();notify(approve?'预览：已同意 '+request.device+' 加入网络':'预览：已拒绝加入申请');
}
function updateExitConfirmation(id) {
  const n=model.networks.find(n=>n.id===id);
  if(!n)return;
  $('confirm-action').textContent=n.role==='host'?'删除并退出此网络':'确认退出此网络';
}
function removeNetwork(id) {
  const n=model.networks.find(n=>n.id===id);
  if(!n)return;
  model.networks=model.networks.filter(n=>n.id!==id);
  model.requests=model.requests.filter(r=>r.network!==id);
  codes.delete(id);
  if(createdId===id)createdId='';
  if(joinedId===id){joinedId='';joinPhase='idle';}
  render();notify(n.role==='host'?'预览：网络已删除':'预览：已退出网络');
}
function exitNetwork(id='') {
  if(!model.networks.length){notify('当前没有可退出的网络');return;}
  const n=id?model.networks.find(n=>n.id===id):model.networks[0];
  if(!n)return;
  if(id) {
    ask(`${n.role==='host'?'删除':'退出'}“${n.name}”？`,'',n.role==='host'?'确认删除网络':'确认退出网络',()=>removeNetwork(n.id));
    return;
  }
  ask('退出网络','','确认退出',()=>removeNetwork($('exit-network-select').value),`<label class="field"><span>选择要退出的网络</span><select id="exit-network-select">${model.networks.map(item=>`<option value="${item.id}">${esc(item.name)} · 本机为${role(item)}</option>`).join('')}</select></label>`);
  updateExitConfirmation(n.id);
}
async function copyCode() {
  const code=formattedCode(normalizeCode(codes.get(createdId)||sampleCode));
  let copied=false;
  try{await navigator.clipboard.writeText(code);copied=true;}
  catch{const input=document.createElement('textarea');input.value=code;input.style.position='fixed';input.style.opacity='0';document.body.append(input);input.select();copied=document.execCommand('copy');input.remove();}
  notify(copied?'直连码已复制':'请手动选择直连码复制',!copied);
}

document.addEventListener('click',event=>{
  const button=event.target.closest('button');
  if(!button||button.disabled)return;
  if(button.dataset.page){navigate(button.dataset.page);return;}
  if(button.dataset.range){chartRange=Number(button.dataset.range);document.querySelectorAll('[data-range]').forEach(b=>{b.classList.toggle('active',Number(b.dataset.range)===chartRange);b.setAttribute('aria-pressed',String(Number(b.dataset.range)===chartRange));});drawChart();return;}
  if(button.dataset.editorSection){editorSection=button.dataset.editorSection;renderEditor();$('network-settings-body').scrollTop=0;return;}
  if(button.dataset.close){$(button.dataset.close).close();return;}
  switch(button.dataset.action) {
    case 'theme': {
      const light=document.documentElement.dataset.theme!=='light';
      document.documentElement.dataset.theme=light?'light':'dark';
      $('theme-button').innerHTML=icon(light?'moon':'sun');
      $('theme-button').setAttribute('aria-label',light?'切换深色外观':'切换浅色外观');
      $('theme-button').title=light?'切换深色外观':'切换浅色外观';
      if(page==='logs'&&model.terminal==='auto')$('log-lines').classList.toggle('light',light);
      break;
    }
    case 'help-create':openHelp('create');break;
    case 'help-join':openHelp('join');break;
    case 'open-network-settings':openNetworkSettings(button.dataset.network||'');break;
    case 'close-network-settings':closeEditor();break;
    case 'revert-network-settings':editor.draft=clone(editor.base);renderEditor();break;
    case 'save-network-settings':saveNetworkSettings();break;
    case 'add-entry':if(editor.draft.entries.length<8){editor.draft.entries.push('');renderEditor();}else notify('最多添加 8 个入口',true);break;
    case 'remove-entry':editor.draft.entries.splice(Number(button.dataset.entryIndex),1);renderEditor();break;
    case 'test-entry': {
      const generation=++entryTestGeneration;
      $('entry-test-state').textContent='正在解析…';
      setTimeout(()=>{if(generation===entryTestGeneration&&$('entry-test-state'))$('entry-test-state').textContent=editor.draft.entries.some(v=>v.trim())?'预览：取得 1 个示例候选':'请先填写入口地址';},600);
      break;
    }
    case 'new-create':createdId='';createName='';createConfig=clone(defaultConfig);render();break;
    case 'view-host-network':createdId=button.dataset.network;render();break;
    case 'regenerate-code':codes.set(createdId,randomCode());render();notify('预览：已重新生成示例直连码');break;
    case 'copy-code':void copyCode();break;
    case 'cancel-join':joinGeneration++;clearTimeout(joinTimer);joinPhase='idle';render();notify('已取消本次申请');break;
    case 'another-join':joinPhase='idle';joinedId='';joinCode='';render();break;
    case 'approve-request':handleRequest(button.dataset.request,true);break;
    case 'reject-request':handleRequest(button.dataset.request,false);break;
    case 'save-device':if(!deviceDraft.name.trim()){notify('请输入设备名称',true);$('device-name').focus();return;}Object.assign(model,clone(deviceDraft),{name:deviceDraft.name.trim()});deviceDraft=null;render();notify('预览：本机设置已保存');break;
    case 'revert-device':deviceDraft=null;render();notify('已恢复保存的本机设置');break;
    case 'default-device':deviceDraft=clone(deviceDefaults);render();notify('已填入默认设置，保存后生效');break;
    case 'pause-logs':logsPaused=!logsPaused;button.textContent=logsPaused?'继续更新':'暂停更新';document.querySelector('.log-foot span').textContent=logsPaused?'已暂停更新':'正在显示最新记录';break;
    case 'export-logs': {
      const blob=new Blob([logs.map(l=>l[0]+' ['+l[1].toUpperCase()+'] '+l[2]).join('\n')],{type:'text/plain;charset=utf-8'}),link=document.createElement('a');
      link.href=URL.createObjectURL(blob);link.download='ConWU-预览日志.txt';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),500);break;
    }
    case 'exit-network':exitNetwork();break;
    case 'delete-owned':case 'delete-joined':exitNetwork(button.dataset.network);break;
  }
});
document.addEventListener('submit',event=>{if(event.target.id==='create-form'){event.preventDefault();createNetwork();}});
document.addEventListener('input',event=>{
  const el=event.target;
  if(el.id==='new-network-name'){createName=el.value;if($('create-error'))$('create-error').textContent='';}
  if(el.dataset.entry!==undefined&&editor&&!editor.readOnly){editor.draft.entries[Number(el.dataset.entry)]=el.value;entryTestGeneration++;if($('entry-test-state'))$('entry-test-state').textContent='';if($('network-settings-error'))$('network-settings-error').textContent='';editorDirty();}
  const {scope,key}=el.dataset;
  if(!scope||!key||el.type==='radio'&&!el.checked)return;
  const value=el.type==='checkbox'?el.checked:el.type==='number'?Number(el.value):key==='automaticIp'?el.value==='true':key==='pkarrRelays'?el.value.split(/\n/).map(v=>v.trim()).filter(Boolean):el.value;
  if(scope==='network'&&editor&&!editor.readOnly) {
    editor.draft[key]=value;
    if($('network-settings-error'))$('network-settings-error').textContent='';
    if(['mode','automaticIp','protocol','discovery'].includes(key))renderEditor();else editorDirty();
  }
  if(scope==='device'&&deviceDraft){deviceDraft[key]=value;deviceDirty();}
});
document.addEventListener('change',event=>{
  if(event.target.id==='exit-network-select')updateExitConfirmation(event.target.value);
  if(event.target.id==='log-filter')renderLogLines();
});
document.addEventListener('input',event=>{if(event.target.id==='log-search')renderLogLines();});
$('confirm-action').onclick=()=>{
  const callback=confirmCallback;confirmCallback=null;
  callback?.();$('confirm-dialog').close();
};
$('confirm-dialog').addEventListener('close',()=>{confirmCallback=null;});
$('network-dialog').addEventListener('cancel',event=>{event.preventDefault();closeEditor();});
$('help-dialog').addEventListener('click',event=>{
  if(event.target!==$('help-dialog'))return;
  const r=$('help-dialog').getBoundingClientRect();
  if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)$('help-dialog').close();
});
setInterval(()=>{
  for(const n of model.networks)if(n.online)n.seconds++;
  chartTick++;
  const i=3600+chartTick;
  history.shift();history.push({up:Math.max(0,.13+.035*Math.sin(i*.09)+.02*Math.cos(i*.03)),down:Math.max(.4,11.9+1.3*Math.sin(i*.08)+.5*Math.cos(i*.2)-(i%431>400?4.3:0))});
  if(page==='overview') {
    document.querySelectorAll('[data-duration]').forEach(span=>{const n=model.networks.find(n=>n.id===span.dataset.duration);if(n)span.textContent=connectedTime(n.seconds);});
    if(chartTick%2===0)drawChart();
  }
},1000);
render();
