'use strict';

// Live workspace presentation. Pairing, operation tracking and local session
// renewal continue to use app.js; this layer never simulates connection success.
(()=>{
Object.assign(titles,{requests:'加入申请'});
delete titles.coordinator;
let terminalTheme='auto';try{terminalTheme=localStorage.getItem('streamlink-terminal-theme')||'auto';}catch{}
const liveLogView=updateLogView;
updateLogView=function(){const prior=saved.logging.terminal;saved.logging.terminal=terminalTheme;try{liveLogView();}finally{saved.logging.terminal=prior;}};
const ui={hostId:'',joinId:'',editor:null,device:null,deviceBase:null,newConfig:'',signature:'',range:60,chart:[],rates:new Map(),sample:null,disclosures:new Map(),test:null};
const all=()=>workspaceState?.networks||[],row=id=>all().find(n=>n.id===id);
const protocolOf=p=>p?.pathSelection==='udp-only'?'直接 UDP（旧网络）':'FakeTCP + HTTP';
const strategyOf=p=>p?.connectionSource==='existing'?'只使用已有入口':'自主打洞';
const deviceSettings=()=>workspaceState?.deviceSettings||newConfigurationSettings();
const privateFields=[['network','连接方式','link'],['discovery','配对与发现方式','globe'],['entry','已有入口','globe'],['virtual','虚拟 IP','laptop'],['port','端口设置','port'],['stun','STUN 服务器','globe']];
const uiToggle=(scope,key,value,label)=>`<label class="switch"><input type="checkbox" data-ui-scope="${scope}" data-ui-key="${key}" ${value?'checked':''} aria-label="${label}"><span class="switch-track"></span></label>`;
const kv=(label,value,mono=false)=>`<div class="kv"><span>${esc(label)}</span><span class="${mono?'mono':''}">${esc(value)}</span></div>`;
const readRows=items=>`<dl class="readonly-values">${items.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value||'未设置')}</dd></div>`).join('')}</dl>`;
const deviceValue=()=>({name:workspaceState?.deviceName||'',startup:!!workspaceState?.desktop?.autoStart,level:workspaceState?.logLevel||'info',terminal:terminalTheme,host:clone({...defaults.host,...deviceSettings().coordinator})});
const defaultDevice=()=>({name:workspaceState.deviceName,startup:true,level:'info',terminal:'auto',host:clone(ui.deviceBase?.host||deviceValue().host)});
const compactCodeValue=value=>String(value||'').toUpperCase().replace(/[\s\u2010-\u2015-]/g,'').replace(/O/g,'0').replace(/[IL]/g,'1');
const formatCompact=value=>compactCodeValue(value).match(/.{1,4}/g)?.join('-')||'';
const validCompactCode=value=>/^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{16}$/.test(compactCodeValue(value));
function normalizedJoinCoordinator(value){
 if(!value.trim())return '';
 try{const url=new URL(value.trim());if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)throw Error();if(!url.pathname.endsWith('/'))url.pathname+='/';return url.href;}
 catch{throw Error('请填写有效的 HTTPS 协调服务器地址。');}
}
const inheritedPairConfig=configFromStatus;
configFromStatus=function(s){
 const c=inheritedPairConfig(s),p=s.settings||{},d=workspaceState?.networkDefaults;
 c.network.pkarrGateways=(p.pkarrGateways||d?.pkarrGateways||['https://pkarr.pubky.app','https://pkarr.pubky.org']).join('\n');
 c.stun.tcp=(p.tcpStun?.length?p.tcpStun:d?.tcpStun||[]).join('\n');
 c.stun.udp=(p.udpStun?.length?p.udpStun:d?.udpStun||[]).join('\n');
 return c;
};
function directGroups(value,placeholder=false){
 const code=compactCodeValue(value);
 return `<div class="direct-groups" aria-hidden="true">${Array.from({length:4},(_,g)=>`<div class="direct-group">${Array.from({length:4},(_,i)=>{const c=code[g*4+i];return `<span class="direct-digit ${c?'filled':placeholder?'placeholder':''}">${esc(c||(placeholder?'X':''))}</span>`;}).join('')}</div>`).join('')}</div>`;
}
function helpLink(kind){return `<div class="form-help"><button class="help-link" type="button" data-ui-action="help-${kind}">如何${kind==='create'?'创建':'加入'}网络？</button></div>`;}
function openHelp(kind){
 const create=kind==='create';$('help-title').textContent=create?'如何创建网络？':'如何加入网络？';
 const steps=create?['首先输入“网络名称”与设置“网络设置”；','在本机生成16位“直连码”。']:['在“输入框”处填写目标主机所生成的16位“直连码”','等待目标主机通过“加入申请”批准本机加入'];
 $('help-content').innerHTML=steps.map((s,i)=>`<p class="help-step"><span>${i?'②':'①'}</span>${esc(s)}</p>`).join('');$('help-dialog').showModal();
}
function initializeDrafts(){
 if(!workspaceState)return;
 if(!ui.device||!ui.savingDevice&&same(ui.device,ui.deviceBase)){ui.deviceBase=deviceValue();ui.device=clone(ui.deviceBase);ui.deviceRevision=workspaceState.deviceSettingsRevision;}
 if(ui.newConfig&&!workspaceState.configurations?.some(c=>c.id===ui.newConfig))ui.newConfig='';
}
function saveActions(scope){return `<div class="heading-actions"><div class="heading-action-buttons">${scope==='device'?'<button class="btn" data-ui-action="default-device">恢复默认设置</button>':''}<button class="btn" data-ui-action="restore-${scope}" id="revert-${scope}">恢复刚才设置</button><button class="btn primary" data-ui-action="save-${scope}" id="save-${scope}">${icon('save')}保存设置</button></div><span class="save-state" id="${scope}-save-state" role="status"></span></div>`;}
function networkList(host){
 const rows=all().filter(n=>!!n.status.networkId&&n.status.isOwner===host);
 return `<article class="card network-list-card" id="${host?'owned':'joined'}-networks"><div class="table-title"><h2>本机${host?'创建':'加入'}的网络</h2><span class="small">${rows.length} 个网络</span></div>${rows.length?rows.map(n=>{
  const s=n.status,p=s.peers[0],live=online&&!!p?.connected;
  const status=live?'已直连 '+p.name:!online?'状态待确认':!s.networkEnabled?'网络已停止':p?'等待 '+p.name+' 上线':'等待另一台设备加入';
  return `<div class="list-row ${host&&n.id===ui.hostId?'selected':''}" data-network-row="${esc(n.id)}"><div class="grow">${host?`<button class="network-name-button" data-ui-action="select-host" data-network="${esc(n.id)}" title="查看直连码">${esc(n.name)}</button>`:`<strong>${esc(n.name)}</strong>`}<div class="network-local-ip">本机虚拟 IP：<span class="mono">${esc(s.virtualIp||'待分配')}</span></div><div class="network-peer"><span class="dot ${live?'good':''}"></span><span>${esc(status)}</span></div><div class="network-peer-ip">对机虚拟 IP：<span class="mono">${esc(p?.virtualIp||'待分配')}</span></div>${!s.networkEnabled?`<button class="text-btn" data-ui-action="start-network" data-network="${esc(n.id)}">连接网络</button>`:''}</div><div class="network-row-actions"><button class="btn compact" data-ui-action="open-editor" data-network="${esc(n.id)}">${icon(host?'settings':'shield')}${host?'网络设置':'查看设置'}</button><button class="text-btn danger-text" data-ui-action="remove-network" data-network="${esc(n.id)}">${host?'删除网络':'退出网络'}</button></div></div>`;
 }).join(''):`<div class="empty">${icon(host?'create':'join')}<h2>还没有${host?'创建':'加入'}网络</h2><p>${host?'在左侧创建后，会在这里显示。':'通过主机审批后，会在这里显示。'}</p></div>`}</article>`;
}
function currentCreateSettings(){return row(ui.hostId)?.status.settings||workspaceState?.configurations.find(c=>c.id===ui.newConfig)?.settings||newConfigurationSettings();}
function settingsLaunch(){
 const p=currentCreateSettings(),custom=ui.hostId?p.requestedVirtualIp:newNetworkIp;
 return `<button class="settings-launch" type="button" data-ui-action="open-editor" data-network="${esc(ui.hostId)}" id="open-network-settings">${icon('settings')}<span class="grow"><strong>网络设置</strong><small>${protocolOf(p)} · ${strategyOf(p)} · ${custom?'自定义虚拟 IP':'自动分配虚拟 IP'}</small></span><span class="open-label">打开设置${icon('chevron')}</span></button>`;
}
createPage=function(){
 const n=row(ui.hostId),pair=n?.status.pairing,valid=pair?.active&&pair.expires*1000>Date.now(),code=valid&&pair.format==='compact'&&validCompactCode(pair.code)?compactCodeValue(pair.code):'';
 const form=n?`<div class="created-network-title"><h2>${esc(n.name)}</h2><span class="badge good">网络已创建</span></div>${kv('本机虚拟 IP',n.status.virtualIp||'待分配',true)}${settingsLaunch()}<div class="code-label-row"><h3>本机直连码</h3><span class="hint">16 位</span></div><div class="code-control direct-code-control direct-code-readonly" role="group" aria-label="${code?'本机直连码：'+formatCompact(code):'尚未生成直连码'}">${directGroups(code,true)}</div><div class="code-actions"><button class="btn compact" data-ui-action="generate" data-network="${esc(n.id)}">${icon('refresh')}${code?'重新生成':'生成直连码'}</button><button class="btn compact" data-ui-action="copy-pair" ${code?'':'disabled'}>${icon('copy')}复制</button></div><div class="form-operation"><button class="btn" data-ui-action="new-create">${icon('plus')}再创建一个网络</button></div>${helpLink('create')}`:`<form id="create-form"><label class="field"><span>网络名称</span><input id="new-network-name" class="form-input-large" value="${esc(newNetworkName)}" maxlength="64" placeholder="例如：主机—笔记本" autocomplete="off"></label>${settingsLaunch()}<div id="create-error" class="error" role="status"></div><div class="form-operation"><button class="btn primary" id="create-network" type="submit">${icon('plus')}创建网络</button></div>${helpLink('create')}</form>`;
 return heading('创建网络','以本机为主机，创建网络')+`<div class="network-columns"><article class="card create-form"><div class="pad">${form}</div></article>${networkList(true)}</div>`;
};
function pendingJoin(){return row(ui.joinId)||all().find(n=>n.status.pairing?.active&&!n.status.pairing.owner);}
joinPage=function(){
 const n=pendingJoin(),p=n?.status.pairing,waiting=p?.active&&!p.owner,done=ui.joinId&&n?.status.networkId;let form;
 if(waiting)form=`<div class="waiting-card"><div class="status-orbit">${icon('clock')}</div><h2>等待主机同意</h2><p>${esc(p.peerName||'目标主机')} 将核对并批准本次申请。</p>${kv('双方校验码',p.verification||'正在交换',true)}<p class="hint">${esc(p.state)}</p><div class="form-actions"><button class="btn" data-ui-action="cancel-join" data-network="${esc(n.id)}">取消申请</button></div></div>`;
 else if(done)form=`<div class="waiting-card"><div class="status-orbit success">${icon('check')}</div><h2>已加入 ${esc(n.name)}</h2><p>已获取主机网络设置，${n.status.directPeers?'已建立直连。':'正在建立直连。'}</p>${kv('本机虚拟 IP',n.status.virtualIp,true)}${kv('目标设备',n.status.peers[0]?.name||'目标主机')}<div class="form-actions"><button class="btn primary" data-page="overview">查看概况</button><button class="btn" data-ui-action="another-join">加入其他网络</button></div></div>`;
 else form=`<form id="join-form"><label class="pair-label" for="join-invite">目标主机的直连码</label><div class="code-control direct-code-control">${directGroups(joinInviteValue,true)}<input id="join-invite" aria-label="目标主机的16位直连码" type="text" maxlength="19" spellcheck="false" autocomplete="off" autocapitalize="characters" value="${esc(formatCompact(joinInviteValue))}"></div><div id="join-error" class="error" role="status">${esc(joinError)}</div><div class="form-operation"><button class="btn primary" id="join-submit" type="submit">请求加入${icon('join')}</button></div>${helpLink('join')}</form>`;
 return heading('加入网络','向目标主机发送申请，加入网络')+`<div class="network-columns"><article class="card pad" id="join-card">${form}</article>${networkList(false)}</div>`;
};
function requestsPage(){return heading('加入申请','核对设备与校验码，决定是否允许加入。')+incomingPage().replaceAll('data-action="approve"','data-ui-action="approve"').replaceAll('data-action="reject"','data-ui-action="reject"').replaceAll('data-request-network=','data-network=');}
function liveSettingsPage(){
 const d=ui.device||deviceValue(),desktop=workspaceState?.desktop,linux=workspaceState?.platform==='linux',host=d.host;
 return heading('设置','',saveActions('device'))+`<article class="card settings-page"><section class="settings-section"><div><h2>启动与服务</h2><p class="intro">配置开机启动与服务</p></div><div><div class="switch-row"><div><h3>开机启动</h3><p>${linux?'由系统服务管理。':'启动后台服务，登录后显示托盘。'}</p></div>${linux?'<span class="badge">由 systemd 管理</span>':uiToggle('device','startup',d.startup,'开机启动')}</div><div class="row between" style="margin-top:23px"><span class="small muted">后台服务</span><span class="badge ${state?.serviceReady&&(linux||desktop?.serviceRegistered)?'good':''}">${linux?state?.serviceReady?'正在运行':'未运行':desktop?.serviceRegistered?state?.serviceReady?'已注册 · 正在运行':'已注册 · 未运行':'尚未注册'}</span>${!linux&&(!desktop?.serviceRegistered||!state?.serviceReady)?'<button class="btn compact" data-ui-action="register-service">注册／启动服务</button>':''}</div><details class="service-advanced" id="local-service-listener"><summary class="text-btn">监听与证书（高级）</summary><div class="section-spacer"><label class="field"><span>本机协调监听地址</span><input data-ui-scope="deviceHost" data-ui-key="listenUrl" value="${esc(host.listenUrl)}" spellcheck="false"></label>${[['certificateFile','监听证书文件'],['certificateKeyFile','监听私钥文件']].map(([k,label])=>`<label class="field"><span>${label}</span><input data-ui-scope="deviceHost" data-ui-key="${k}" value="${esc(host[k]||'')}" spellcheck="false"></label>`).join('')}${readRows([['协调服务',workspaceState?.coordinator?.state||'正在读取'],['本机证书指纹',workspaceState?.coordinator?.certificatePin||host.publicCertificatePin||'当前使用本机反向代理']])}</div></details></div></section><section class="settings-section"><div><h2>本机设备名</h2><p class="intro">所有网络统一使用这个设备名称。</p></div><label class="field"><span>设备名称</span><input id="device-name" data-ui-scope="device" data-ui-key="name" maxlength="64" value="${esc(d.name)}"></label></section><section class="settings-section"><div><h2>日志设置</h2><p class="intro">调整日志详细程度与终端外观</p></div><div><label class="field"><span>日志等级</span><select data-ui-scope="device" data-ui-key="level">${[['error','仅错误'],['warn','警告与错误'],['info','常规信息'],['debug','详细调试'],['off','关闭记录']].map(([v,t])=>`<option value="${v}" ${d.level===v?'selected':''}>${t}</option>`).join('')}</select></label><label class="field"><span>终端外观</span><select data-ui-scope="device" data-ui-key="terminal">${[['auto','跟随界面'],['dark','深色'],['light','浅色']].map(([v,t])=>`<option value="${v}" ${d.terminal===v?'selected':''}>${t}</option>`).join('')}</select></label><button class="text-btn" data-page="logs">打开日志${icon('chevron')}</button></div></section></article>`;
}
function sampleTraffic(next){const now=performance.now(),old=ui.sample,a=next.aggregate,peers=new Map(all().flatMap(n=>(n.status.peers||[]).map(p=>[n.id+':'+p.slot,p])));if(!a)return;const dt=old?(now-old.time)/1000:0,valid=old&&dt>=.1&&dt<=10;ui.rates.clear();if(valid)for(const [id,p]of peers){const q=old.peers.get(id);if(q&&p.sentBytes>=q.sentBytes&&p.receivedBytes>=q.receivedBytes)ui.rates.set(id,{up:(p.sentBytes-q.sentBytes)/dt,down:(p.receivedBytes-q.receivedBytes)/dt});}if(valid&&a.sentBytes>=old.sent&&a.receivedBytes>=old.received)ui.chart.push({time:now,up:(a.sentBytes-old.sent)/dt,down:(a.receivedBytes-old.received)/dt});ui.chart=ui.chart.filter(p=>now-p.time<3600000);ui.sample={time:now,sent:a.sentBytes,received:a.receivedBytes,peers};}
function chart(){const now=performance.now(),values=ui.chart.filter(p=>now-p.time<=ui.range*1000),max=Math.max(1,...values.flatMap(p=>[p.up,p.down])),points=key=>values.map(p=>`${32+600*(1-(now-p.time)/(ui.range*1000))},${105-98*p[key]/max}`).join(' ');return `<svg class="traffic-chart" viewBox="0 0 640 128" preserveAspectRatio="none" role="img" aria-label="实际上传与下载速度折线图"><path d="M32 105H632M32 56H632M32 7H632" stroke="var(--line)" stroke-dasharray="3 5" fill="none"/><text x="4" y="12" fill="var(--dim)">${(max/1e6).toFixed(1)}</text><text x="4" y="109" fill="var(--dim)">0</text><polyline points="${points('down')}" fill="none" stroke="var(--accent)" stroke-width="1.8" vector-effect="non-scaling-stroke"/><polyline points="${points('up')}" fill="none" stroke="var(--green)" stroke-width="1.5" vector-effect="non-scaling-stroke"/><text x="32" y="124" fill="var(--dim)">${ui.range===60?'1 分钟前':'1 小时前'}</text><text x="610" y="124" fill="var(--dim)">现在</text></svg>`;}
overviewPage=function(){
 const networks=all().filter(n=>n.status.networkId),a=workspaceState?.aggregate,live=networks.filter(n=>n.status.directPeers>0).length,rate=online?ui.chart.at(-1):null;
 return heading('概况','本机信息与所有网络的连接状态。')+`<div class="overview-top"><article class="card pad device-card"><div class="row device-heading"><div class="avatar">${icon('laptop')}</div><div class="grow"><h2 class="device-name">${esc(workspaceState?.deviceName||'正在读取')}</h2></div></div></article><article class="card chart-card"><div class="chart-head"><h2>实时流量</h2><div class="range" role="group" aria-label="流量图时间范围"><button data-ui-action="range-60" aria-pressed="${ui.range===60}" class="${ui.range===60?'active':''}">一分钟</button><button data-ui-action="range-3600" aria-pressed="${ui.range===3600}" class="${ui.range===3600?'active':''}">一小时</button></div></div><div class="chart-metrics">${[['up','上传','green',a?.sentBytes],['down','下载','accent',a?.receivedBytes]].map(([key,name,color,value])=>`<div><div class="metric-caption"><span class="dot" style="background:var(--${color})"></span>${name}</div><div class="metric-value">${rate?(rate[key]/1e6).toFixed(2):'—'}<small>MB/s</small></div><div class="metric-total">累计 ${total(value||0)}</div></div>`).join('')}</div><div class="chart-wrap">${chart()}</div></article></div><article class="card overview-devices"><div class="table-title"><h2>设备与网络</h2></div><div class="table-scroll"><table><colgroup><col style="width:18%"><col style="width:13%"><col style="width:10%"><col style="width:19%"><col style="width:22%"><col style="width:8%"><col style="width:10%"></colgroup><thead><tr><th scope="col">设备</th><th scope="col">网络</th><th scope="col">角色</th><th scope="col">虚拟 IP</th><th scope="col">连接状态</th><th scope="col">延迟</th><th scope="col">流量</th></tr></thead><tbody><tr class="local-row"><td><div class="row">${icon('laptop')}<strong>${esc(workspaceState?.deviceName||'本机')}</strong></div></td><td colspan="6" class="self-label">本机</td></tr>${networks.map(n=>{
  const s=n.status,p=s.peers[0],connected=online&&p?.connected,r=ui.rates.get(n.id+':'+p?.slot),elapsed=p?.connection?.elapsedMs||0;
  const pairs=(name,values,mono=false)=>`<div class="paired-values">${values.map((v,i)=>`<div class="paired-line"><span class="paired-label">${i?'对机':'本机'}</span><span class="${mono?'mono':''}" data-value="${i?'peer':'local'}-${name}">${esc(v||'待分配')}</span></div>`).join('')}</div>`;
  return `<tr data-peer-row="${esc(n.id)}"><td><strong class="peer-name">${esc(p?.name||'等待另一台设备')}</strong></td><td>${esc(n.name)}</td><td class="role-value">${pairs('role',[s.isOwner?'主机':'从机',s.isOwner?'从机':'主机'])}</td><td>${pairs('ip',[s.virtualIp,p?.virtualIp],true)}</td><td><div class="cell-status"><span class="dot ${connected?'good':''}"></span>${connected?'已直连':!online?'状态待确认':!s.networkEnabled?'已停止':esc(phaseNames[p?.connection?.phase]||'等待设备')}</div><div class="cell-sub">${protocolOf(s.settings)}</div>${connected?`<div class="cell-sub">已直连 <span data-network-duration="${elapsed}" data-duration-sample="${performance.now()}">${connectedDuration(elapsed)}</span></div>`:''}<div class="cell-sub entry">${esc(connected?'实际入口：':'上次入口：')}${esc(p?.outerTarget&&p.outerTarget!=='Unknown'?p.outerTarget:p?.entryDirection==='Inbound'?'入站直连 · 本机端口 '+s.settings.listenPort:'待认证连接')}</div></td><td class="mono">${connected&&p.rttMs!=null?p.rttMs.toFixed(1)+' ms':'—'}</td><td><div class="traffic-cell"><div><span class="up">↑</span> ${total(p?.sentBytes||0)}<div class="rate">${speed(online?r?.up:null)}</div></div><div><span class="down">↓</span> ${total(p?.receivedBytes||0)}<div class="rate">${speed(online?r?.down:null)}</div></div></div></td></tr>`;
 }).join('')}</tbody></table></div><div class="device-table-foot"><span class="dot ${online&&live?'good':''}"></span><span>${networks.length} 个网络</span><span>·</span><span class="direct-total">与其余 ${online?live:0} 台设备直连</span></div></article>`;
};
function drawPage(){const pages={overview:overviewPage,create:createPage,join:joinPage,requests:requestsPage,settings:liveSettingsPage,logs:logsPage};return pages[page]();}
function pageSignature(){return JSON.stringify([page,ui.hostId,ui.joinId,newNetworkName,newNetworkIp,all().map(n=>[n.id,n.name,n.configurationId,n.status.networkId,n.status.settingsRevision,n.status.networkEnabled,n.status.directPeers,n.status.pairing,n.status.pairing?.expires*1000>Date.now(),n.status.entryPreparation,n.status.peers.map(p=>[p.name,p.virtualIp,p.connected,p.connection?.phase])]),workspaceState?.deviceName,workspaceState?.coordinator?.state,ui.deviceBase?.host]);}
render=function(next){
 const observed=!!next;
 if(next?.workspaceVersion){workspaceState=next;state=next;online=true;lastStatusAt=performance.now();lastStatusFailure='';if(noticeSource==='backend'||noticeSource==='pair'&&!next.networks.some(n=>n.status.pairing?.active)){lastPairError='';notice('');}appendLogs(next.logs||[]);initializeDrafts();if(ui.hostId&&!row(ui.hostId))ui.hostId='';if(ui.joinId&&!row(ui.joinId))ui.joinId='';if(observed)sampleTraffic(next);}
 if(!workspaceState){$('content').innerHTML=heading('ConWU','正在读取本机后台状态。');controls();return;}
 const chosen=row(selectedNetwork)?.status;state=chosen?{...workspaceState,...chosen,desktop:workspaceState.desktop}:workspaceState;
 networkActive=!!state.networkId;owner=!!state.isOwner;createdAt=(state.networkEstablishedAt||0)*1000;
 const signature=pageSignature(),replace=!observed||ui.signature!==signature||page==='overview';updateShell();
 if(replace){
  for(const d of $('content').querySelectorAll('details[id]'))ui.disclosures.set((ui.renderedPage||page)+'|'+d.id,d.open);
  const focused=document.activeElement,focusId=$('content').contains(focused)?focused.id:'',start=focused?.selectionStart,end=focused?.selectionEnd;
  $('content').innerHTML=drawPage();ui.signature=signature;ui.renderedPage=page;
  for(const d of $('content').querySelectorAll('details[id]'))if(ui.disclosures.has(page+'|'+d.id))d.open=ui.disclosures.get(page+'|'+d.id);
  if(page==='join')bindJoinInput();if(page==='create'&&$('create-form'))$('create-form').onsubmit=e=>{e.preventDefault();void run(create).catch(()=>{});};if(page==='logs')updateLogView();
  if(focusId&&$(focusId)&&!$(focusId).disabled){$(focusId).focus({preventScroll:true});try{$(focusId).setSelectionRange(start,end);}catch{}}
 }else if(page==='logs')updateLogView();
 if(ui.editor&&section==='discovery')refreshPkarrStatus();controls();
};
navigate=function(next){page=titles[next]?next:'overview';ui.signature='';render();window.scrollTo({top:0,behavior:'instant'});};
updateShell=function(){
 document.querySelectorAll('.nav[data-page]').forEach(b=>{const active=b.dataset.page===page;b.classList.toggle('active',active);if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
 document.title=titles[page]+' · ConWU';$('sidebar-name').textContent=workspaceState?.deviceName||'正在读取';$('sidebar-initials').textContent=(workspaceState?.deviceName||'CW').slice(0,2).toUpperCase();
 const count=all().filter(n=>n.status.pairing?.active&&n.status.pairing.owner&&n.status.pairing.candidate).length;
 $('requests-count').textContent=count;$('requests-count').hidden=!count;$('request-dot').hidden=true;$('settings-dirty-dot').hidden=!ui.device||same(ui.device,ui.deviceBase);
 $('backend-state').textContent=expired?'面板授权已过期':!online?'后台状态未更新':state?.serviceReady?'后台运行中':state?.state||'后台尚未就绪';
 $('backend-dot').className='dot'+(online&&!expired&&state?.serviceReady?' good':'');
 $('app-version').textContent=workspaceState?.version?'v'+workspaceState.version.split('+')[0]:'';
};
controls=function(){
 const ready=online&&!expired&&state?.serviceReady&&!busy&&!ui.preparingCommand;
 for(const b of document.querySelectorAll('[data-ui-action]')){
  const action=b.dataset.uiAction;
  if(['close-editor','close-exit','open-editor','select-host','new-create','another-join','help-create','help-join','close-help','open-local-service'].includes(action))b.disabled=!!ui.editor?.saving;
  else if(['range-60','range-3600'].includes(action))b.disabled=false;
  else b.disabled=!ready;
 }
 if($('save-device')){
  const changed=!same(ui.device,ui.deviceBase);$('save-device').disabled=!ready||!changed;
  $('revert-device').disabled=!!ui.savingDevice||!changed;$('device-save-state').textContent=ui.savingDevice?'保存中…':changed?'有未保存的更改':'已保存';$('device-save-state').className='save-state'+(changed?' dirty':'');
 }
 for(const b of document.querySelectorAll('[data-ui-action="approve"],[data-ui-action="reject"]')){const p=row(b.dataset.network)?.status.pairing;b.disabled=!ready||!p?.candidate||(b.dataset.uiAction==='approve'&&!/^\d{6}$/.test(p.verification||''));}
 const copy=document.querySelector('[data-ui-action="copy-pair"]');
 if(copy){const p=row(ui.hostId)?.status.pairing;copy.disabled=!p?.active||p.expires*1000<=Date.now()||p.format!=='compact'||!validCompactCode(p.code);}
 for(const b of document.querySelectorAll('[data-ui-action="refresh-pkarr"]'))b.disabled=!ready||!row(b.dataset.network)?.status.networkEnabled||row(b.dataset.network)?.status.settings?.discoveryMode!=='pkarr';
 for(const b of document.querySelectorAll('[data-ui-action="generate"]'))b.disabled=!ready||!row(b.dataset.network)?.status.networkEnabled;
 document.querySelector('[data-ui-action="choose-exit"]').disabled=!ready||!all().length;
 const restore=document.querySelector('[data-ui-action="default-device"]');if(restore)restore.disabled=!!ui.savingDevice||same(ui.device,defaultDevice());
 if($('join-submit'))$('join-submit').disabled=!ready;if($('join-invite'))$('join-invite').disabled=!ready;if($('create-network'))$('create-network').disabled=!ready||!!ui.creating;
 for(const el of document.querySelectorAll('[data-ui-scope="device"],[data-ui-scope="deviceHost"]'))el.disabled=!!ui.savingDevice;
 if(ui.editor){
  const ro=ui.editor.readOnly,changed=editorChanged();
  for(const b of $('network-edit-actions').querySelectorAll('button'))b.disabled=ro||!changed||(b.dataset.uiAction==='restore-editor'?!!ui.editor.saving:!ready);
  $('network-save-state').textContent=ro?'主机设置 · 仅供查看':ui.editor.saving?'保存中…':changed?'有未保存的更改':'没有未保存的修改';$('network-save-state').className='save-state'+(!ro&&changed?' dirty':'');
  if($('settings-fields'))$('settings-fields').inert=!!ui.editor.saving;
 }
};
inputChange=function(el){
 if(!ui.editor||ui.editor.readOnly)return;
 if(el.matches('[data-entry-index]')){
  drafts.network.entries.local[Number(el.dataset.entryIndex)]=el.value;
  if($('test-status'))$('test-status').textContent='';if($('test-results'))$('test-results').innerHTML='';
 }else{
  const key=el.dataset.key;if(!key||el.type==='radio'&&!el.checked)return;
  const value=el.type==='checkbox'?el.checked:el.type==='number'?el.value===''?'':Number(el.value):el.value;
  if(section==='discovery'){
   if(key==='url')drafts.coordination.url=value;else if(key==='pin')drafts.certificate.pin=value;else drafts.network[key]=value;
  }else if(section==='entry'){drafts.network.refresh=value;drafts.network.unit=1;}
  else if(section==='virtual'&&key==='virtualMode'){
   if(value==='auto'){ui.editor.customIp=newNetworkIp;newNetworkIp='';}else newNetworkIp=ui.editor.customIp||'';
   ui.editor.ipMode=value;
  }else drafts[section][key]=value;
  if(['mode','route','protocol','virtualMode'].includes(key)){renderEditor();return;}
 }
 if($('settings-error'))$('settings-error').textContent='';
 for(const key of ['tcp','udp'])if($('stun-count-'+key))$('stun-count-'+key).textContent=drafts.stun[key].split(/\n/).filter(v=>v.trim()).length+' 个地址';
 controls();
};
refreshSettingsTools=function(){controls();};
const oldRenderFields=renderFields;
renderFields=function(){if(ui.editor)renderEditor();else oldRenderFields();};
function editorFields(){
 const d=drafts.network;
 if(section==='network'){
  const protocols=[['faketcp','FakeTCP + HTTP','适合高码率串流，默认使用。'],['tcp','纯 TCP','后续功能，暂不可选。']];
  if(d.protocol==='udp')protocols.push(['udp','直接 UDP（旧网络）','保留原有协议；两端须使用相同协议。']);
  return `<h3>连接协议</h3><div class="radio-cards">${protocols.map(([v,t,h])=>`<label class="radio-card ${v==='tcp'?'unavailable':''}"><input type="radio" name="protocol" data-key="protocol" value="${v}" ${d.protocol===v?'checked':''} ${v==='tcp'?'disabled':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div><h3>连接策略</h3><div class="radio-cards">${[['custom','自主打洞','由 ConWU 准备入口并尝试穿透。'],['existing','只使用已有入口','公网、端口转发或第三方已打通的入口。']].map(([v,t,h])=>`<label class="radio-card"><input type="radio" name="mode" data-key="mode" value="${v}" ${d.mode===v?'checked':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div><div class="note strategy-note">${icon('info')}<span>${d.mode==='existing'?'仅通过已有入口连接。':'首次使用直连码配对；后续入口更新可在左侧“配对与发现方式”中设置。'}</span></div>`;
 }
 if(section==='discovery'){
  const tips={pkarr:'首次通过直连码配对，之后经由 PKARR 发布和查询最新地址。',server:'使用你指定的协调服务器更新入口与交换连接信息；首次配对仍使用直连码。',direct:'只通过直连码配对连接；入口变化后，需要重新生成并输入直连码。'};
  let fields='';
  if(d.route==='pkarr')fields=`<section class="discovery-settings"><h3>PKARR 发现</h3><label class="field"><span>发现网关（每行一个）</span><textarea data-key="pkarrGateways" spellcheck="false" class="pkarr-endpoints">${esc(d.pkarrGateways)}</textarea></label>${ui.editor.id?`<p class="hint" id="pkarr-live-state">${esc(row(ui.editor.id)?.status.pkarr?.state||'等待发现状态')}</p><div id="pkarr-live-details">${pkarrDetails(row(ui.editor.id)?.status.pkarr)}</div><div class="form-actions"><button class="btn compact" data-ui-action="refresh-pkarr" data-network="${esc(ui.editor.id)}">立即刷新发现信息</button></div>`:''}</section>`;
  if(d.route==='server')fields=`<section class="discovery-settings"><h3>HTTPS 协调服务器</h3><label class="field"><span>协调服务器地址</span><input data-key="url" value="${esc(drafts.coordination.url)}" placeholder="https://coord.example.com/" spellcheck="false"></label><label class="field"><span>证书 SHA-256 指纹（可选）</span><input class="mono" data-key="pin" value="${esc(drafts.certificate.pin)}" placeholder="留空使用系统证书信任" spellcheck="false"></label></section>`;
  return `<h3>配对与发现方式</h3><label class="field"><span>发现方式</span><select data-key="route">${[['pkarr','PKARR 自动发现（默认）'],['server','自建协调服务器（高级）'],['direct','仅直连码 · 手动更新入口']].map(([v,t])=>`<option value="${v}" ${d.route===v?'selected':''}>${t}</option>`).join('')}</select></label><div class="note discovery-note">${icon('info')}<span>${tips[d.route]||tips.pkarr}</span></div>${fields}`;
 }
 if(section==='entry')return `<h3>本机已有入口</h3><div class="entry-copy"><p class="hint">填写本机的公网 IP:端口、已打通的地址或 HTTPS/TXT 等订阅链接。</p><p class="hint">若填写的不是可更新的订阅链接，入口变化后需要重新填写新入口地址。</p></div><div class="entry-rows">${d.entries.local.map((v,i)=>entryRow(v,i,d.entries.local.length)).join('')}</div><div class="test-row"><button class="btn compact" data-ui-action="test-entry">${icon('refresh')}测试地址</button><span id="test-status" class="hint"></span></div><div id="test-results"></div><label class="field"><span>订阅更新间隔（秒）</span><input data-key="refresh" type="number" min="1" max="86400" value="${d.refresh*Number(d.unit||1)}"></label>`;
 if(section==='virtual'){
  if(ui.editor.id)return `<h3>本机在此网络中的虚拟 IP</h3>${readRows([['当前虚拟 IP',row(ui.editor.id)?.status.virtualIp],['修改方式','网络创建后地址固定；需要更换地址时重新创建网络。']])}`;
  return `<h3>本机在此网络中的虚拟 IP</h3><div class="radio-cards">${[['auto','自动分配','自动选择可用网段，避免与其他网络冲突。'],['custom','自定义地址','指定本机在此网络使用的私有 IPv4 地址。']].map(([v,t,h])=>`<label class="radio-card"><input type="radio" name="virtual-mode" data-key="virtualMode" value="${v}" ${ui.editor.ipMode===v?'checked':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div>${ui.editor.ipMode==='custom'?`<label class="field"><span>自定义虚拟 IP</span><input class="mono" id="new-network-ip" value="${esc(newNetworkIp)}" placeholder="10.171.139.1" spellcheck="false"></label>`:''}`;
 }
 if(section==='port')return `<h3>接收端口</h3><label class="field"><span>ConWU 接收端口</span><input type="number" data-key="listen" min="1024" max="65535" value="${drafts.port.listen}"><span class="hint">已有入口应映射到这个端口。</span></label><div class="note">${icon('info')}<span>修改接收端口后，请同步核对公网转发或外部打洞工具的配置。</span></div>`;
 if(section==='stun')return `<h3>打洞 STUN 服务器</h3><div class="stun-columns">${[['tcp','TCP STUN'],['udp','UDP STUN']].map(([key,title])=>`<label class="field"><span>${title}<small id="stun-count-${key}">${drafts.stun[key].split(/\n/).filter(v=>v.trim()).length} 个地址</small></span><textarea data-key="${key}" spellcheck="false" wrap="off" aria-label="${title} 服务器列表">${esc(drafts.stun[key])}</textarea></label>`).join('')}</div>`;
 return '';
}
function readOnlyEditor(){
 const n=row(ui.editor.id);if(!n)return '<div class="note">此网络已被移除，可以关闭窗口。</div>';
 const s=n.status,p=s.settings,remote=s.receivedNetworkSettings,route=p.discoveryMode||(p.pkarrPublish?'pkarr':p.directMode?'direct':'coordinator');
 const groups={network:[['连接协议',protocolOf(p)],['连接策略',strategyOf(p)],['配置来源',s.peers[0]?.name||'目标主机']],entry:[['目标主机入口／订阅',(p.existingEntries||[]).filter(e=>e.peerSlot!==0).map(e=>e.source).join('\n')||remote?.entries?.map(e=>e.source).join('\n')],['订阅更新间隔',p.entryRefreshSeconds+' 秒']],virtual:[['本机虚拟 IP',s.virtualIp],['对机虚拟 IP',s.peers[0]?.virtualIp]],port:[['主机接收端口',remote?.hostListenPort?String(remote.hostListenPort):'由入口或协调发现'],['本机接收端口',String(p.listenPort)],['本机源端口',String(p.sourcePort)]],stun:[['TCP STUN',(p.tcpStun||[]).join('\n')],['UDP STUN',(p.udpStun||[]).join('\n')]],discovery:[['发现方式',route==='pkarr'?'PKARR 自动发现':route==='coordinator'?'自建协调服务器':'仅直连码'],...(route==='pkarr'?[['发现网关',(p.pkarrGateways||[]).join('\n')],['主机 PKARR 入口',(remote?.entries||[]).filter(e=>e.source.startsWith('pkarr://')).map(e=>e.source).join('\n')]]:route==='coordinator'?[['HTTPS 协调服务器',p.service],['证书 SHA-256 指纹（可选）',p.certificatePin||'使用系统证书信任']]:[['入口更新','入口变化后重新交换直连码']])]};
 const live=section==='discovery'&&route==='pkarr'?`<p class="hint" id="pkarr-live-state" style="margin-top:16px">${esc(s.pkarr?.state||'等待发现状态')}</p><div id="pkarr-live-details">${pkarrDetails(s.pkarr)}</div>`:'';
 return `<div class="note readonly-intro">以下网络设置仅供查看。</div><h3>${editorSections().find(v=>v[0]===section)?.[1]||'网络设置'}</h3>${readRows(groups[section]||[])}${live}`;
}
function pkarrRows(status){return status?.source?[['本机发现地址',status.source],['当前发布入口',(status.endpoints||[]).join('\n')],['最近发布',status.publishedAt?new Date(status.publishedAt*1000).toLocaleString():'尚未成功发布'],['本次接受发布的网关',`${status.acceptedGateways||0} / ${status.totalGateways||0}`],['对端入口确认',status.peerAcknowledged?'对端已确认当前入口':'等待对端确认当前入口'],['最近对端公告',status.peerSeenAt?new Date(status.peerSeenAt*1000).toLocaleString():'尚未收到'],['发布状态说明',status.error||'无发布错误'],['查询状态说明',status.queryError||'无查询错误']]:[];}
function pkarrDetails(status){return status?.source?readRows(pkarrRows(status)):'';}
function refreshPkarrStatus(){const status=row(ui.editor?.id)?.status.pkarr;if($('pkarr-live-state'))$('pkarr-live-state').textContent=status?.state||'创建并启动网络后开始发布';if($('pkarr-live-details'))$('pkarr-live-details').innerHTML=pkarrDetails(status);}
function editorSections(){
 const p=ui.editor?.readOnly?row(ui.editor.id)?.status.settings:null,existing=p?p.connectionSource==='existing':drafts.network.mode==='existing';
 return privateFields.filter(([key])=>key==='entry'?existing:['discovery','stun'].includes(key)?!existing:true);
}
function renderEditor(){
 if(!ui.editor)return;const ro=ui.editor.readOnly,fields=editorSections();if(!fields.some(f=>f[0]===section))section='network';
 $('network-settings-nav').innerHTML=fields.map(([key,name,ico])=>`<button data-ui-section="${key}" class="${section===key?'active':''}" ${section===key?'aria-current="page"':''}>${icon(ico)}${name}</button>`).join('');
 $('network-settings-body').innerHTML=ro?readOnlyEditor():`<div id="settings-fields">${editorFields()}</div><div id="settings-error" class="field-error" role="status"></div>`;controls();
}
settingsDto=function(){
 const n=drafts.network,active=n.mode!=='existing'&&n.route==='server',lines=v=>String(v||'').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
 let service=drafts.coordination.url.trim();if(active&&service)service=normalizedJoinCoordinator(service.includes('://')?service:'https://'+service);
 return {...(configuration()?.settings||newConfigurationSettings()),service,certificatePin:drafts.certificate.pin.trim(),pairingService:'',pairingCertificatePin:'',manualEndpoint:'',pathSelection:n.protocol==='udp'?'udp-only':'faketcp-only',connectionSource:n.mode,directMode:!active,discoveryMode:n.mode==='existing'?'existing':n.route==='pkarr'?'pkarr':active?'coordinator':'direct',pkarrPublish:n.mode!=='existing'&&n.route==='pkarr',pkarrGateways:lines(n.pkarrGateways),coordinatorBackup:false,existingEntries:Object.entries(n.entries).flatMap(([key,values])=>values.map(v=>v.trim()).filter(Boolean).map(source=>({peerSlot:key==='local'?0:-1,source}))),entryRefreshSeconds:Number(n.refresh)*Number(n.unit),listenPort:Number(drafts.port.listen),sourcePort:configuration()?.settings.sourcePort||44691,requestedVirtualIp:'',tcpStun:lines(drafts.stun.tcp),udpStun:lines(drafts.stun.udp),coordinator:{...defaults.host},ddns:null};
};
validateSection=function(key,configuration=drafts){
 const n=configuration.network;
 if(key==='network'&&!['faketcp','udp'].includes(n.protocol))return '此传输协议尚未开放。';
 if(key==='entry'&&n.mode==='existing'){
  const interval=Number(n.refresh)*Number(n.unit);if(!Number.isInteger(interval)||interval<1||interval>86400)return '自动更新间隔应为 1 秒至 24 小时。';
  if(Object.values(n.entries).flat().filter(v=>v.trim()).length>12)return '最多保存 12 项地址来源。';
 }
 if(key==='port'&&(!Number.isInteger(configuration.port.listen)||configuration.port.listen<1024||configuration.port.listen>65535))return '接收端口应为 1024～65535 之间的整数。';
 if(key==='stun'&&n.mode!=='existing'&&(!configuration.stun.tcp.trim()||!configuration.stun.udp.trim()))return '请填写 STUN 服务器地址。';
 if(key==='discovery'&&n.mode!=='existing'){
  if(n.route==='server'){
   try{normalizedJoinCoordinator(configuration.coordination.url.includes('://')?configuration.coordination.url:'https://'+configuration.coordination.url);}catch{return '请填写有效的 HTTPS 协调服务器地址。';}
   if(!configuration.coordination.url.trim())return '请填写 HTTPS 协调服务器地址。';
   if(configuration.certificate.pin&&!/^[a-fA-F0-9]{64}$/.test(configuration.certificate.pin))return '证书指纹应为 64 位十六进制字符。';
  }
  if(n.route==='pkarr'){
   const values=String(n.pkarrGateways||'').split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
   if(values.length<1||values.length>4)return '请填写 1–4 个 HTTPS PKARR 发现网关。';
   try{for(const value of values){const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error();}}catch{return '请填写有效的 HTTPS PKARR 发现网关。';}
  }
 }
 if(key==='virtual'&&!ui.editor?.id&&ui.editor?.ipMode==='custom'&&!newNetworkIp.trim())return '请填写自定义虚拟 IPv4 地址，或选择自动分配。';
 return '';
};
function openEditor(id=''){
 const n=row(id);if(id&&!n)return;const ro=!!n&&!n.status.isOwner,bound=workspaceState.configurations.find(c=>c.id===(n?n.configurationId:ui.newConfig));
 selectedConfiguration=bound&&!bound.networks.some(v=>v.networkId!==id)?bound.id:'';settingsScope='configuration';configurationRevision=0;settingsHydrated=false;configurationDrafts.delete('new');hydrateEditor();
 if(!selectedConfiguration&&bound){saved=configFromStatus({...workspaceState,settings:bound.settings});drafts=clone(saved);}
 drafts.network.owner='local';saved.network.owner='local';for(const c of [drafts,saved]){c.network.refresh*=Number(c.network.unit||1);c.network.unit=1;}
 if(!selectedConfiguration){configurationName=baseConfigurationName=n?.name||newNetworkName||'网络设置';}
 ui.editor={id,configurationId:selectedConfiguration,readOnly:ro,baseIp:newNetworkIp,baseIpMode:newNetworkIp?'custom':'auto',ipMode:newNetworkIp?'custom':'auto',customIp:newNetworkIp,saving:false};section='network';$('network-dialog').classList.toggle('read-only',ro);$('network-dialog-title').textContent=ro?'主机提供的网络设置 · '+n.name:n?'网络设置 · '+n.name:'新网络设置';$('network-dialog-subtitle').textContent=ro?'由目标主机提供，本机仅供查看。':'每个网络使用独立设置；修改仅对本网络生效。';$('network-edit-actions').hidden=ro;$('network-readonly-close').hidden=!ro;renderEditor();$('network-dialog').showModal();
}
function editorChanged(){return !!ui.editor&&(!same(saved,drafts)||newNetworkIp!==ui.editor.baseIp||!ui.editor.id&&ui.editor.ipMode!==ui.editor.baseIpMode||configurationName.trim()!==baseConfigurationName);}
async function closeEditor(){if(!ui.editor||ui.editor.saving)return;if(!ui.editor.readOnly&&editorChanged()&&!await confirmAction('放弃未保存的设置？','已保存设置保持不变。','放弃修改'))return;if(!ui.editor.readOnly){configurationDrafts.delete(selectedConfiguration||'new');newNetworkIp=ui.editor.baseIp;drafts=clone(saved);configurationName=baseConfigurationName;}$('network-dialog').close();ui.editor=null;render();}
async function saveEditor(){
 if(!ui.editor||ui.editor.readOnly)return;
 if(ui.editor.configurationId!==selectedConfiguration||ui.editor.id&&!row(ui.editor.id))throw Error('当前网络或设置已在其他窗口变更，请关闭后重新打开设置。');
 for(const [key] of editorSections()){const error=validateSection(key);if(error){section=key;renderEditor();$('settings-error').textContent=error;$('settings-error').scrollIntoView({block:'nearest'});return;}}
 if(!ui.editor.id&&newNetworkIp.trim()){
  const ip=newNetworkIp.trim().split('.').map(Number),valid=ip.length===4&&ip.every(v=>Number.isInteger(v)&&v>=0&&v<=255)&&ip[3]>0&&ip[3]<255&&(ip[0]===10||ip[0]===172&&ip[1]>=16&&ip[1]<=31||ip[0]===192&&ip[1]===168);
  if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(newNetworkIp.trim())||!valid){section='virtual';renderEditor();$('settings-error').textContent='请填写有效的私有 IPv4，或留空自动分配。';return;}
 }
 const target=row(ui.editor.id),fork=!!configuration()?.networks.some(n=>n.networkId!==ui.editor.id),assign=!!target&&(fork||target.configurationId!==selectedConfiguration),write=fork||!selectedConfiguration||!same(saved,drafts)||configurationName.trim()!==baseConfigurationName;
 if(target&&(write||assign)&&!await confirmAction('保存并应用网络设置？','仅更新：'+target.name+'。需要时会重新连接，其它网络保持不变。','保存并应用'))return;
 ui.editor.saving=true;
 try{
  const previous=selectedConfiguration||'new';
  if(write){const reply=await command('configuration',{networkId:target?.id||'',configuration:{action:'save',id:fork?'':selectedConfiguration,name:configurationName.trim()||newNetworkName||'网络设置',expectedRevision:fork?0:configurationRevision,settings:settingsDto(),confirmReconnect:true,independent:true}});selectedConfiguration=reply.configurationId||selectedConfiguration;if(!selectedConfiguration)throw Error('后台未返回独立设置编号，请保留当前草稿并重试。');ui.editor.configurationId=selectedConfiguration;configurationRevision=configuration()?.revision||1;saved=clone(drafts);baseConfigurationName=configurationName;}
  if(target&&target.configurationId!==selectedConfiguration)await command('configuration',{networkId:target.id,configuration:{action:'assign',id:selectedConfiguration,expectedRevision:configurationRevision,confirmReconnect:true,independent:true}});
  if(!ui.editor.id){ui.newConfig=selectedConfiguration;try{localStorage.setItem('conwu-create-configuration-draft',ui.newConfig);localStorage.setItem('conwu-create-ip-draft',newNetworkIp.trim());}catch{}}
  configurationDrafts.delete(previous);configurationDrafts.delete(selectedConfiguration);$('network-dialog').close();ui.editor=null;settingsHydrated=false;render();notify('网络设置已保存');
 }finally{if(ui.editor)ui.editor.saving=false;controls();}
}
async function create(){
 if(ui.creating)return;if(!newNetworkName.trim())throw Error('请为网络起一个名称。');
 ui.creating=true;controls();
 try{
  let c=workspaceState.configurations.find(c=>c.id===ui.newConfig);
  if(c?.networks.length)throw Error('本次设置已用于其他网络，请重新打开网络设置。');
  if(!c){
   const reply=await command('configuration',{networkId:'',configuration:{action:'save',id:'',name:newNetworkName.trim(),expectedRevision:0,settings:newConfigurationSettings(),confirmReconnect:false,independent:true}});
   ui.newConfig=reply.configurationId||'';try{localStorage.setItem('conwu-create-configuration-draft',ui.newConfig);}catch{}c=workspaceState.configurations.find(c=>c.id===ui.newConfig);
   if(!c)throw Error('后台未返回本次独立设置，请稍后重试。');
  }
  const p=c.settings;if(p.connectionSource==='existing'&&!p.existingEntries.some(e=>e.peerSlot===0))throw Error('请在网络设置中填写本机已有入口。');
  selectedConfiguration=c.id;
  const reply=await command('network',{networkId:'',network:{action:p.directMode?'create-direct':'create',localEnrollment:true,configurationId:c.id,service:p.service,certificatePin:p.certificatePin,mode:p.pathSelection==='udp-only'?'udp':'faketcp',name:newNetworkName.trim(),requestedVirtualIp:newNetworkIp.trim(),expectedNetwork:''}});
  ui.hostId=reply.status?.selectedNetworkId||selectedNetwork;ui.newConfig='';newNetworkIp='';
  try{localStorage.removeItem('conwu-create-ip-draft');localStorage.removeItem('conwu-create-configuration-draft');}catch{}
  render();notify('网络已创建，可生成直连码');
 }finally{ui.creating=false;controls();}
}
async function join(){
 const code=compactCodeValue(joinInviteValue);if(!validCompactCode(code))throw Error('请输入完整的 16 位直连码。');
 const reply=await command('network',{networkId:'',network:{action:'join-compact',autoConfigure:true,code,service:'',certificatePin:'',mode:'faketcp',name:'连接 '+(all().length+1),expectedNetwork:''}});
 ui.joinId=reply.status?.selectedNetworkId||selectedNetwork;render();notify('申请已发送，等待主机批准');
}
bindJoinInput=function(){
 const input=$('join-invite');if(!input)return;
 const logicalOffset=offset=>compactCodeValue(input.value.slice(0,offset||0)).length;
 const visibleOffset=offset=>Math.min(input.value.length,offset+Math.floor(offset/4));
 const updateSlots=()=>{
  const value=compactCodeValue(input.value),start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);
  document.querySelectorAll('#join-card .direct-digit').forEach((digit,i)=>{
   digit.textContent=value[i]||'X';digit.classList.toggle('filled',!!value[i]);digit.classList.toggle('placeholder',!value[i]);
   digit.classList.toggle('active',document.activeElement===input&&start===end&&i===Math.min(start,15));digit.classList.toggle('selected',document.activeElement===input&&i>=start&&i<end);
  });
 };
 const apply=(value,start,end=start)=>{
  joinInviteValue=compactCodeValue(value).slice(0,16);input.value=formatCompact(joinInviteValue);input.setSelectionRange(visibleOffset(start),visibleOffset(end));
  joinError='';$('join-error').textContent='';updateSlots();
 };
 const replaceSelection=text=>{
  const start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd),current=compactCodeValue(input.value),room=16-(current.length-(end-start)),insertion=compactCodeValue(text).slice(0,Math.max(0,room));
  apply(current.slice(0,start)+insertion+current.slice(end),start+insertion.length);
 };
 input.oninput=()=>apply(input.value,logicalOffset(input.selectionStart),logicalOffset(input.selectionEnd));
 input.onbeforeinput=e=>{
  if(!['deleteContentBackward','deleteContentForward'].includes(e.inputType))return;e.preventDefault();
  let start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);if(start===end){if(e.inputType==='deleteContentBackward')start=Math.max(0,start-1);else end=Math.min(16,end+1);}
  const value=compactCodeValue(input.value);apply(value.slice(0,start)+value.slice(end),start);
 };
 input.onpaste=e=>{e.preventDefault();replaceSelection(e.clipboardData.getData('text/plain'));};
 input.oncopy=e=>{if(input.selectionStart===input.selectionEnd)return;e.preventDefault();e.clipboardData.setData('text/plain',formatCompact(input.value.slice(input.selectionStart,input.selectionEnd)));};
 input.oncut=e=>{if(input.selectionStart===input.selectionEnd)return;e.preventDefault();e.clipboardData.setData('text/plain',formatCompact(input.value.slice(input.selectionStart,input.selectionEnd)));replaceSelection('');};
 input.onfocus=input.onclick=input.onkeyup=input.onselect=updateSlots;
 input.onblur=()=>document.querySelectorAll('#join-card .direct-digit').forEach(d=>d.classList.remove('active','selected'));
 $('join-form').onsubmit=e=>{e.preventDefault();void run(join).catch(()=>{});};
};
async function removeNetwork(id,confirmed=false){const n=row(id);if(!n)return;const host=n.status.isOwner;if(!confirmed&&!await confirmAction(host?'删除本机创建的网络？':'退出网络？',host?'结束“'+n.name+'”并删除此网络。其他网络和本机设置保留。':'本机退出“'+n.name+'”。',host?'确认删除网络':'确认退出网络','danger'))return;try{await command('network',{networkId:id,network:{action:host?'delete-network':'leave',expectedNetwork:n.status.networkId,confirmReplace:true}});}catch(error){if(!row(id))return;if(!await confirmAction('远端尚未确认','可以只移除本机记录，不代表远端授权已经撤销。原因：'+error.message,'仅从本机移除','danger'))return;await command('network',{networkId:id,network:{action:n.status.networkId?'forget-network':'remove-network',expectedNetwork:n.status.networkId,confirmReplace:true}});}if(ui.hostId===id)ui.hostId='';if(ui.joinId===id)ui.joinId='';render();notify('本机网络已移除，其他网络和设置保留');}
function chooseExit(){const networks=all();if(!networks.length)return;$('exit-network-select').innerHTML=networks.map(n=>`<option value="${esc(n.id)}">${esc(n.name)} · 本机为${n.status.isOwner?'主机':'从机'}</option>`).join('');updateExit();$('exit-dialog').showModal();}
function updateExit(){const n=row($('exit-network-select').value);if(!n)return;$('exit-title').textContent='退出网络';$('exit-confirm').textContent=n.status.isOwner?'删除并退出此网络':'确认退出网络';}
async function lockedSave(key,action){if(ui[key])return;ui[key]=true;controls();try{return await action();}finally{ui[key]=false;controls();}}
async function saveDevice(){
 const d=ui.device;if(!d.name.trim())throw Error('请输入设备名称。');
 const action={action:'settings',settings:{...deviceSettings(),coordinator:clone(d.host)},expectedRevision:ui.deviceRevision,confirmReplace:true,patch:{deviceName:d.name.trim(),expectedDeviceName:ui.deviceBase.name,logLevel:d.level,expectedLogLevel:ui.deviceBase.level}};
 if(d.startup!==ui.deviceBase.startup){action.autoStart=d.startup;action.expectedAutoStart=ui.deviceBase.startup;}
 await command('save-settings',{networkId:'',settingsBatch:{device:action,networks:[]}});terminalTheme=d.terminal;
 try{localStorage.setItem('streamlink-terminal-theme',terminalTheme);}catch{}
 ui.deviceBase=deviceValue();ui.device=clone(ui.deviceBase);ui.deviceRevision=workspaceState.deviceSettingsRevision;render();notify('本机设置已保存');
}
async function generateFor(id){
 const n=row(id);if(!n)throw Error('此网络已被移除。');const s=n.status;
 if(s.pairing?.candidate&&!await confirmAction('重新生成直连码？','当前尚未处理的申请将被取消。','重新生成'))return;
 await command('network',{networkId:id,network:{action:'invite-compact',expectedNetwork:s.networkId}});render();notify('直连码已生成');
}
async function testEntry(){const values=drafts.network.entries.local.filter(v=>v.trim());if(!values.length)throw Error('请先填写本机入口。');await command('network',{networkId:'',network:{action:'resolve-entries',settings:{...settingsDto(),existingEntries:values.map(source=>({peerSlot:0,source}))}}});if(!$('test-results'))return;const results=workspaceState.entryResolutions||[];$('test-status').textContent=results.filter(r=>!r.error).length+'/'+results.length+' 个来源解析成功';$('test-results').innerHTML=results.map(r=>`<div class="note" style="margin-bottom:8px">${esc(r.error||r.endpoints.join('、'))}</div>`).join('');}

document.addEventListener('input',e=>{
 const el=e.target,scope=el.dataset.uiScope,key=el.dataset.uiKey;
 if(scope&&key&&ui.device){const target=scope==='deviceHost'?ui.device.host:ui.device;target[key]=el.type==='checkbox'?el.checked:el.value;controls();}
 if(el.id==='new-network-ip'){newNetworkIp=el.value;if(ui.editor)ui.editor.customIp=el.value;if($('settings-error'))$('settings-error').textContent='';controls();}
});
document.addEventListener('change',e=>{if(e.target.id==='exit-network-select')updateExit();});
document.addEventListener('click',e=>{
 const b=e.target.closest('[data-ui-action],[data-ui-section]');if(!b||b.disabled)return;e.preventDefault();
 if(b.dataset.uiSection){section=b.dataset.uiSection;renderEditor();$('network-settings-body').scrollTop=0;return;}
 void run(async()=>{const id=b.dataset.network;switch(b.dataset.uiAction){
  case 'help-create':openHelp('create');break;case 'help-join':openHelp('join');break;case 'close-help':$('help-dialog').close();break;
  case 'open-editor':openEditor(id||'');break;case 'close-editor':await closeEditor();break;case 'save-editor':await saveEditor();break;
  case 'restore-editor':drafts=clone(saved);configurationName=baseConfigurationName;newNetworkIp=ui.editor.baseIp;ui.editor.ipMode=ui.editor.baseIpMode;ui.editor.customIp=newNetworkIp;renderEditor();break;
  case 'new-create':{const abandoned=workspaceState.configurations.find(c=>c.id===ui.newConfig);if(abandoned&&!abandoned.networks.length)await command('configuration',{networkId:'',configuration:{action:'delete',id:abandoned.id,expectedRevision:abandoned.revision}});ui.hostId='';ui.newConfig='';configurationDrafts.delete('new');newNetworkName='';newNetworkIp='';try{localStorage.removeItem('conwu-create-ip-draft');localStorage.removeItem('conwu-create-configuration-draft');}catch{}render();break;}
  case 'select-host':ui.hostId=id;render();break;case 'generate':await generateFor(id);break;case 'copy-pair':await copyText(formatCompact(row(ui.hostId)?.status.pairing?.code||''));break;
  case 'another-join':ui.joinId='';joinInviteValue='';joinError='';render();break;
  case 'cancel-join':await command('network',{networkId:id,network:{action:'pair-cancel'}});ui.joinId=row(id)?.status.networkId?id:'';render();if(ui.joinId)notify('申请已获批准，可在右侧退出不再需要的网络。');break;
  case 'approve':case 'reject':{const n=row(id),p=n.status.pairing;await command('network',{networkId:id,network:{action:b.dataset.uiAction,verification:p.verification,candidate:p.candidate,proposedIp:p.proposedIp,expectedNetwork:n.status.networkId}});render();break;}
  case 'remove-network':await removeNetwork(id);break;case 'choose-exit':chooseExit();break;case 'close-exit':$('exit-dialog').close();break;
  case 'confirm-exit':{const target=$('exit-network-select').value;$('exit-dialog').close();await removeNetwork(target,true);break;}
  case 'start-network':await command('start',{networkId:id});break;case 'save-device':await lockedSave('savingDevice',saveDevice);break;
  case 'restore-device':ui.device=clone(ui.deviceBase);render();break;case 'default-device':ui.device=defaultDevice();render();break;
  case 'register-service':await command('register-service',{networkId:''});break;
  case 'refresh-pkarr':await command('network',{networkId:id,network:{action:'refresh-pkarr',expectedNetwork:row(id).status.networkId}});notify('已请求刷新发现信息');break;
  case 'range-60':ui.range=60;render();break;case 'range-3600':ui.range=3600;render();break;case 'test-entry':await testEntry();break;
 }}).catch(()=>{});
});
$('network-dialog').addEventListener('cancel',e=>{e.preventDefault();void run(closeEditor).catch(()=>{});});
// Passive pairing observation has its own cancellable operation. It must not
// acquire the UI's foreground busy flag or make Cancel/Exit unclickable.
const foregroundCommand=command;
command=async function(method,extra={},quiet=false){
 const probe=ui.pairProbe;if(ui.preparingCommand||busy)throw Error('上一项操作仍在进行，请稍候。');
 if(probe&&!probe.cancelled){probe.cancelled=true;ui.preparingCommand=true;controls();try{await api('/api/command',{method:'cancel',operationId:crypto.randomUUID(),cancelOperationId:probe.id,networkId:probe.target});}catch{}finally{ui.preparingCommand=false;controls();}}
 return foregroundCommand(method,extra,quiet);
};
pollPair=async function(){
 if(!online||busy||ui.preparingCommand||expired||ui.pairProbe||Date.now()-lastPairPoll<2000)return;
 const pending=all().filter(n=>n.status.pairing?.active&&(!n.status.pairing.direct||!n.status.pairing.owner));if(!pending.length)return;
 const n=pending[pairPollCursor++%pending.length],probe={id:crypto.randomUUID(),target:n.id,version:generation,cancelled:false};ui.pairProbe=probe;lastPairPoll=Date.now();
 try{
  let reply=await api('/api/command',{method:'network',operationId:probe.id,networkId:n.id,network:{action:'pair-poll',background:true}},()=>!probe.cancelled&&generation===probe.version);
  while(reply.operation&&!reply.operation.completed&&!probe.cancelled&&online&&!expired){
   if(reply.status&&generation===probe.version&&!busy)render(reply.status);
   await new Promise(resolve=>setTimeout(resolve,700));
   reply=await api('/api/status?operation='+encodeURIComponent(probe.id),undefined,()=>!probe.cancelled&&generation===probe.version);
  }
  if(probe.cancelled||generation!==probe.version)return;
  if(reply.status&&!busy)render(reply.status);
  if(!reply.ok||reply.operation?.error)throw Error(reply.error||reply.operation.error);
  if(noticeSource==='pair')notice('');lastPairError='';
 }catch(error){if(!probe.cancelled&&generation===probe.version){lastPairPoll=Date.now()+8000;if(error.message!==lastPairError){lastPairError=error.message;notice(n.name+'：'+error.message,true,'pair');}}}
 finally{if(ui.pairProbe===probe)ui.pairProbe=null;}
};
openSettings=function(next='network'){if(['network','discovery','entry','virtual','port','stun'].includes(next)&&page==='create')openEditor(ui.hostId);else navigate('settings');};
dirtyCount=()=>((ui.editor&&!ui.editor.readOnly&&editorChanged()?1:0)+(ui.device&&!same(ui.device,ui.deviceBase)?1:0));
try{newNetworkIp=localStorage.getItem('conwu-create-ip-draft')||'';ui.newConfig=localStorage.getItem('conwu-create-configuration-draft')||'';}catch{}
boot();
})();
