'use strict';

// Live workspace presentation. Pairing, operation tracking and local session
// renewal continue to use app.js; this layer never simulates connection success.
(()=>{
Object.assign(titles,{exit:'退出网络',requests:'加入申请',coordination:'对外协调',uu:'UU远程'});
if(projectionMode.desktop)titles.projection='Projection';
delete titles.coordinator;
let terminalTheme='auto';try{terminalTheme=localStorage.getItem('streamlink-terminal-theme')||'auto';}catch{}
const liveLogView=updateLogView;
updateLogView=function(){const prior=saved.logging.terminal;saved.logging.terminal=terminalTheme;try{liveLogView();}finally{saved.logging.terminal=prior;}};
const ui={coordination:null,coordinationBase:null,codeId:'',joinId:'',joinCoordinator:'',editor:null,device:null,deviceBase:null,newConfig:'',signature:'',range:60,chart:[],rates:new Map(),sample:null,disclosures:new Map(),test:null};
// Polling keeps running while text is selected. Delay DOM writes so a refresh
// cannot destroy the browser's Range or an input's selected text mid-copy.
function holdAutomaticPaint(){
 const selection=window.getSelection(),input=document.activeElement;
 let held=ui.selecting||selection&&!selection.isCollapsed&&selection.anchorNode?.parentElement?.getClientRects().length;
 try{held=held||input?.matches('input,textarea')&&input.selectionStart!==input.selectionEnd;}catch{}
 if(held)ui.pendingPaint=true;
 return !!held;
}
function resumePaint(){
 if(ui.pendingPaint&&!holdAutomaticPaint()){
  ui.pendingPaint=false;render();updateConnectedTimes();
 }
}
function releaseSelection(){clearTimeout(ui.pointerRelease);ui.pointerRelease=0;ui.selecting=false;setTimeout(resumePaint,0);}
document.addEventListener('pointerdown',e=>{if(e.button===0&&e.isPrimary){clearTimeout(ui.pointerRelease);ui.selecting=true;}},true);
// Preserve the target until WebView2 dispatches click after pointerup.
document.addEventListener('pointerup',e=>{if(ui.selecting&&e.isPrimary&&e.button===0)ui.pointerRelease=setTimeout(releaseSelection,80);},true);
for(const event of ['click','pointercancel'])document.addEventListener(event,releaseSelection,true);
// A release outside WebView2 may not reach the document. Resume on re-entry.
window.addEventListener('pointermove',e=>{if(ui.selecting&&!ui.pointerRelease&&e.isPrimary&&!(e.buttons&1))releaseSelection();},true);
document.addEventListener('selectionchange',()=>{if(ui.pendingPaint)setTimeout(resumePaint,0);});
window.addEventListener('blur',releaseSelection);
window.addEventListener('focus',()=>{ui.selecting=false;resumePaint();resumeStatus();controls();});
const liveConnectedTimes=updateConnectedTimes;
updateConnectedTimes=function(){if(!holdAutomaticPaint())liveConnectedTimes();};
const selectedLogView=updateLogView;
updateLogView=function(){if(!holdAutomaticPaint())selectedLogView();};
const liveUnavailable=unavailable;
unavailable=function(message){if(holdAutomaticPaint()){online=false;previousTraffic=null;ui.unavailableMessage=message;}else liveUnavailable(message);if(page==='projection')projectionMode.updateCover();};
const all=()=>workspaceState?.networks||[],row=id=>all().find(n=>n.id===id);
const protocolOf=p=>({'udp-only':'直接 UDP（旧网络）','tcp-only':'纯 TCP','https-only':'HTTPS','phantun-only':'Phantun','mimic-only':'Mimic（实验）','tcpraw-only':'TCPRAW（实验）'}[p?.pathSelection]||'FakeTCP + HTTP');
const strategyOf=p=>p?.connectionSource==='existing'?'只使用已有入口':'自主打洞';
const deviceSettings=()=>workspaceState?.deviceSettings||newConfigurationSettings();
const privateFields=[['network','连接方式','link'],['discovery','配对与发现方式','globe'],['entry','已有入口','globe'],['virtual','虚拟 IP','laptop'],['port','端口设置','port'],['stun','STUN 服务器','globe']];
const uiToggle=(scope,key,value,label)=>`<label class="switch"><input type="checkbox" data-ui-scope="${scope}" data-ui-key="${key}" ${value?'checked':''} aria-label="${label}"><span class="switch-track"></span></label>`;
const kv=(label,value,mono=false)=>`<div class="kv"><span>${esc(label)}</span><span class="${mono?'mono':''}">${esc(value)}</span></div>`;
const readRows=items=>`<dl class="readonly-values">${items.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value||'未设置')}</dd></div>`).join('')}</dl>`;
const deviceValue=()=>({name:workspaceState?.deviceName||'',startup:!!workspaceState?.desktop?.autoStart,level:workspaceState?.logLevel||'info',terminal:terminalTheme});
const defaultDevice=()=>({name:workspaceState.deviceDefaults?.name||workspaceState.deviceName,startup:!!workspaceState.deviceDefaults?.autoStart,level:'info',terminal:'auto'});
function coordinatorValue(useDefaults=false){
 const host=clone({...defaults.host,...deviceSettings().coordinator});
 if(useDefaults){
  const initial=workspaceState?.deviceDefaults?.coordinator;
  return {...host,port:String(new URL(initial?.listenUrl||'https://0.0.0.0:1145').port),certificateFile:'',certificateKeyFile:''};
 }
 return {...host,port:String(new URL(host.listenUrl).port||47822)};
}
const compactCodeValue=value=>String(value||'').toUpperCase().replace(/[\s\u2010-\u2015-]/g,'').replace(/O/g,'0').replace(/[IL]/g,'1');
const formatCompact=value=>compactCodeValue(value).match(/.{1,4}/g)?.join('-')||'';
const compactLimit=value=>compactCodeValue(value).startsWith('2')?36:16;
const validCompactCode=value=>{const code=compactCodeValue(value);return /^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]+$/.test(code)&&code.length===compactLimit(code);};
const coordinatedCode=value=>validCompactCode(value)&&/^[MNPQRSTVWXYZ]/.test(compactCodeValue(value));
function normalizedJoinCoordinator(value){
 if(!value.trim())return '';
 try{const url=new URL(value.trim());if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)throw Error();if(!url.pathname.endsWith('/'))url.pathname+='/';return url.href;}
 catch{throw Error('请填写有效的 HTTPS 协调服务器地址。');}
}
const inheritedPairConfig=configFromStatus;
configFromStatus=function(s){
 const c=inheritedPairConfig(s),p=s.settings||{},d=workspaceState?.networkDefaults;
 c.network.pkarrGateways=(p.pkarrGateways||d?.pkarrGateways||['https://pkarr.pubky.app','https://pkarr.pubky.org']).join('\n');
 c.stun.tcp=(p.tcpStun??d?.tcpStun??[]).join('\n');
 return c;
};
function directGroups(value,placeholder=false){
 const code=compactCodeValue(value);
 const extended=compactLimit(code)===36;
 return `<div class="direct-groups${extended?' extended':''}" aria-hidden="true">${Array.from({length:extended?9:4},(_,g)=>`<div class="direct-group">${Array.from({length:4},(_,i)=>{const c=code[g*4+i];return `<span class="direct-digit ${c?'filled':placeholder?'placeholder':''}">${esc(c||(placeholder?'X':''))}</span>`;}).join('')}</div>`).join('')}</div>`;
}
function helpLink(kind){return `<div class="form-help"><button class="help-link" type="button" data-ui-action="help-${kind}">如何${kind==='create'?'创建':'加入'}网络？</button></div>`;}
function openHelp(kind){
 const create=kind==='create';$('help-title').textContent=create?'如何创建网络？':'如何加入网络？';
 const steps=create?['首先输入“网络名称”与设置“网络设置”；','在本机生成“直连码”（IPv4 为 16 位；TCP／HTTPS 可选择 36 位 IPv6 码）。']:['在“输入框”处填写目标主机所生成的“直连码”','等待目标主机通过“加入申请”批准本机加入'];
 $('help-content').innerHTML=steps.map((s,i)=>`<p class="help-step"><span>${i?'②':'①'}</span>${esc(s)}</p>`).join('');$('help-dialog').showModal();
}
function initializeDrafts(){
 if(!workspaceState)return;
 if(!ui.device||!ui.savingDevice&&same(ui.device,ui.deviceBase)){ui.deviceBase=deviceValue();ui.device=clone(ui.deviceBase);ui.deviceRevision=workspaceState.deviceSettingsRevision;}
 if(!ui.coordination||!ui.savingCoordination&&same(ui.coordination,ui.coordinationBase)){ui.coordinationBase=coordinatorValue();ui.coordination=clone(ui.coordinationBase);}
 if(ui.newConfig&&!workspaceState.configurations?.some(c=>c.id===ui.newConfig))ui.newConfig='';
}
function deviceSaveActions(){return `<div class="heading-actions"><div class="heading-action-buttons"><button class="btn" data-ui-action="default-device">恢复默认设置</button><button class="btn primary" data-ui-action="save-device" id="save-device">${icon('save')}保存设置</button></div><span class="save-state" id="device-save-state" role="status"></span></div>`;}
function networkList(host){
 const rows=all().filter(n=>!!n.status.networkId&&n.status.isOwner===host);
 return `<article class="card network-list-card" id="${host?'owned':'joined'}-networks"><div class="table-title"><h2>本机${host?'创建':'加入'}的网络</h2><span class="small">${rows.length} 个网络</span></div>${rows.length?rows.map(n=>{
  const s=n.status,p=s.peers[0],live=online&&s.networkEnabled&&!!p?.connected;
  const status=live?'已直连 '+p.name:!online?'状态待确认':!s.networkEnabled?'已断开连接':p?.connection?.phase==='Paused'?'对机已断开连接':p?'等待 '+p.name+' 上线':'等待另一台设备加入';
  const action=host?'remove-network':s.networkEnabled?'disconnect-network':'reconnect-network';
  const label=host?'删除网络':s.networkEnabled?'断开连接':'重新连接';
  return `<div class="network-entry" data-network-row="${esc(n.id)}">
   <div class="list-row">
    <div class="grow">${host?`<button class="network-name-button" data-ui-action="select-host" data-network="${esc(n.id)}" title="查看此网络的直连码">${esc(n.name)}</button>`:`<strong>${esc(n.name)}</strong>`}
     <div class="network-local-ip">本机虚拟 IP：<span class="mono">${esc(s.virtualIp||'待分配')}</span></div>
     <div class="network-peer"><span class="dot ${live?'good':''}"></span><span>${esc(status)}</span></div>
     <div class="network-peer-ip">对机虚拟 IP：<span class="mono">${esc(p?.virtualIp||'待分配')}</span></div>
     ${host&&!s.networkEnabled?`<button class="text-btn" data-ui-action="start-network" data-network="${esc(n.id)}">连接网络</button>`:''}
    </div>
    <div class="network-row-actions">${host?`<button class="btn compact" data-ui-action="select-host" data-network="${esc(n.id)}">${icon('link')}查看直连码</button>`:''}
     <button class="btn compact" data-ui-action="open-editor" data-network="${esc(n.id)}">${icon(host?'settings':'shield')}${host?'网络设置':'查看设置'}</button>
     ${networkActionButton(n,action,label)}
    </div>
   </div>
  </div>`;
 }).join(''):`<div class="empty">${icon(host?'create':'join')}<h2>还没有${host?'创建':'加入'}网络</h2><p>${host?'在左侧创建后，会在这里显示。':'通过主机审批后，会在这里显示。'}</p></div>`}</article>`;
}
function currentCreateSettings(){return workspaceState?.configurations.find(c=>c.id===ui.newConfig)?.settings||newConfigurationSettings();}
function settingsLaunch(){
 const p=currentCreateSettings(),custom=newNetworkIp;
 return `<button class="settings-launch" type="button" data-ui-action="open-editor" data-network="" id="open-network-settings">${icon('settings')}<span class="grow"><strong>网络设置</strong><small>${protocolOf(p)} · ${strategyOf(p)} · ${custom?'自定义虚拟 IP':'自动分配虚拟 IP'}</small></span><span class="open-label">打开设置${icon('chevron')}</span></button>`;
}
createPage=function(){
 const form=`<form id="create-form"><label class="field"><span>网络名称</span><input id="new-network-name" class="form-input-large" value="${esc(newNetworkName)}" maxlength="64" placeholder="例如：主机—笔记本" autocomplete="off"></label>${settingsLaunch()}<div id="create-error" class="error" role="status"></div><div class="form-operation"><button class="btn primary" id="create-network" type="submit">${icon('plus')}创建网络</button></div>${helpLink('create')}</form>`;
 return heading('创建网络','以本机为主机，创建网络')+`<div class="network-columns"><article class="card create-form"><div class="pad">${form}</div></article>${networkList(true)}</div>`;
};
function invitationCode(){const p=row(ui.codeId)?.status.pairing;return p?.active&&p.expires*1000>Date.now()&&p.format==='compact'&&validCompactCode(p.code)?compactCodeValue(p.code):'';}
function updateInvitationDialog(){
 if(holdAutomaticPaint())return;
 const dialog=$('invitation-dialog');if(!dialog.open)return;
 const n=row(ui.codeId);if(!n||!n.status.isOwner){closeInvitation();return;}
 $('invitation-title').textContent=n.name;
 const code=invitationCode(),display=$('invitation-code');
 const dualStack=['tcp-only','https-only'].includes(n.status.settings?.pathSelection);
 const coordinated=n.status.settings?.discoveryMode==='coordinator'&&n.status.settings.connectionSource!=='existing'&&!!n.status.settings.service;
 $('invitation-code-length').textContent=code?(n.status.pairing?.coordinated?'协调 IPv4 · 16 位':code.length===36?'IPv6 · 36 位':'IPv4 · 16 位'):'';
 $('invitation-family-field').hidden=!dualStack||coordinated;
 $('invitation-family').hidden=!dualStack||coordinated;
 $('invitation-family-hint').textContent=coordinated
  ? '协调配对使用 16 位直连码。复制时附带协调服务器地址。'
  : dualStack?'默认优先生成 IPv4 码；使用 IPv6 码时，双方均需具备可用的 IPv6 网络。':'当前协议使用 IPv4 入口，生成 16 位直连码。';
 display.setAttribute('aria-label',code?'本机直连码：'+formatCompact(code):'尚未生成直连码');
 if(display.dataset.code!==code){display.innerHTML=directGroups(code,true);display.dataset.code=code;}
 const entry=n.status.entryPreparation,existing=n.status.settings?.connectionSource==='existing';
 let entryText=entry?.receiverError?'本机接收入口启动失败：'+entry.receiverError:entry?.detail||'正在准备本机入口';
 if(!entry?.receiverError&&entry?.receiverReady===false)entryText+='；本机接收入口尚未就绪';
 if(existing&&entry?.receiverReady)entryText='本机接收入口已就绪，生成时解析已配置的主机入口。';
 if(entry?.state==='Unavailable'&&entry.retryAt){const wait=Math.max(0,Math.ceil(entry.retryAt-Date.now()/1000));entryText+=wait?'；约 '+wait+' 秒后自动重试':'；等待重试，也可点击下方按钮立即重试';}
 if(entry?.attempt)entryText+='（第 '+entry.attempt+' 次'+(entry.elapsedMilliseconds?'，本轮 '+(entry.elapsedMilliseconds/1000).toFixed(1)+' 秒':'')+'）';
 $('invitation-status').textContent=entryText;
 $('invitation-generate').dataset.network=n.id;
 $('invitation-generate').innerHTML=icon('refresh')+(code?'重新生成直连码':entry?.state==='Unavailable'?'重试并生成直连码':'生成直连码');
}
function openInvitation(id){
 const n=row(id);if(!n?.status.isOwner)throw Error('此网络不是本机创建的网络。');
 ui.codeId=id;$('invitation-error').textContent='';
 $('invitation-family').value='';
 const dialog=$('invitation-dialog');if(!dialog.open)dialog.showModal();updateInvitationDialog();controls();
}
function closeInvitation(){ui.codeId='';$('invitation-dialog').close();$('invitation-error').textContent='';}

function pendingJoin(){
 return row(ui.joinId)||all().find(n=>!n.status.networkId&&!n.status.networkRevoked&&n.status.pairing?.active&&!n.status.pairing.owner);
}
joinPage=function(){
 const n=pendingJoin(),p=n?.status.pairing;
 const done=!!(ui.joinId&&n?.status.networkId),waiting=!n?.status.networkId&&p?.active&&!p.owner;
 const progress=waiting?`<section class="join-progress" aria-live="polite"><p><strong>${p.verification?'等待主机同意':'正在联系主机'}</strong></p><p>${esc(p.state)}</p>${p.verification?kv('双方校验码',p.verification,true):''}<button type="button" class="btn compact" data-ui-action="cancel-join" data-network="${esc(n.id)}">取消加入</button></section>`:
  done?`<section class="join-progress" aria-live="polite"><p><strong>已加入 ${esc(n.name)}</strong></p><p>${n.status.directPeers?'已建立直连':'正在建立直连'}</p><div class="row wrap"><button type="button" class="btn compact" data-page="overview">查看概况</button><button type="button" class="btn compact" data-ui-action="another-join">加入其他网络</button></div></section>`:'';
 const form=`<form id="join-form"><label class="pair-label" for="join-invite">目标主机的直连码</label><div class="code-control direct-code-control">${directGroups(joinInviteValue,true)}<input id="join-invite" aria-label="目标主机的直连码，IPv4 为16位，IPv6 为36位" type="text" maxlength="44" spellcheck="false" autocomplete="off" autocapitalize="characters" value="${esc(formatCompact(joinInviteValue))}"></div><label class="field" id="join-coordinator-field" ${coordinatedCode(joinInviteValue)?'':'hidden'}><span>协调服务器地址（可选）</span><input id="join-coordinator" type="url" maxlength="2113" spellcheck="false" autocomplete="off" placeholder="https://coord.example.com/" value="${esc(ui.joinCoordinator)}"></label><div class="form-operation"><button class="btn primary" id="join-submit" type="submit">请求加入${icon('join')}</button></div><div id="join-error" class="error" role="status">${esc(joinError||p?.error||'')}</div>${progress}${helpLink('join')}</form>`;
 return heading('加入网络','向目标主机发送申请，加入网络')+`<div class="network-columns"><article class="card pad" id="join-card">${form}</article>${networkList(false)}</div>`;
};
function requestsPage(){return heading('加入申请','核对设备与校验码，决定是否允许加入。')+incomingPage().replaceAll('data-action="approve"','data-ui-action="approve"').replaceAll('data-action="reject"','data-ui-action="reject"').replaceAll('data-request-network=','data-network=');}
function liveSettingsPage(){
 const d=ui.device||deviceValue(),desktop=workspaceState?.desktop,linux=workspaceState?.platform==='linux';
 const registered=linux||desktop?.serviceRegistered;
 const serviceState=registered?(state?.serviceReady?'正在运行':'未运行'):'尚未注册';
 return heading('设置','',deviceSaveActions())+`
 <article class="card settings-page">
  <section class="settings-section"><div><h2>启动与服务</h2><p class="intro">配置开机启动与服务</p></div><div>
   <div class="switch-row"><div><h3>开机启动</h3><p>${linux?'由系统服务管理。':'启动后台服务，登录后显示托盘。'}</p></div>${linux?'<span class="badge">由 systemd 管理</span>':uiToggle('device','startup',d.startup,'开机启动')}</div>
   <div class="row between section-spacer"><span class="small muted">后台服务</span><span class="badge ${state?.serviceReady&&registered?'good':''}">${serviceState}</span>${!linux&&(!registered||!state?.serviceReady)?'<button class="btn compact" data-ui-action="register-service">注册／启动服务</button>':''}</div>
  </div></section>
  <section class="settings-section"><div><h2>本机设备名</h2><p class="intro">所有网络统一使用这个设备名称。</p></div><label class="field"><span>设备名称</span><input id="device-name" data-ui-scope="device" data-ui-key="name" maxlength="64" value="${esc(d.name)}"></label></section>
  <section class="settings-section"><div><h2>日志设置</h2><p class="intro">调整日志详细程度与终端外观</p></div><div>
   <label class="field"><span>日志等级</span><select data-ui-scope="device" data-ui-key="level">${[['error','仅错误'],['warn','警告与错误'],['info','常规信息'],['debug','详细调试'],['off','关闭记录']].map(([v,t])=>`<option value="${v}" ${d.level===v?'selected':''}>${t}</option>`).join('')}</select></label>
   <label class="field"><span>终端外观</span><select data-ui-scope="device" data-ui-key="terminal">${[['auto','跟随界面'],['dark','深色'],['light','浅色']].map(([v,t])=>`<option value="${v}" ${d.terminal===v?'selected':''}>${t}</option>`).join('')}</select></label><button class="text-btn" data-page="logs">打开日志${icon('chevron')}</button>
  </div></section>
  <section class="settings-section"><div><h2>软件更新</h2><p class="intro">检查 ConWU 官方正式版</p></div>${updateDetails()}</section>
 </article>`;
}
function updateDetails(){
 const u=workspaceState?.update,l=workspaceState?.localUpdate;
 const resumable=l?.state==='Error'&&l.version===u?.latestVersion&&l.downloadedBytes>0&&l.downloadedBytes<l.totalBytes;
 const safeLink=value=>{try{const p=new URL(value);return p.protocol==='https:'&&p.hostname==='github.com'&&!p.username&&!p.password&&p.port===''&&p.pathname.startsWith('/MrSGSA/ConWU/releases/')?p.href:'';}catch{return '';}};
 const pageUrl=safeLink(u?.releaseUrl||''),download=safeLink(u?.package?.url||'');
 if(['Installed','Completed','WaitingPeers','Error','Failed'].includes(l?.state)){try{localStorage.removeItem('conwu-local-update');}catch{}}
 return `<div id="software-update-details" data-update-signature="${esc(updateSignature())}"><p>当前版本：<span class="mono">${esc((workspaceState?.version||'读取中').split('+')[0])}</span></p><p role="status" id="update-state">${esc(u?.message||'尚未检查更新')}</p>${u?.checkedAt?`<p class="hint">上次检查：${esc(new Date(u.checkedAt*1000).toLocaleString())}</p>`:''}
 ${l?.state&&l.state!=='Idle'&&!l.acknowledged?`<p id="local-update-state" role="status">${esc(l.message||l.state)}</p>${l.receiptId&&['Installed','Error'].includes(l.state)?`<button class="text-btn" data-ui-action="dismiss-update" data-receipt="${esc(l.receiptId)}">关闭提示</button>`:''}${l.state==='Downloading'||resumable?`<progress aria-label="安装包下载进度" max="${Number(l.totalBytes)||1}" value="${Number(l.downloadedBytes)||0}"></progress><span class="hint"> ${Math.floor((l.downloadedBytes||0)*100/Math.max(1,l.totalBytes||1))}%</span>`:''}${l.rebootRequired?'<p class="hint">系统提示需要稍后重启；ConWU 不会自动重启设备。</p>':''}`:''}
 <div class="row section-spacer"><button class="btn compact" data-ui-action="check-update" ${u?.state==='Checking'?'disabled':''}>${icon('refresh')}${u?.state==='Checking'?'正在检查…':'检查更新'}</button>${l?.supported?`${u?.updateAvailable&&download&&!l.busy&&!l.canInstall?`<button class="btn primary compact" data-ui-action="download-update">${resumable?'继续下载':'下载'} ${esc(u.latestVersion)}</button>`:''}${l.canInstall?`<button class="btn primary compact" data-ui-action="install-update">安装 ${esc(l.version)}</button>`:''}`:u?.updateAvailable&&download?`<button class="btn primary compact" data-ui-action="download-update">下载 ${esc(u.latestVersion)}</button>`:''}${pageUrl?`<a class="text-btn" href="${esc(pageUrl)}" target="_blank" rel="noopener noreferrer">版本说明</a>`:''}</div><p class="hint">${l?.supported?'完整下载并校验后，由你确认安装。本机独立运行 MSI，安装后自动恢复后台和原先启用的网络。':'更新检查不会自动安装或更改设置。'}</p></div>`;
}
function updateSignature(){const u=workspaceState?.update;return JSON.stringify([workspaceState?.version,u?.state,u?.message,u?.latestVersion,u?.checkedAt,u?.updateAvailable,u?.releaseUrl,u?.package?.url,workspaceState?.localUpdate]);}
function syncUpdateNotice(){
 const l=workspaceState?.localUpdate,terminal=['Installed','Completed','WaitingPeers','Error','Failed'].includes(l?.state);
 if(terminal){try{localStorage.removeItem('conwu-local-update');}catch{}if(noticeSource==='update')notice('');}
 const receipt=l?.state==='Installed'&&!l.acknowledged&&!l.busy?l.receiptId:'';
 if(ui.updateNoticeReceipt===receipt)return;
 clearTimeout(ui.updateNoticeTimer);ui.updateNoticeReceipt=receipt;
 if(receipt)ui.updateNoticeTimer=setTimeout(async()=>{
  const current=workspaceState?.localUpdate;
  if(!online||current?.receiptId!==receipt||current.acknowledged||current.busy||current.state!=='Installed')return;
  try{await command('update-dismiss',{localUpdate:{receiptId:receipt}},true);}catch{}
 },12000);
}
function installingLocally(){try{return Date.now()-Number(localStorage.getItem('conwu-local-update'))<300000;}catch{return false;}}
const normalUnavailable=unavailable;
unavailable=function(message){if(installingLocally()){online=false;notice('正在本机安装 ConWU，暂时断开属于更新过程。安装后会自动恢复后台和组网，并重新打开面板。',false,'update');controls();return;}normalUnavailable(message);};
function openUpdateSources(){
 const u=workspaceState?.update,l=workspaceState?.localUpdate;
 if(!u?.updateAvailable||!u.package||!/^\d+\.\d+\.\d+$/.test(u.latestVersion))throw Error('请先检查适合本机的正式版更新。');
 const github=new URL(u.releaseUrl);
 if(github.origin!=='https://github.com'||!github.pathname.startsWith('/MrSGSA/ConWU/releases/tag/'))throw Error('正式版来源无效。');
 const tag=github.pathname.split('/').pop(),gitee='https://gitee.com/space4sgsa/ConWU/releases/tag/'+encodeURIComponent(tag);
 const msi=String(u.package.url).endsWith('.msi');ui.updateVersion=u.latestVersion;
 $('update-source-title').textContent='下载 ConWU '+u.latestVersion;
 $('update-source-error').textContent='';
 $('update-source-content').innerHTML=[['github','GitHub',github.href],['gitee','Gitee',gitee]].map(([source,name,url])=>`<article class="update-source-card"><h3>${name}</h3>${l?.supported&&msi?`<button class="btn primary" data-ui-action="download-from-source" data-source="${source}">下载 MSI</button>`:`<a class="btn primary" href="${esc(source==='github'?u.package.url:url)}" target="_blank" rel="noopener noreferrer">${msi?'下载 MSI':'下载安装包'}</a>`}<a class="source-website" href="${esc(url)}" target="_blank" rel="noopener noreferrer">访问 ${name}</a></article>`).join('');
 $('update-source-dialog').showModal();controls();
}
async function downloadFromSource(source){
 try{if(ui.updateVersion!==workspaceState?.update?.latestVersion)throw Error('可更新版本已改变，请关闭后重新选择。');await localUpdate(false,source);$('update-source-dialog').close();}
 catch(error){$('update-source-error').textContent=error.message;}
}
async function localUpdate(install,source='github'){
 const l=workspaceState?.localUpdate,u=workspaceState?.update;
 if(install&&!await confirmAction('安装 ConWU '+l.version+'？','安装包已下载并校验。确认后在本机继续安装，期间远程连接会暂时中断；完成后自动恢复后台和原先启用的网络。','确认更新'))return;
 if(install)try{localStorage.setItem('conwu-local-update',String(Date.now()));}catch{}
 let reply;
 try{reply=await api('/api/command',{method:install?'update-install':'update-download',operationId:crypto.randomUUID(),localUpdate:{version:install?l.version:u.latestVersion,ticket:install?l.ticket:'',source}});}
 catch(error){if(install&&error.retryable){notify('已发送本机更新确认，正在等待安装状态。请稍候自动恢复后台。');void refresh();return;}if(install)try{localStorage.removeItem('conwu-local-update');}catch{}throw error;}
 if(!reply.ok){if(install)try{localStorage.removeItem('conwu-local-update');}catch{}throw Error(reply.error||'更新任务未被受理');}
 if(reply.status)render(reply.status);
}
function coordinationPage(){
 const host=deviceSettings().coordinator||{},status=workspaceState.coordinator,clients=status?.clients||[];
 const running=online&&status?.running;
 const label=!online?'等待后台状态':status?.enabled!==host.enabled?(host.enabled?'正在启动':'正在停止'):status?.state||'正在读取';
 return heading('对外协调','由本机提供配对、地址发现与自主打洞辅助服务。')+`
 <div class="network-columns coordination-columns">
  <article class="card pad">
   <div class="switch-row"><div><h2>本机协调服务</h2><p class="hint">为选用本机协调地址的设备提供服务。</p></div>${uiToggle('coordinationSwitch','enabled',host.enabled,'开启本机协调服务')}</div>
   <div class="kv provider-status"><span>当前状态</span><span class="row" id="coordinator-state"><span class="dot ${running?'good':''}"></span>${esc(label)}</span></div>
   ${running&&status?.punchAssist?`<div class="kv"><span>首次配对辅助</span><span>等待 ${Number(status.punchAssist.waiting)||0} · 已安排探测 ${Number(status.punchAssist.scheduled)||0}</span></div><p class="hint">仅协助自主打洞，业务保持设备直连；已有入口不参与。</p>`:''}
   <button class="settings-launch" data-ui-action="open-coordination-settings"><span>${icon('settings')}</span><span class="grow"><strong>本机协调设置</strong><small>监听端口 ${esc(coordinatorValue().port)}</small></span><span class="open-label">打开设置${icon('chevron')}</span></button>
  </article>
  <article class="card table-card">
   <div class="pad"><h2>使用本机协调的设备</h2><p class="hint">最近 3 分钟内有已验证活动的设备，最多显示 128 台。</p></div>
   ${clients.length?`<div class="table-scroll"><table><thead><tr><th>设备</th><th>用途</th><th>网络数</th><th>最近活动</th></tr></thead><tbody>${clients.map(client=>`<tr><td><strong>${esc(client.name)}</strong></td><td>${esc(client.phase)}</td><td>${client.networks||'—'}</td><td class="mono">${esc(new Date(client.lastSeen).toLocaleTimeString())}</td></tr>`).join('')}</tbody></table></div>`:`<div class="empty">${icon('server')}<h2>${running?'暂无设备使用本机协调':'等待本机协调服务开启'}</h2></div>`}
  </article>
 </div>`;
}
function renderCoordinatorEditor(){
 const draft=ui.coordination;
 $('coordination-error').textContent='';
 $('coordination-settings-fields').innerHTML=`
  <label class="field"><span>监听端口</span><input type="number" min="1024" max="65535" data-ui-scope="coordination" data-ui-key="port" value="${esc(draft.port)}"></label>
  <label class="field"><span>证书文件（可选）</span><input data-ui-scope="coordination" data-ui-key="certificateFile" value="${esc(draft.certificateFile||'')}" placeholder="留空使用本机自动管理的证书" spellcheck="false"></label>
  <label class="field"><span>私钥文件（可选）</span><input data-ui-scope="coordination" data-ui-key="certificateKeyFile" value="${esc(draft.certificateKeyFile||'')}" placeholder="留空使用本机自动管理的私钥" spellcheck="false"></label>
  ${readRows([['本机证书指纹',workspaceState.coordinator?.certificatePin||'尚未启用 HTTPS 监听']])}`;
 controls();
}
async function saveCoordinatorSettings(settings,quiet=false){
 const action={action:'settings',settings:{...deviceSettings(),coordinator:settings},expectedRevision:workspaceState.deviceSettingsRevision,confirmReplace:true};
 await command('save-settings',{networkId:'',settingsBatch:{device:action,networks:[]}},quiet);
}
async function toggleCoordinator(enabled){
 const draft=clone(ui.coordination),base=ui.coordinationBase;
 await saveCoordinatorSettings({...deviceSettings().coordinator,enabled});
 const current=coordinatorValue();
 for(const key of Object.keys(current))if(same(draft[key],base[key]))draft[key]=current[key];
 ui.coordinationBase=current;ui.coordination=draft;render();
}
async function saveCoordinator(){
 if(!same(coordinatorValue(),ui.coordinationBase))throw Error('本机协调设置已被其他窗口修改，请关闭并重新打开设置后重试。');
 const {port,...settings}=ui.coordination;
 if(!/^\d+$/.test(port)||Number(port)<1024||Number(port)>65535)throw Error('监听端口需为 1024–65535。');
 if(!!settings.certificateFile.trim()!==!!settings.certificateKeyFile.trim())throw Error('证书与私钥需要同时填写，也可以同时留空。');
 const address=new URL(settings.listenUrl);address.port=String(Number(port));
 await saveCoordinatorSettings({...settings,listenUrl:address.href,certificateFile:settings.certificateFile.trim(),certificateKeyFile:settings.certificateKeyFile.trim()},true);
 ui.coordinationBase=coordinatorValue();ui.coordination=clone(ui.coordinationBase);renderCoordinatorEditor();render();notify('本机协调设置已保存');
}
function sampleTraffic(next){const now=performance.now(),old=ui.sample,a=next.aggregate,peers=new Map(all().flatMap(n=>(n.status.peers||[]).map(p=>[n.id+':'+p.slot,p])));if(!a)return;const dt=old?(now-old.time)/1000:0,valid=old&&dt>=.1&&dt<=10;ui.rates.clear();if(valid)for(const [id,p]of peers){const q=old.peers.get(id);if(q&&p.sentBytes>=q.sentBytes&&p.receivedBytes>=q.receivedBytes)ui.rates.set(id,{up:(p.sentBytes-q.sentBytes)/dt,down:(p.receivedBytes-q.receivedBytes)/dt});}if(valid&&a.sentBytes>=old.sent&&a.receivedBytes>=old.received)ui.chart.push({time:now,up:(a.sentBytes-old.sent)/dt,down:(a.receivedBytes-old.received)/dt});ui.chart=ui.chart.filter(p=>now-p.time<3600000);ui.sample={time:now,sent:a.sentBytes,received:a.receivedBytes,peers};}
function chart(){const now=performance.now(),values=ui.chart.filter(p=>now-p.time<=ui.range*1000),max=Math.max(1,...values.flatMap(p=>[p.up,p.down])),points=key=>values.map(p=>`${32+600*(1-(now-p.time)/(ui.range*1000))},${105-98*p[key]/max}`).join(' ');return `<svg class="traffic-chart" viewBox="0 0 640 128" preserveAspectRatio="none" role="img" aria-label="实际上传与下载速度折线图"><path d="M32 105H632M32 56H632M32 7H632" stroke="var(--line)" stroke-dasharray="3 5" fill="none"/><text x="4" y="12" fill="var(--dim)">${(max/1e6).toFixed(1)}</text><text x="4" y="109" fill="var(--dim)">0</text><polyline points="${points('down')}" fill="none" stroke="var(--accent)" stroke-width="1.8" vector-effect="non-scaling-stroke"/><polyline points="${points('up')}" fill="none" stroke="var(--green)" stroke-width="1.5" vector-effect="non-scaling-stroke"/><text x="32" y="124" fill="var(--dim)">${ui.range===60?'1 分钟前':'1 小时前'}</text><text x="610" y="124" fill="var(--dim)">现在</text></svg>`;}
overviewPage=function(){
 const networks=all().filter(n=>n.status.networkId),a=workspaceState?.aggregate,rate=online?ui.chart.at(-1):null;
 const members=networks.filter(n=>!n.status.networkRevoked);
 const created=members.filter(n=>n.status.isOwner).length;
 const direct=new Set(members.flatMap(n=>n.status.peers.filter(p=>p.connected&&p.deviceId).map(p=>p.deviceId)));
 return heading('概况','本机信息与所有网络的连接状态。')+`<div class="overview-top"><article class="card pad device-card"><div class="row device-heading"><div class="avatar">${icon('laptop')}</div><div class="grow"><h2 class="device-name">${esc(workspaceState?.deviceName||'正在读取')}</h2></div></div><div class="device-summary"><span>已加入 <b>${members.length-created}</b> 个网络</span><span>已创建 <b>${created}</b> 个网络</span><span>与 <b>${online?direct.size:'—'}</b> 台设备直连</span></div></article><article class="card chart-card"><div class="chart-head"><h2>实时流量</h2><div class="range" role="group" aria-label="流量图时间范围"><button data-ui-action="range-60" aria-pressed="${ui.range===60}" class="${ui.range===60?'active':''}">一分钟</button><button data-ui-action="range-3600" aria-pressed="${ui.range===3600}" class="${ui.range===3600?'active':''}">一小时</button></div></div><div class="chart-metrics">${[['up','上传','green',a?.sentBytes],['down','下载','accent',a?.receivedBytes]].map(([key,name,color,value])=>`<div><div class="metric-caption"><span class="dot" style="background:var(--${color})"></span>${name}</div><div class="metric-value"><span data-overview-rate="${key}">${rate?(rate[key]/1e6).toFixed(2):'—'}</span><small>MB/s</small></div><div class="metric-total" data-overview-total="${key}">累计 ${total(value||0)}</div></div>`).join('')}</div><div class="chart-wrap">${chart()}</div></article></div><article class="card overview-devices"><div class="table-title"><h2>设备与网络</h2></div><div class="table-scroll"><table><colgroup><col style="width:18%"><col style="width:13%"><col style="width:10%"><col style="width:19%"><col style="width:22%"><col style="width:8%"><col style="width:10%"></colgroup><thead><tr><th scope="col">设备</th><th scope="col">网络</th><th scope="col">角色</th><th scope="col">虚拟 IP</th><th scope="col">连接状态</th><th scope="col">延迟</th><th scope="col">流量</th></tr></thead><tbody><tr class="local-row"><td><div class="row">${icon('laptop')}<strong>${esc(workspaceState?.deviceName||'本机')}</strong></div></td><td colspan="6" class="self-label">本机</td></tr>${networks.map(n=>{
  const s=n.status,p=s.peers[0],connected=online&&p?.connected,r=ui.rates.get(n.id+':'+p?.slot),elapsed=p?.connection?.elapsedMs||0;
  const pairs=(name,values,mono=false)=>`<div class="paired-values">${values.map((v,i)=>`<div class="paired-line"><span class="paired-label">${i?'对机':'本机'}</span><span class="${mono?'mono':''}" data-value="${i?'peer':'local'}-${name}">${esc(v||'待分配')}</span></div>`).join('')}</div>`;
  return `<tr data-peer-row="${esc(n.id)}"><td><strong class="peer-name">${esc(p?.name||'等待另一台设备')}</strong></td><td>${esc(n.name)}</td><td class="role-value">${pairs('role',[s.isOwner?'主机':'从机',s.isOwner?'从机':'主机'])}</td><td>${pairs('ip',[s.virtualIp,p?.virtualIp],true)}</td><td><div class="cell-status"><span class="dot ${connected?'good':''}"></span>${connected?'已直连':!online?'状态待确认':!s.networkEnabled?'已断开连接':esc(phaseNames[p?.connection?.phase]||'等待设备')}</div><div class="cell-sub">${protocolOf(s.settings)}</div>${connected?`<div class="cell-sub">已直连 <span data-network-duration="${elapsed}" data-duration-sample="${performance.now()}">${connectedDuration(elapsed)}</span></div>`:''}<div class="cell-sub entry">${esc(connected?'实际入口：':'上次入口：')}${esc(p?.outerTarget&&p.outerTarget!=='Unknown'?p.outerTarget:p?.entryDirection==='Inbound'?'入站直连 · 本机端口 '+s.settings.listenPort:'待认证连接')}</div></td><td class="mono" data-overview-rtt>${connected&&p.rttMs!=null?p.rttMs.toFixed(1)+' ms':'—'}</td><td><div class="traffic-cell"><div><span class="up">↑</span> <span data-peer-total="up">${total(p?.sentBytes||0)}</span><div class="rate" data-peer-rate="up">${speed(online?r?.up:null)}</div></div><div><span class="down">↓</span> <span data-peer-total="down">${total(p?.receivedBytes||0)}</span><div class="rate" data-peer-rate="down">${speed(online?r?.down:null)}</div></div></div></td></tr>`;
 }).join('')}</tbody></table></div></article>`;
};
function overviewSignature(){
 return JSON.stringify([page,online,workspaceState?.deviceName,all().filter(n=>n.status.networkId).map(n=>{
  const s=n.status,p=s.peers[0];
  return [n.id,n.name,s.isOwner,s.virtualIp,s.networkRevoked,s.networkEnabled,s.settings?.pathSelection,
   s.settings?.listenPort,p?.deviceId,p?.name,p?.virtualIp,p?.connected,p?.connection?.phase,p?.outerTarget,p?.entryDirection];
 })]);
}
function updateOverviewTraffic(){
 const rate=online?ui.chart.at(-1):null,aggregate=workspaceState?.aggregate;
 for(const [key,value] of [['up',aggregate?.sentBytes],['down',aggregate?.receivedBytes]]){
  document.querySelector('[data-overview-rate="'+key+'"]').textContent=rate?(rate[key]/1e6).toFixed(2):'—';
  document.querySelector('[data-overview-total="'+key+'"]').textContent='累计 '+total(value||0);
 }
 document.querySelector('.overview-top .chart-wrap').innerHTML=chart();
 for(const b of document.querySelectorAll('.chart-head [data-ui-action]')){
  const active=b.dataset.uiAction==='range-'+ui.range;b.classList.toggle('active',active);b.setAttribute('aria-pressed',String(active));
 }
 for(const tr of document.querySelectorAll('[data-peer-row]')){
  const n=row(tr.dataset.peerRow),p=n?.status.peers[0],rate=online&&ui.rates.get(n.id+':'+p?.slot);
  tr.querySelector('[data-overview-rtt]').textContent=online&&p?.connected&&p.rttMs!=null?p.rttMs.toFixed(1)+' ms':'—';
  for(const [key,value] of [['up',p?.sentBytes],['down',p?.receivedBytes]]){
   tr.querySelector('[data-peer-total="'+key+'"]').textContent=total(value||0);
   tr.querySelector('[data-peer-rate="'+key+'"]').textContent=speed(rate&&rate[key]||null);
  }
  const duration=tr.querySelector('[data-network-duration]');
  if(duration&&p?.connection?.elapsedMs!=null){
   duration.dataset.networkDuration=p.connection.elapsedMs;duration.dataset.durationSample=performance.now();
  }
 }
}
function projectionReady(projection,peer){
 return !!(projection?.authorized&&projection.remoteSunshinePort&&projection.companionReady&&peer?.connected&&peer.deviceId);
}
function projectionSettingsFields(){
 const custom=$('projection-resolution').value==='custom';
 $('projection-custom-size').hidden=!custom;
 $('projection-width').disabled=$('projection-height').disabled=!custom;
 queueProjectionBandwidth();
}
$('projection-resolution').addEventListener('change',projectionSettingsFields);
for(const id of ['projection-width','projection-height','projection-fps','projection-bitrate'])
 $(id).addEventListener('input',queueProjectionBandwidth);
function currentProjectionVideo(editor){
 const resolutionMode=$('projection-resolution').value,custom=resolutionMode==='custom';
 return {...editor.previous.video,resolutionMode,
  width:custom?$('projection-width').valueAsNumber:editor.previous.video.width,
  height:custom?$('projection-height').valueAsNumber:editor.previous.video.height,
  fps:$('projection-fps').valueAsNumber,bitratePreset:$('projection-bitrate').value,codec:'auto',scalePercent:100};
}
let bandwidthTimer=0,bandwidthRequest=0;
function queueProjectionBandwidth(){
 clearTimeout(bandwidthTimer);
 const editor=ui.projectionEditor,number=++bandwidthRequest,label=$('projection-bandwidth');
 label.textContent='';
 if(!editor)return;
 const video=currentProjectionVideo(editor);
 if(!Number.isFinite(video.width)||!Number.isFinite(video.height)||!Number.isFinite(video.fps))return;
 const current=()=>ui.projectionEditor===editor&&$('projection-dialog').open&&number===bandwidthRequest;
 bandwidthTimer=setTimeout(async()=>{
  if(!current())return;
  const peer=row(editor.id)?.status.peers[0];
  label.textContent='正在计算带宽需求…';
  try{
   const screenScale=window.devicePixelRatio;
   const display={width:Math.round(screen.width*screenScale),height:Math.round(screen.height*screenScale),refresh_hz:0};
   const reply=await api('/api/projection/bitrate',{networkId:editor.id,deviceId:peer?.deviceId,video,display},current);
   if(!reply.ok)throw Error(reply.error);
   if(current()){
    const size=reply.value.width+'×'+reply.value.height;
    const mbps=(reply.value.kbps/1000).toLocaleString('zh-CN',{maximumFractionDigits:2});
    label.textContent=size+' · 视频约 '+mbps+' Mb/s（本机下载、对机上传）';
   }
  }catch{
   if(current())label.textContent=video.resolutionMode==='peer'?'连接对机后可计算所需带宽':'请检查分辨率与帧率';
  }
 },180);
}
function openProjectionSettings(id){
 const network=row(id),p=network?.status.projection;if(!p)return;
 const video={width:1920,height:1080,fps:60,bitrateMbps:20,codec:'auto',scalePercent:100,resolutionMode:'custom',...p.video};
 ui.projectionEditor={id,wire:network.status.networkId,previous:{allowed:p.authorized,port:p.port,files:!!p.files,fileBrowser:!!p.fileBrowser,clipboard:!!p.clipboard,video}};
 $('projection-network').textContent=network.name;
 $('projection-legacy-port').hidden=!!workspaceState?.projectionBundled;
 $('projection-port').value=p.port;$('projection-allowed').checked=p.authorized;
 $('projection-files').checked=!!p.files&&!!p.fileBrowser;
 $('projection-files').indeterminate=!!p.files&&!p.fileBrowser;
 $('projection-clipboard').checked=!!p.clipboard;
 $('projection-width').value=video.width;$('projection-height').value=video.height;
 $('projection-resolution').value=video.resolutionMode;
 $('projection-fps').value=video.fps;$('projection-bitrate').value=video.bitratePreset||'medium';
 projectionSettingsFields();
 $('projection-error').textContent='';$('projection-dialog').showModal();controls();
}
async function saveProjectionSettings(){
 const editor=ui.projectionEditor;if(!editor)return;
 await dialogAction(async()=>{
  const port=workspaceState?.projectionBundled?editor.previous.port:$('projection-port').valueAsNumber;
  if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Projection 监听端口应为 1024～65535 的整数。');
   const video=currentProjectionVideo(editor),{width,height,fps}=video;
  if(!Number.isInteger(width)||!Number.isInteger(height)||width%2||height%2||width<640||width>7680||height<360||height>4320)throw Error('分辨率宽高须为偶数，支持 640×360 至 7680×4320。');
  if(!Number.isInteger(fps)||fps<15||fps>240)throw Error('帧率须为 15–240 FPS。');
  const filePermission=$('projection-files');
  const projection={port,allowed:$('projection-allowed').checked,files:filePermission.checked||filePermission.indeterminate,
   fileBrowser:filePermission.checked,clipboard:$('projection-clipboard').checked,video};
  await command('network',{networkId:editor.id,network:{action:'projection-settings',expectedNetwork:editor.wire,previous:editor.previous,projection}},true);
  if(ui.projectionEditor===editor){$('projection-dialog').close();ui.projectionEditor=null;notify('Projection 设置已保存');}
 },'projection-dialog','projection-error',()=>ui.projectionEditor===editor,$('projection-width'));
}
function fadeSection(element){
 if(element&&!matchMedia('(prefers-reduced-motion: reduce)').matches)element.animate([{opacity:.72},{opacity:1}],{duration:140});
}
function drawPage(){const pages={overview:overviewPage,create:createPage,join:joinPage,exit:exitPage,requests:requestsPage,settings:liveSettingsPage,coordination:coordinationPage,uu:()=>heading('UU远程','自动使用已直连的 ConWU 网络，无需选择网络。')+uuTakeoverUi.section(workspaceState),logs:logsPage,projection:()=>projectionMode.view(all(),projectionReady)};return pages[page]();}
function pageSignature(){return JSON.stringify([page,ui.joinId,newNetworkName,newNetworkIp,all().map(n=>[n.id,n.name,n.configurationId,n.status.networkId,n.status.networkRevoked,n.status.settingsRevision,n.status.networkEnabled,n.status.directPeers,n.status.pairing,n.status.pairing?.expires*1000>Date.now(),n.status.entryPreparation,n.status.projection,n.status.peers.map(p=>[p.deviceId,p.name,p.virtualIp,p.connected,p.connection?.phase])]),workspaceState?.deviceName,workspaceState?.projectionAvailable,workspaceState?.projectionMoonlight,page==='projection'?[online,projectionMode.phase()]:null,workspaceState?.coordinator?.state,page==='coordination'?[workspaceState?.coordinator?.clients,workspaceState?.coordinator?.punchAssist]:null,ui.coordinationBase]);}
render=function(next){
 const observed=!!next;
 if(next?.workspaceVersion){workspaceState=next;state=next;online=true;lastStatusAt=performance.now();lastStatusFailure='';ui.unavailableMessage='';appendStatusLogs(next);initializeDrafts();if(observed)sampleTraffic(next);}
 if(observed){syncUpdateNotice();updateRequestBadge();if(holdAutomaticPaint()){controls();if(page==='projection')projectionMode.updateCover();return;}}
 ui.pendingPaint=false;
 if(ui.unavailableMessage){notice(ui.unavailableMessage,true,expired?'authorization':'backend');ui.unavailableMessage='';}
 if(workspaceState){if(online&&(noticeSource==='backend'||noticeSource==='pair'&&!workspaceState.networks.some(n=>n.status.pairing?.active))){lastPairError='';notice('');}if(ui.codeId&&!row(ui.codeId))closeInvitation();if(ui.joinId&&(!row(ui.joinId)||row(ui.joinId).status.networkRevoked))ui.joinId='';}
 if(!workspaceState){updateShell();$('content').innerHTML=heading(titles[page],'正在读取本机后台状态。');projectionMode.afterRender();controls();return;}
 const chosen=row(selectedNetwork)?.status;state=chosen?{...workspaceState,...chosen,desktop:workspaceState.desktop}:workspaceState;
 networkActive=!!state.networkId;owner=!!state.isOwner;createdAt=(state.networkEstablishedAt||0)*1000;
 // Preserve the actual scroll container while network status and log rows change.
 const logsMounted=page==='logs'&&ui.renderedPage==='logs'&&$('terminal-content');
 const signature=page==='overview'?overviewSignature():pageSignature();
 const replace=!logsMounted&&(ui.renderedPage!==page||ui.signature!==signature||!observed&&page!=='overview');updateShell();
 if(replace){
  for(const d of $('content').querySelectorAll('details[id]'))ui.disclosures.set((ui.renderedPage||page)+'|'+d.id,d.open);
  const focused=document.activeElement,focusId=$('content').contains(focused)?focused.id:'',start=focused?.selectionStart,end=focused?.selectionEnd;
  const currentPage=ui.renderedPage===page,scroll=document.scrollingElement;
  const scrollTop=currentPage?scroll.scrollTop:0;
  const tableLeft=currentPage?$('content').querySelector('.table-scroll')?.scrollLeft:0;
  $('content').innerHTML=drawPage();ui.signature=signature;ui.renderedPage=page;
  if(currentPage){scroll.scrollTop=scrollTop;const table=$('content').querySelector('.table-scroll');if(table&&tableLeft)table.scrollLeft=tableLeft;}
  for(const d of $('content').querySelectorAll('details[id]'))if(ui.disclosures.has(page+'|'+d.id))d.open=ui.disclosures.get(page+'|'+d.id);
  if(page==='join')bindJoinInput();if(page==='create'&&$('create-form'))$('create-form').onsubmit=e=>{e.preventDefault();void run(create).catch(()=>{});};if(page==='logs')updateLogView();
  if(focusId&&$(focusId)&&!$(focusId).disabled){$(focusId).focus({preventScroll:true});try{$(focusId).setSelectionRange(start,end);}catch{}}
 }else if(page==='logs')updateLogView();else if(page==='overview')updateOverviewTraffic();
 updateInvitationDialog();if(ui.editor&&section==='discovery')refreshPkarrStatus();controls();projectionMode.afterRender();
};
navigate=function(next){const previous=page;page=titles[next]?next:'overview';ui.signature='';render();if(page!==previous)fadeSection($('page-title'));window.scrollTo({top:0,behavior:'instant'});};
updateShell=function(){
 projectionMode.updateBrand();
 document.querySelectorAll('.nav[data-page]').forEach(b=>{const active=b.dataset.page===page;b.classList.toggle('active',active);if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');});
 document.title=titles[page]+' · ConWU';$('sidebar-name').textContent=workspaceState?.deviceName||'正在读取';$('sidebar-initials').textContent=(workspaceState?.deviceName||'CW').slice(0,2).toUpperCase();
 updateRequestBadge();$('request-dot').hidden=true;$('settings-dirty-dot').hidden=!ui.device||same(ui.device,ui.deviceBase);
 $('backend-state').textContent=!online&&installingLocally()?'正在本机更新':expired?'面板授权已过期':!online?'后台状态未更新':state?.serviceReady?'后台运行中':state?.state||'后台尚未就绪';
 $('backend-dot').className='dot'+(online&&!expired&&state?.serviceReady?' good':'');
 $('app-version').textContent=workspaceState?.version?'v'+workspaceState.version.split('+')[0]:'';
};
function updateRequestBadge(){
 const count=all().filter(n=>pendingRequest(n.status.pairing)).length,badge=$('requests-count'),selection=window.getSelection();
 if(badge.textContent!==String(count)&&!(selection&&!selection.isCollapsed&&selection.containsNode(badge,true)))badge.textContent=count;
 badge.hidden=!count;
}
controls=function(){
 const paint=!holdAutomaticPaint(),updateRoot=$('software-update-details');if(paint&&updateRoot&&updateRoot.dataset.updateSignature!==updateSignature())updateRoot.outerHTML=updateDetails();
 const panelReady=online&&!expired&&state?.serviceReady;
 const ready=panelReady&&!busy&&!ui.preparingCommand;
 if(paint)uuTakeoverUi.refresh(workspaceState,ready);
 for(const b of document.querySelectorAll('[data-ui-action]')){
  const action=b.dataset.uiAction;
  if(['close-editor','close-exit','open-editor','select-host','new-create','another-join','help-create','help-join','close-help','close-invitation','close-projection-settings','open-local-service','open-coordination-settings','close-coordination-settings','close-update-source'].includes(action))b.disabled=!!ui.editor?.saving;
  else if(['range-60','range-3600'].includes(action))b.disabled=false;
  else if(action==='projection-moonlight'){
   const player=workspaceState?.projectionMoonlight,status=row(b.dataset.network)?.status;
   b.disabled=!ready||!player?.available||!!projectionMode.sessionId()||!projectionReady(status?.projection,status?.peers?.[0]);
  }
  else if(action==='projection-settings')b.disabled=expired;
  else if(action==='projection-fullscreen')b.disabled=!panelReady||projectionMode.phase()!=='playing';
  else if(action==='projection-moonlight-stop')b.disabled=!ready||projectionMode.phase()!=='playing';
  else if(action==='projection-file-browser'){
   const s=row(b.dataset.network)?.status;
   b.disabled=!panelReady||!s?.peers?.[0]?.connected||!s.projection?.files||!s.projection?.authorized||!s.projection?.companionReady;
  }
  else if(action==='projection-files')b.disabled=!ready||b.dataset.ready!=='true'||!!workspaceState?.projectionTransfer?.active;
  else if(action==='projection-select-device'){
   const active=projectionMode.sessionId();
   b.disabled=!ready||(!!active&&active!==b.dataset.network);
  }
  else b.disabled=!ready;
 }
 for(const b of document.querySelectorAll('[data-ui-action="close-coordination-settings"]'))b.disabled=!!ui.savingCoordination;
 const updateButton=document.querySelector('[data-ui-action="check-update"]');if(updateButton)updateButton.disabled=!ready||workspaceState?.update?.state==='Checking';
 for(const b of document.querySelectorAll('[data-ui-action="download-update"],[data-ui-action="install-update"]'))b.disabled=!ready||workspaceState?.localUpdate?.busy;
 if($('save-device')){
  const changed=!same(ui.device,ui.deviceBase);$('save-device').disabled=!ready||!changed;
  if(paint)$('device-save-state').textContent=ui.savingDevice?'保存中…':changed?'有未保存的更改':'已保存';$('device-save-state').className='save-state'+(changed?' dirty':'');
 }
 if($('save-coordination')){
  const changed=!same(ui.coordination,ui.coordinationBase);
  $('save-coordination').disabled=!ready||!!ui.savingCoordination||!changed;
  $('restore-coordination').disabled=!!ui.savingCoordination||same(ui.coordination,coordinatorValue(true));
  if(paint)$('coordination-save-state').textContent=ui.savingCoordination?'保存中…':changed?'有未保存的更改':'已保存';
  $('coordination-save-state').className='save-state'+(changed?' dirty':'');
 }
 for(const input of document.querySelectorAll('[data-ui-scope="coordination"],[data-ui-scope="coordinationSwitch"]'))input.disabled=!ready||!!ui.savingCoordination;
 for(const b of document.querySelectorAll('[data-ui-action="approve"],[data-ui-action="reject"]')){const p=row(b.dataset.network)?.status.pairing;b.disabled=!ready||!pendingRequest(p)||(b.dataset.uiAction==='approve'&&!/^\d{6}$/.test(p.verification||''));}
 const copy=document.querySelector('[data-ui-action="copy-pair"]');
 if(copy)copy.disabled=!invitationCode();
 for(const b of document.querySelectorAll('[data-ui-action="refresh-pkarr"]'))b.disabled=!ready||!row(b.dataset.network)?.status.networkEnabled||row(b.dataset.network)?.status.settings?.discoveryMode!=='pkarr';
 for(const b of document.querySelectorAll('[data-ui-action="generate"]'))b.disabled=!ready||!row(b.dataset.network)?.status.networkEnabled;
 const restore=document.querySelector('[data-ui-action="default-device"]');if(restore)restore.disabled=!!ui.savingDevice||same(ui.device,defaultDevice());
 if($('join-submit')){
  const n=pendingJoin(),locked=!!(n?.status.networkId||n?.status.pairing?.active&&!n.status.pairing.owner);
  $('join-submit').disabled=!ready||locked;
  $('join-invite').disabled=locked;
  $('join-coordinator').disabled=locked;
 }if($('create-network'))$('create-network').disabled=!ready||!!ui.creating;
 for(const el of document.querySelectorAll('[data-ui-scope="device"],[data-ui-scope="deviceHost"]'))el.disabled=!!ui.savingDevice;
 if(ui.editor){
  const ro=ui.editor.readOnly,changed=editorChanged();
  for(const b of $('network-edit-actions').querySelectorAll('button'))b.disabled=ro||!!ui.editor.saving||(b.dataset.uiAction==='restore-editor'?(same(drafts,editorDefaults())&&(ui.editor.id||ui.editor.ipMode==='auto')):!ready||!changed);
  if(paint)$('network-save-state').textContent=ro?'主机设置 · 仅供查看':ui.editor.saving?'保存中…':changed?'有未保存的更改':'没有未保存的修改';$('network-save-state').className='save-state'+(!ro&&changed?' dirty':'');
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
 if($('stun-count-tcp'))$('stun-count-tcp').textContent=drafts.stun.tcp.split(/\n/).filter(v=>v.trim()).length+' 个地址';
 controls();
};
refreshSettingsTools=function(){controls();};
const oldRenderFields=renderFields;
renderFields=function(){if(ui.editor)renderEditor();else oldRenderFields();};
function editorFields(){
 const d=drafts.network;
 if(section==='network'){
  const protocols=[['faketcp','FakeTCP + HTTP','适合高码率串流，默认使用。'],['phantun','Phantun','使用 TCP 格式承载数据报，保留数据报传输特性；主机需要可达的 TCP 入口。'],['mimic','Mimic（实验）','独立的数据报 TCP 承载；Windows 使用签名的 Microsoft XDP，Linux 使用原始报文。'],['tcpraw','TCPRAW（实验）','系统完成真实 TCP 握手，数据使用原始 TCP 报文交付；不等待外层数据重传。'],['tcp','纯 TCP','使用真实 TCP 通道，适合已有入口或较宽松的 NAT。'],['https','HTTPS','使用 TLS 与 WebSocket 加密承载，首次配对自动绑定设备证书。']];
  if(d.protocol==='udp')protocols.push(['udp','直接 UDP（旧网络）','保留原有协议；两端须使用相同协议。']);
  return `<h3>连接协议</h3><div class="radio-cards">${protocols.map(([v,t,h])=>`<label class="radio-card ${ui.editor?.id&&v!==d.protocol&&(['tcp','https','phantun','mimic','tcpraw'].includes(v)||['tcp','https','phantun','mimic','tcpraw'].includes(d.protocol))?'unavailable':''}"><input type="radio" name="protocol" data-key="protocol" value="${v}" ${d.protocol===v?'checked':''} ${ui.editor?.id&&v!==d.protocol&&(['tcp','https','phantun','mimic','tcpraw'].includes(v)||['tcp','https','phantun','mimic','tcpraw'].includes(d.protocol))?'disabled':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div>${['tcp','https'].includes(d.protocol)?`<div class="stream-flow-setting"><div><strong>按流分离连接</strong><p class="hint">将不同数据流分到独立连接，减少大流量阻塞控制与音频。对端不支持时使用单连接。</p></div>${switchControl('streamFlowLanes',d.streamFlowLanes===true,'按流分离连接')}</div>`:''}<h3>连接策略</h3><div class="radio-cards">${[['custom','自主打洞','由 ConWU 准备入口并尝试穿透。'],['existing','只使用已有入口','公网、端口转发或第三方已打通的入口。']].map(([v,t,h])=>`<label class="radio-card"><input type="radio" name="mode" data-key="mode" value="${v}" ${d.mode===v?'checked':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div><div class="note strategy-note">${icon('info')}<span>${d.mode==='existing'?'仅通过已有入口连接。':'首次使用直连码配对；后续入口更新可在左侧“配对与发现方式”中设置。'}</span></div>`;
 }
 if(section==='discovery'){
  const tips={pkarr:'适用于NAT1 NAT2等宽松网络环境。首次通过直连码配对，之后经由 PKARR 发布和查询最新地址。',server:'适用于NAT3、NAT4等封闭网络环境，利用同样安装了ConWU的协调服务器进行配对。',direct:'适用于NAT1 NAT2等宽松网络环境。通过主机公布的入口配对。入口变化后重新生成直连码。'};
  let fields='';
  if(d.route==='pkarr')fields=`<section class="discovery-settings"><h3>PKARR 发现</h3><label class="field"><span>发现网关（每行一个）</span><textarea data-key="pkarrGateways" spellcheck="false" class="pkarr-endpoints">${esc(d.pkarrGateways)}</textarea></label>${ui.editor.id?`<p class="hint" id="pkarr-live-state">${esc(row(ui.editor.id)?.status.pkarr?.state||'等待发现状态')}</p><div id="pkarr-live-details">${pkarrDetails(row(ui.editor.id)?.status.pkarr)}</div><div class="form-actions"><button class="btn compact" data-ui-action="refresh-pkarr" data-network="${esc(ui.editor.id)}">立即刷新发现信息</button></div>`:''}</section>`;
  if(d.route==='server')fields=`<section class="discovery-settings"><h3>HTTPS 协调服务器</h3><label class="field"><span>协调服务器地址</span><input data-key="url" value="${esc(drafts.coordination.url)}" placeholder="https://coord.example.com/" spellcheck="false"></label><label class="field"><span>证书 SHA-256 指纹（可选）</span><input class="mono" data-key="pin" value="${esc(drafts.certificate.pin)}" placeholder="留空使用系统证书信任" spellcheck="false"></label></section>`;
  return `<h3>配对与发现方式</h3><label class="field"><span>发现方式</span><select data-key="route">${[['server','协调服务器'],['pkarr','PKARR 自动发现'],['direct','仅直连码 · 手动更新入口']].map(([v,t])=>`<option value="${v}" ${d.route===v?'selected':''}>${t}</option>`).join('')}</select></label><div class="note discovery-note">${icon('info')}<span>${tips[d.route]||tips.pkarr}</span></div>${fields}`;
 }
 if(section==='entry')return `<h3>本机已有入口</h3><div class="entry-copy"><p class="hint">填写本机的公网 IP:端口、已打通的地址或 HTTPS/TXT 等订阅链接。${['tcp','https'].includes(d.protocol)?'支持 IPv4／IPv6；IPv6 地址使用 [地址]:端口。':'当前协议使用 IPv4；纯 TCP／HTTPS 也支持 IPv6 入口。'}</p><p class="hint">若填写的不是可更新的订阅链接，入口变化后需要重新填写新入口地址。</p></div><div class="entry-rows">${d.entries.local.map((v,i)=>entryRow(v,i,d.entries.local.length)).join('')}</div><div class="test-row"><button class="btn compact" data-ui-action="test-entry">${icon('refresh')}测试地址</button><span id="test-status" class="hint"></span></div><div id="test-results"></div><label class="field"><span>订阅更新间隔（秒）</span><input data-key="refresh" type="number" min="1" max="86400" value="${d.refresh*Number(d.unit||1)}"></label>`;
 if(section==='virtual'){
  if(ui.editor.id)return `<h3>本机在此网络中的虚拟 IP</h3>${readRows([['当前虚拟 IP',row(ui.editor.id)?.status.virtualIp],['修改方式','网络创建后地址固定；需要更换地址时重新创建网络。']])}`;
  return `<h3>本机在此网络中的虚拟 IP</h3><div class="radio-cards">${[['auto','自动分配','自动选择可用网段，避免与其他网络冲突。'],['custom','自定义地址','指定本机在此网络使用的私有 IPv4 地址。']].map(([v,t,h])=>`<label class="radio-card"><input type="radio" name="virtual-mode" data-key="virtualMode" value="${v}" ${ui.editor.ipMode===v?'checked':''}><strong>${t}</strong><small>${h}</small></label>`).join('')}</div>${ui.editor.ipMode==='custom'?`<label class="field"><span>自定义虚拟 IP</span><input class="mono" id="new-network-ip" value="${esc(newNetworkIp)}" placeholder="10.171.139.1" spellcheck="false"></label>`:''}`;
 }
 if(section==='port')return `<h3>接收端口</h3><label class="field"><span>ConWU 接收端口</span><input type="number" data-key="listen" min="1024" max="65535" value="${drafts.port.listen}"><span class="hint">已有入口应映射到这个端口。</span></label><div class="note">${icon('info')}<span>修改接收端口后，请同步核对公网转发或外部打洞工具的配置。</span></div>`;
 if(section==='stun')return `<h3>打洞 STUN 服务器</h3><div class="stun-columns"><label class="field"><span>TCP STUN<small id="stun-count-tcp">${drafts.stun.tcp.split(/\n/).filter(v=>v.trim()).length} 个地址</small></span><textarea data-key="tcp" spellcheck="false" wrap="off" aria-label="TCP STUN 服务器列表">${esc(drafts.stun.tcp)}</textarea><span class="hint">每行一个地址。使用自建 STUN 时，可清空默认地址并填写自建地址。</span></label></div>`;
 return '';
}
function readOnlyEditor(){
 const n=row(ui.editor.id);if(!n)return '<div class="note">此网络已被移除，可以关闭窗口。</div>';
 const s=n.status,p=s.settings,remote=s.receivedNetworkSettings,route=p.discoveryMode||(p.pkarrPublish?'pkarr':p.directMode?'direct':'coordinator');
 const flow=s.peers[0]?.streamFlows,flowText=flow?.splitActive?'已启用 · '+flow.connections+' 条连接':flow?.negotiated?'已协商 · 当前使用单连接':p.streamFlowLanes===true?'启用（等待对端协商）':'关闭';
 const groups={network:[['连接协议',protocolOf(p)],...(['tcp-only','https-only'].includes(p.pathSelection)?[['按流分离连接',flowText]]:[]),['连接策略',strategyOf(p)],['配置来源',s.peers[0]?.name||'目标主机']],entry:[['目标主机入口／订阅',(p.existingEntries||[]).filter(e=>e.peerSlot!==0).map(e=>e.source).join('\n')||remote?.entries?.map(e=>e.source).join('\n')],['订阅更新间隔',p.entryRefreshSeconds+' 秒']],virtual:[['本机虚拟 IP',s.virtualIp],['对机虚拟 IP',s.peers[0]?.virtualIp]],port:[['主机接收端口',remote?.hostListenPort?String(remote.hostListenPort):'由入口或协调发现'],['本机接收端口',String(p.listenPort)],['本机源端口',String(p.sourcePort)]],stun:[['TCP STUN',(p.tcpStun||[]).join('\n')]],discovery:[['发现方式',route==='pkarr'?'PKARR 自动发现':route==='coordinator'?'协调服务器':'仅直连码'],...(route==='pkarr'?[['发现网关',(p.pkarrGateways||[]).join('\n')],['主机 PKARR 入口',(remote?.entries||[]).filter(e=>e.source.startsWith('pkarr://')).map(e=>e.source).join('\n')]]:route==='coordinator'?[['HTTPS 协调服务器',p.service],['证书 SHA-256 指纹（可选）',p.certificatePin||'使用系统证书信任']]:[['入口更新','入口变化后重新交换直连码']])]};
 const live=section==='discovery'&&route==='pkarr'?`<p class="hint" id="pkarr-live-state" style="margin-top:16px">${esc(s.pkarr?.state||'等待发现状态')}</p><div id="pkarr-live-details">${pkarrDetails(s.pkarr)}</div>`:'';
 return `<div class="note readonly-intro">以下网络设置仅供查看。</div><h3>${editorSections().find(v=>v[0]===section)?.[1]||'网络设置'}</h3>${readRows(groups[section]||[])}${live}`;
}
function pkarrRows(status){return status?.source?[['本机发现地址',status.source],['当前发布入口',(status.endpoints||[]).join('\n')],['最近发布',status.publishedAt?new Date(status.publishedAt*1000).toLocaleString():'尚未成功发布'],['本次接受发布的网关',`${status.acceptedGateways||0} / ${status.totalGateways||0}`],['对端入口确认',status.peerAcknowledged?'对端已确认当前入口':'等待对端确认当前入口'],['最近对端公告',status.peerSeenAt?new Date(status.peerSeenAt*1000).toLocaleString():'尚未收到'],['发布状态说明',status.error||'无发布错误'],['查询状态说明',status.queryError||'无查询错误']]:[];}
function pkarrDetails(status){return status?.source?readRows(pkarrRows(status)):'';}
function refreshPkarrStatus(){if(holdAutomaticPaint())return;const status=row(ui.editor?.id)?.status.pkarr;if($('pkarr-live-state'))$('pkarr-live-state').textContent=status?.state||'创建并启动网络后开始发布';if($('pkarr-live-details'))$('pkarr-live-details').innerHTML=pkarrDetails(status);}
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
 return {...(configuration()?.settings||newConfigurationSettings()),service,certificatePin:drafts.certificate.pin.trim(),pairingService:'',pairingCertificatePin:'',manualEndpoint:'',streamFlowLanes:n.streamFlowLanes===true,pathSelection:({faketcp:'faketcp-only',udp:'udp-only',tcp:'tcp-only',https:'https-only',phantun:'phantun-only',mimic:'mimic-only',tcpraw:'tcpraw-only'})[n.protocol],connectionSource:n.mode,directMode:!active,discoveryMode:n.mode==='existing'?'existing':n.route==='pkarr'?'pkarr':active?'coordinator':'direct',pkarrPublish:n.mode!=='existing'&&n.route==='pkarr',pkarrGateways:lines(n.pkarrGateways),coordinatorBackup:false,existingEntries:Object.entries(n.entries).flatMap(([key,values])=>values.map(v=>v.trim()).filter(Boolean).map(source=>({peerSlot:key==='local'?0:-1,source}))),entryRefreshSeconds:Number(n.refresh)*Number(n.unit),listenPort:Number(drafts.port.listen),sourcePort:configuration()?.settings.sourcePort||44691,requestedVirtualIp:'',tcpStun:lines(drafts.stun.tcp),coordinator:{...defaults.host},ddns:null};
};
validateSection=function(key,configuration=drafts){
 const n=configuration.network;
 if(key==='network'&&!['faketcp','udp','tcp','https','phantun','mimic','tcpraw'].includes(n.protocol))return '请选择有效的传输协议。';
 if(key==='entry'&&n.mode==='existing'){
  const interval=Number(n.refresh)*Number(n.unit);if(!Number.isInteger(interval)||interval<1||interval>86400)return '自动更新间隔应为 1 秒至 24 小时。';
  if(Object.values(n.entries).flat().filter(v=>v.trim()).length>12)return '最多保存 12 项地址来源。';
 }
 if(key==='port'&&(!Number.isInteger(configuration.port.listen)||configuration.port.listen<1024||configuration.port.listen>65535))return '接收端口应为 1024～65535 之间的整数。';
 if(key==='stun'&&n.mode!=='existing'){
  const servers=configuration.stun.tcp.split(/\r?\n/).filter(value=>value.trim());
  if(!servers.length)return '请填写 TCP STUN 服务器地址。';
 }
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
 selectedConfiguration=bound&&!bound.networks.some(v=>(v.networkId??v.id)!==id)?bound.id:'';settingsScope='configuration';configurationRevision=0;settingsHydrated=false;configurationDrafts.delete('new');hydrateEditor();
 if(!selectedConfiguration&&bound){saved=configFromStatus({...workspaceState,settings:bound.settings});drafts=clone(saved);}
 drafts.network.owner='local';saved.network.owner='local';for(const c of [drafts,saved]){c.network.refresh*=Number(c.network.unit||1);c.network.unit=1;}
 if(!selectedConfiguration){configurationName=baseConfigurationName=n?.name||newNetworkName||'网络设置';}
 ui.editor={id,configurationId:selectedConfiguration,readOnly:ro,baseIp:newNetworkIp,baseIpMode:newNetworkIp?'custom':'auto',ipMode:newNetworkIp?'custom':'auto',customIp:newNetworkIp,saving:false};section='network';$('network-dialog').classList.toggle('read-only',ro);$('network-dialog-title').textContent=ro?'主机提供的网络设置 · '+n.name:n?'网络设置 · '+n.name:'新网络设置';$('network-dialog-subtitle').textContent=ro?'由目标主机提供，本机仅供查看。':'每个网络使用独立设置；修改仅对本网络生效。';$('network-edit-actions').hidden=ro;$('network-readonly-close').hidden=!ro;renderEditor();$('network-dialog').showModal();
}
function editorDefaults(){
 const settings=newConfigurationSettings();
 if(ui.editor.id){
  const current=row(ui.editor.id)?.status.settings;
  if(current){settings.pathSelection=current.pathSelection;settings.listenPort=current.listenPort;}
 }
 const value=configFromStatus({...workspaceState,settings});
 value.network.owner='local';value.network.refresh*=Number(value.network.unit||1);value.network.unit=1;
 return value;
}
function editorChanged(){return !!ui.editor&&(!same(saved,drafts)||newNetworkIp!==ui.editor.baseIp||!ui.editor.id&&ui.editor.ipMode!==ui.editor.baseIpMode||configurationName.trim()!==baseConfigurationName);}
async function closeEditor(){if(!ui.editor||ui.editor.saving)return;if(!ui.editor.readOnly){configurationDrafts.delete(selectedConfiguration||'new');newNetworkIp=ui.editor.baseIp;drafts=clone(saved);configurationName=baseConfigurationName;}$('network-dialog').close();ui.editor=null;render();}
function showDialogError(dialogId,errorId,error,focus){
 const dialog=$(dialogId),target=$(errorId);if(!dialog.open||!target)return;
 target.textContent=error.message||String(error);
 if(focus?.isConnected&&dialog.contains(focus)&&!focus.disabled)focus.focus({preventScroll:true});
 target.scrollIntoView({block:'nearest'});
}
async function dialogAction(action,dialogId,errorId,current,focus){
 try{return await action();}catch(error){
  // Only the action's original dialog owns this error. A delayed address test
  // must not report against edited sources or a subsequently opened dialog.
  if(current())showDialogError(dialogId,errorId,error,focus);
  if(expired)throw error; // Session expiration also retains its global notice.
 }
}
const entryTestSource=()=>JSON.stringify([drafts.network.mode,drafts.network.entries.local]);
function editorAction(action,test=false){
 const editor=ui.editor,source=test?entryTestSource():null;if(!editor)return;
 return dialogAction(action,'network-dialog','settings-error',()=>ui.editor===editor&&(!test||section==='entry'&&entryTestSource()===source),editor.focus);
}
function showEditorError(message){showDialogError('network-dialog','settings-error',Error(message),$('settings-fields')?.querySelector(':invalid')||ui.editor?.focus);}
async function saveEditor(){
 if(!ui.editor||ui.editor.readOnly)return;
 if(ui.editor.configurationId!==selectedConfiguration||ui.editor.id&&!row(ui.editor.id))throw Error('当前网络或设置已在其他窗口变更，请关闭后重新打开设置。');
 for(const [key] of editorSections()){const error=validateSection(key);if(error){if(section!==key){section=key;renderEditor();}showEditorError(error);return;}}
 if(!ui.editor.id&&newNetworkIp.trim()){
  const ip=newNetworkIp.trim().split('.').map(Number),valid=ip.length===4&&ip.every(v=>Number.isInteger(v)&&v>=0&&v<=255)&&ip[3]>0&&ip[3]<255&&(ip[0]===10||ip[0]===172&&ip[1]>=16&&ip[1]<=31||ip[0]===192&&ip[1]===168);
  if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(newNetworkIp.trim())||!valid){if(section!=='virtual'){section='virtual';renderEditor();}showEditorError('请填写有效的私有 IPv4，或留空自动分配。');return;}
 }
 const target=row(ui.editor.id),fork=!!configuration()?.networks.some(n=>(n.networkId??n.id)!==ui.editor.id),write=fork||!selectedConfiguration||!same(saved,drafts)||configurationName.trim()!==baseConfigurationName;
 ui.editor.saving=true;
 try{
  const previous=selectedConfiguration||'new';
  if(write){const reply=await command('configuration',{networkId:target?.id||'',configuration:{action:'save',id:fork?'':selectedConfiguration,name:configurationName.trim()||newNetworkName||'网络设置',expectedRevision:fork?0:configurationRevision,settings:settingsDto(),confirmReconnect:true,independent:true}},true);selectedConfiguration=reply.configurationId||selectedConfiguration;if(!selectedConfiguration)throw Error('后台未返回独立设置编号，请保留当前草稿并重试。');ui.editor.configurationId=selectedConfiguration;configurationRevision=configuration()?.revision||1;saved=clone(drafts);baseConfigurationName=configurationName;}
  if(target&&target.configurationId!==selectedConfiguration)await command('configuration',{networkId:target.id,configuration:{action:'assign',id:selectedConfiguration,expectedRevision:configurationRevision,confirmReconnect:true,independent:true}},true);
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
  const settings=c?.settings||newConfigurationSettings();
  if(settings.discoveryMode==='coordinator'&&!settings.service?.trim()){
   openEditor();section='discovery';renderEditor();showEditorError('请先填写协调服务器的 HTTPS 地址。');return;
  }
  if(!c){
   const reply=await command('configuration',{networkId:'',configuration:{action:'save',id:'',name:newNetworkName.trim(),expectedRevision:0,settings:newConfigurationSettings(),confirmReconnect:false,independent:true}});
   ui.newConfig=reply.configurationId||'';try{localStorage.setItem('conwu-create-configuration-draft',ui.newConfig);}catch{}c=workspaceState.configurations.find(c=>c.id===ui.newConfig);
   if(!c)throw Error('后台未返回本次独立设置，请稍后重试。');
  }
  const p=c.settings;if(p.connectionSource==='existing'&&!p.existingEntries.some(e=>e.peerSlot===0))throw Error('请在网络设置中填写本机已有入口。');
  selectedConfiguration=c.id;
  const reply=await command('network',{networkId:'',network:{action:p.directMode?'create-direct':'create',localEnrollment:true,configurationId:c.id,service:p.service,certificatePin:p.certificatePin,mode:({'udp-only':'udp','tcp-only':'tcp','https-only':'https','phantun-only':'phantun','mimic-only':'mimic','tcpraw-only':'tcpraw'})[p.pathSelection]||'faketcp',name:newNetworkName.trim(),requestedVirtualIp:newNetworkIp.trim(),expectedNetwork:''}});
  const createdId=reply.status?.selectedNetworkId||selectedNetwork;ui.newConfig='';newNetworkName='';newNetworkIp='';
  try{localStorage.removeItem('conwu-create-ip-draft');localStorage.removeItem('conwu-create-configuration-draft');}catch{}
  render();openInvitation(createdId);notify('网络已创建，可在弹窗中生成直连码');
 }finally{ui.creating=false;controls();}
}
async function join(){
 const code=compactCodeValue(joinInviteValue);if(!validCompactCode(code))throw Error('请输入完整的 16 位或 36 位直连码。');
 const coordinator=coordinatedCode(code)?ui.joinCoordinator.trim():'';
 const reply=await command('network',{networkId:'',network:{action:'join-compact',autoConfigure:true,code:coordinator?code+'@'+coordinator:code,mode:'faketcp',name:'连接 '+(all().length+1),expectedNetwork:''}});
 ui.joinId=reply.status?.selectedNetworkId||selectedNetwork;render();const p=row(ui.joinId)?.status.pairing;if(p?.error)notice(p.error,true,'pair');else notify('正在联系目标主机');
}
bindJoinInput=function(){
 const input=$('join-invite');if(!input)return;
 const coordinator=$('join-coordinator');
 coordinator.oninput=()=>{ui.joinCoordinator=coordinator.value;joinError='';$('join-error').textContent='';};
 const logicalOffset=offset=>compactCodeValue(input.value.slice(0,offset||0)).length;
 const visibleOffset=offset=>Math.min(input.value.length,input.value.includes('-')?offset+Math.floor(offset/4):offset);
 const updateSlots=()=>{
  const value=compactCodeValue(input.value),start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);
  const groups=document.querySelector('#join-card .direct-groups'),extended=compactLimit(value)===36;
  if(groups&&groups.classList.contains('extended')!==extended)groups.outerHTML=directGroups(value,true);
  document.querySelectorAll('#join-card .direct-digit').forEach((digit,i)=>{
   digit.textContent=value[i]||'X';digit.classList.toggle('filled',!!value[i]);digit.classList.toggle('placeholder',!value[i]);
   digit.classList.toggle('active',document.activeElement===input&&start===end&&i===Math.min(start,compactLimit(value)-1));digit.classList.toggle('selected',document.activeElement===input&&i>=start&&i<end);
  });
 };
 const apply=(value,start,end=start)=>{
  const code=compactCodeValue(value).slice(0,compactLimit(value));
  joinInviteValue=code;input.value=formatCompact(code);input.setSelectionRange(visibleOffset(start),visibleOffset(end));
  $('join-coordinator-field').hidden=!coordinatedCode(code);
  joinError='';$('join-error').textContent='';updateSlots();
 };
 const replaceSelection=text=>{
  const start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd),current=compactCodeValue(input.value),raw=compactCodeValue(text),room=compactLimit(current.slice(0,start)+raw+current.slice(end))-(current.length-(end-start)),insertion=raw.slice(0,Math.max(0,room));
  apply(current.slice(0,start)+insertion+current.slice(end),start+insertion.length);
 };
 input.oninput=()=>apply(input.value,logicalOffset(input.selectionStart),logicalOffset(input.selectionEnd));
 input.onbeforeinput=e=>{
  if(!['deleteContentBackward','deleteContentForward'].includes(e.inputType))return;e.preventDefault();
  let start=logicalOffset(input.selectionStart),end=logicalOffset(input.selectionEnd);if(start===end){if(e.inputType==='deleteContentBackward')start=Math.max(0,start-1);else end=Math.min(compactLimit(input.value),end+1);}
  const value=compactCodeValue(input.value);apply(value.slice(0,start)+value.slice(end),start);
 };
 input.onpaste=e=>{
  e.preventDefault();const text=e.clipboardData.getData('text/plain').trim(),separator=text.indexOf('@');
  const code=separator>=0?compactCodeValue(text.slice(0,separator)):'';
  if(coordinatedCode(code)){
   apply(code,code.length);coordinator.value=ui.joinCoordinator=text.slice(separator+1).trim();
  }else replaceSelection(text);
 };
 input.oncopy=e=>{if(input.selectionStart===input.selectionEnd)return;e.preventDefault();e.clipboardData.setData('text/plain',formatCompact(input.value.slice(input.selectionStart,input.selectionEnd)));};
 input.oncut=e=>{if(input.selectionStart===input.selectionEnd)return;e.preventDefault();e.clipboardData.setData('text/plain',formatCompact(input.value.slice(input.selectionStart,input.selectionEnd)));replaceSelection('');};
 input.onfocus=input.onclick=input.onkeyup=input.onselect=updateSlots;
 input.onblur=()=>document.querySelectorAll('#join-card .direct-digit').forEach(d=>d.classList.remove('active','selected'));
 $('join-form').onsubmit=e=>{e.preventDefault();void run(join).catch(()=>{});};
};
const exitDetails={
 owner:{role:'本机创建',label:'退出',action:'delete-network',done:'网络已删除'},
 member:{role:'本机加入',label:'退出',action:'leave',done:'已退出网络'},
 pending:{role:'未完成的加入申请',label:'移除申请',action:'leave',done:'加入申请已移除'},
 revoked:{role:'授权已撤销',label:'移除记录',action:'remove-network',done:'已移除本机网络记录'},
};
function exitKind(n){return n.status.networkRevoked?'revoked':!n.status.networkId?'pending':n.status.isOwner?'owner':'member';}
function networkActionButton(n,action,label){
 return `<button type="button" id="network-action-${esc(n.id)}" class="text-btn${action==='remove-network'?' danger-text':''}"
  data-ui-action="${action}" data-network="${esc(n.id)}">${label}</button>`;
}
function exitPage(){
 const rows=all();
 return heading('退出网络','退出网络并删除本机在网络中的信息')+`<article class="card network-list-card network-exit-card">
  ${rows.length?rows.map(n=>{
   const {role,label}=exitDetails[exitKind(n)];
   return `<div class="network-entry" data-network-row="${esc(n.id)}">
    <div class="list-row"><strong>${esc(n.name)}</strong><span class="muted">${role}</span>${networkActionButton(n,'remove-network',label)}</div>
   </div>`;
  }).join(''):'<div class="empty"><h2>暂无可退出的网络</h2></div>'}
 </article>`;
}
async function applyNetworkAction(id,action){
 const n=row(id);if(!n)return;
 const kind=exitKind(n),wire=n.status.networkId;
 if(action==='disconnect-network'){
  if(kind==='member'&&n.status.networkEnabled)await command('network',{networkId:id,network:{action:'disconnect',expectedNetwork:wire}});
  return;
 }
 const choice=exitDetails[kind];
 await command('network',{networkId:id,network:{action:choice.action,expectedNetwork:wire,confirmReplace:true}});
 if(ui.codeId===id)closeInvitation();if(ui.joinId===id)ui.joinId='';
 render();notify(choice.done);
}
async function lockedSave(key,action){if(ui[key])return;ui[key]=true;controls();try{return await action();}finally{ui[key]=false;controls();}}
async function saveDevice(){
 const d=ui.device;if(!d.name.trim())throw Error('请输入设备名称。');
 const action={action:'settings',settings:{...deviceSettings(),coordinator:clone(deviceSettings().coordinator)},expectedRevision:workspaceState.deviceSettingsRevision,confirmReplace:true,patch:{deviceName:d.name.trim(),expectedDeviceName:ui.deviceBase.name,logLevel:d.level,expectedLogLevel:ui.deviceBase.level}};
 if(d.startup!==ui.deviceBase.startup){action.autoStart=d.startup;action.expectedAutoStart=ui.deviceBase.startup;}
 await command('save-settings',{networkId:'',settingsBatch:{device:action,networks:[]}});terminalTheme=d.terminal;
 try{localStorage.setItem('streamlink-terminal-theme',terminalTheme);}catch{}
 ui.deviceBase=deviceValue();ui.device=clone(ui.deviceBase);ui.deviceRevision=workspaceState.deviceSettingsRevision;render();notify('本机设置已保存');
}
async function generateFor(id){
 const n=row(id);if(!n)throw Error('此网络已被移除。');const s=n.status;
 if(ui.codeId===id)$('invitation-error').textContent='';
 await command('network',{networkId:id,network:{action:'invite-compact',expectedNetwork:s.networkId,entryFamily:$('invitation-family').hidden?'':$('invitation-family').value}},true);render();notify('直连码已生成');
}
async function testEntry(){const editor=ui.editor,source=entryTestSource(),values=drafts.network.entries.local.filter(v=>v.trim());if(!values.length)throw Error('请先填写本机入口。');await command('network',{networkId:'',network:{action:'resolve-entries',settings:{...settingsDto(),existingEntries:values.map(source=>({peerSlot:0,source}))}}},true);if(ui.editor!==editor||entryTestSource()!==source||!$('test-results'))return;const results=workspaceState.entryResolutions||[];$('test-status').textContent=results.filter(r=>!r.error).length+'/'+results.length+' 个来源解析成功';$('test-results').innerHTML=results.map(r=>`<div class="note" style="margin-bottom:8px">${esc(r.error||r.endpoints.join('、'))}</div>`).join('');}

document.addEventListener('focusin',e=>{
 if(!e.target.matches('input,select,textarea'))return;
 if(ui.editor&&$('network-dialog').contains(e.target))ui.editor.focus=e.target;
 if(ui.coordinationEditor&&$('coordination-dialog').contains(e.target))ui.coordinationEditor.focus=e.target;
});
document.addEventListener('input',e=>{
 const el=e.target,scope=el.dataset.uiScope,key=el.dataset.uiKey;
 if(scope==='coordinationSwitch'){void run(()=>lockedSave('savingCoordination',()=>toggleCoordinator(el.checked))).catch(()=>{});return;}
 if(scope&&key&&ui.device){const target=scope==='coordination'?ui.coordination:ui.device;target[key]=el.type==='checkbox'?el.checked:el.value;if(scope==='coordination')$('coordination-error').textContent='';controls();}
 if(el.id==='new-network-ip'){newNetworkIp=el.value;if(ui.editor)ui.editor.customIp=el.value;if($('settings-error'))$('settings-error').textContent='';controls();}
});
document.addEventListener('click',e=>{
 const b=e.target.closest('[data-ui-action],[data-ui-section]');if(!b||b.disabled)return;e.preventDefault();
 if(b.dataset.uiSection){section=b.dataset.uiSection;renderEditor();fadeSection($('network-settings-body').querySelector('h2,h3'));$('network-settings-body').scrollTop=0;return;}
 void run(async()=>{const id=b.dataset.network;switch(b.dataset.uiAction){
  case 'help-create':openHelp('create');break;case 'help-join':openHelp('join');break;case 'close-help':$('help-dialog').close();break;
  case 'open-editor':openEditor(id||'');break;case 'close-editor':await editorAction(closeEditor);break;case 'save-editor':await editorAction(saveEditor);break;
 case 'projection-settings':openProjectionSettings(id);break;
 case 'close-projection-settings':$('projection-dialog').close();ui.projectionEditor=null;break;
 case 'save-projection-settings':await saveProjectionSettings();break;
 case 'projection-file-browser':projectionFiles.open(id);break;
 case 'projection-open-desktop':await projectionMode.openDesktop();break;
 case 'projection-select-device':await projectionMode.selectDevice(id,projectionReady);break;
 case 'projection-files':{const deviceId=row(id)?.status.peers[0]?.deviceId;if(!deviceId)throw Error('设备已变化，请刷新。');await command('projection-files',{networkId:id,deviceId},true);break;}
 case 'projection-files-cancel':await command('projection-files-cancel',{jobId:b.dataset.job},true);break;
 case 'projection-moonlight':{const peer=row(id)?.status.peers[0];if(!peer?.deviceId)throw Error('设备已变化，请刷新。');await projectionMode.connectMoonlight(id,peer);break;}
 case 'projection-moonlight-stop':await projectionMode.stopMoonlight(id);break;
 case 'projection-fullscreen':await projectionMode.toggleFullscreen();break;
  case 'restore-editor':drafts=editorDefaults();if(!ui.editor.id){newNetworkIp='';ui.editor.ipMode='auto';ui.editor.customIp='';}renderEditor();break;
  case 'new-create':{const abandoned=workspaceState.configurations.find(c=>c.id===ui.newConfig);if(abandoned&&!abandoned.networks.length)await command('configuration',{networkId:'',configuration:{action:'delete',id:abandoned.id,expectedRevision:abandoned.revision}});ui.codeId='';ui.newConfig='';configurationDrafts.delete('new');newNetworkName='';newNetworkIp='';try{localStorage.removeItem('conwu-create-ip-draft');localStorage.removeItem('conwu-create-configuration-draft');}catch{}render();break;}
  case 'select-host':openInvitation(id);break;case 'close-invitation':closeInvitation();break;case 'generate':{const target=id;await dialogAction(()=>generateFor(target),'invitation-dialog','invitation-error',()=>ui.codeId===target,$('invitation-generate'));break;}
  case 'copy-pair':{const code=invitationCode();if(code)await copyText(row(ui.codeId)?.status.pairing?.shareCode||formatCompact(code));break;}
  case 'another-join':ui.joinId='';joinInviteValue='';ui.joinCoordinator='';joinError='';render();break;
  case 'cancel-join':await command('network',{networkId:id,network:{action:'pair-cancel'}});ui.joinId=row(id)?.status.networkId?id:'';render();if(ui.joinId)notify('申请已获批准，可在右侧退出不再需要的网络。');break;
  case 'approve':case 'reject':{const n=row(id),p=n.status.pairing;await command('network',{networkId:id,network:{action:b.dataset.uiAction,verification:p.verification,candidate:p.candidate,proposedIp:p.proposedIp,expectedNetwork:n.status.networkId}});render();break;}
  case 'remove-network':case 'disconnect-network':await applyNetworkAction(id,b.dataset.uiAction);break;
  case 'start-network':await command('start',{networkId:id});break;case 'reconnect-network':{
   const n=row(id);if(!n)break;
   if(exitKind(n)==='member'&&!n.status.networkEnabled)
    await command('network',{networkId:id,network:{action:'reconnect',expectedNetwork:n.status.networkId}});
   break;
  }case 'save-device':await lockedSave('savingDevice',saveDevice);break;
  case 'open-coordination-settings':ui.coordinationBase=coordinatorValue();ui.coordination=clone(ui.coordinationBase);ui.coordinationEditor={};renderCoordinatorEditor();$('coordination-dialog').showModal();break;
  case 'close-coordination-settings':if(!ui.savingCoordination){$('coordination-dialog').close();ui.coordinationEditor=null;}break;
  case 'restore-coordination':ui.coordination=coordinatorValue(true);renderCoordinatorEditor();break;
  case 'save-coordination':{const editor=ui.coordinationEditor;await dialogAction(()=>lockedSave('savingCoordination',saveCoordinator),'coordination-dialog','coordination-error',()=>ui.coordinationEditor===editor,editor?.focus);break;}
  case 'default-device':ui.device=defaultDevice();render();break;
  case 'register-service':await command('register-service',{networkId:''});break;
  case 'check-update':{const reply=await api('/api/command',{method:'update-check',operationId:crypto.randomUUID()});if(!reply.ok)throw Error(reply.error||'暂时无法开始更新检查');if(reply.status)render(reply.status);break;}
   case 'download-update':openUpdateSources();break;case 'download-from-source':await downloadFromSource(b.dataset.source);break;case 'close-update-source':$('update-source-dialog').close();break;case 'install-update':await localUpdate(true);break;case 'dismiss-update':await command('update-dismiss',{localUpdate:{receiptId:b.dataset.receipt}});break;
  case 'refresh-pkarr':await command('network',{networkId:id,network:{action:'refresh-pkarr',expectedNetwork:row(id).status.networkId}});notify('已请求刷新发现信息');break;
  case 'range-60':ui.range=60;render();break;case 'range-3600':ui.range=3600;render();break;case 'test-entry':await editorAction(testEntry,true);break;
 }}).catch(()=>{});
});
$('network-dialog').addEventListener('cancel',e=>{e.preventDefault();void run(()=>editorAction(closeEditor)).catch(()=>{});});
$('invitation-dialog').addEventListener('cancel',e=>{e.preventDefault();closeInvitation();});
$('coordination-dialog').addEventListener('cancel',e=>{if(ui.savingCoordination)e.preventDefault();else ui.coordinationEditor=null;});
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
   reply=await api('/api/status?operation='+encodeURIComponent(probe.id)+'&networkId='+encodeURIComponent(probe.target),undefined,()=>!probe.cancelled&&generation===probe.version);
  }
  if(probe.cancelled||generation!==probe.version)return;
  if(reply.status&&!busy)render(reply.status);
  if(!reply.ok||reply.operation?.error)throw Error(reply.error||reply.operation.error);
  if(noticeSource==='pair')notice('');lastPairError='';
 }catch(error){if(!probe.cancelled&&generation===probe.version){lastPairPoll=Date.now()+8000;if(error.message!==lastPairError){lastPairError=error.message;notice(n.name+'：'+error.message,true,'pair');}}}
 finally{if(ui.pairProbe===probe)ui.pairProbe=null;}
};
openSettings=function(next='network'){if(['network','discovery','entry','virtual','port','stun'].includes(next)&&page==='create')openEditor();else navigate('settings');};
dirtyCount=()=>((ui.editor&&!ui.editor.readOnly&&editorChanged()?1:0)+(ui.device&&!same(ui.device,ui.deviceBase)?1:0));
try{newNetworkIp=localStorage.getItem('conwu-create-ip-draft')||'';ui.newConfig=localStorage.getItem('conwu-create-configuration-draft')||'';}catch{}
boot();
})();
