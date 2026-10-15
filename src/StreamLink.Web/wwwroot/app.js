'use strict';
const $ = id => document.getElementById(id);
let csrf = '', state = null, busy = false, connectionDirty = false, metadataDirty = false, connectionBase = null, metadataBase = null, lastTraffic = null, cooldownUntil = 0;
const titles = {overview:'网络总览',devices:'设备与链路',network:'创建与加入',settings:'连接策略',diagnostics:'诊断与设置'};
function notice(text, error=false) { $('notice').textContent=text; $('notice').hidden=!text; $('notice').classList.toggle('error',error); }
function show(page) {document.querySelectorAll('.page').forEach(e=>e.hidden=e.id!==page); document.querySelectorAll('.nav').forEach(e=>{e.classList.toggle('active',e.dataset.page===page);e.setAttribute('aria-current',e.dataset.page===page?'page':'false');});$('page-title').textContent=titles[page];}
async function api(path, body) {
 const response=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json','X-StreamLink-CSRF':csrf}:{},body:body?JSON.stringify(body):undefined});
 if(!response.ok){if(response.status===401)throw Error('面板会话已过期，请双击托盘图标重新打开。');if(response.status===409)throw Error('重复请求已拒绝，或会话额度已满；请刷新状态，必要时从托盘重新打开。');let message;try{message=(await response.json()).error;}catch{}throw Error(message||`本机面板请求未完成（${response.status}）`);}
 return response.json();
}
async function command(method, extra={}, quiet=false) {
 if(busy)throw Error('上一项操作仍在进行，请稍候。');busy=true;document.body.setAttribute('aria-busy','true');
 try{const reply=await api('/api/command',{method,operationId:crypto.randomUUID(),...extra});if(reply.status)render(reply.status);if(!reply.ok)throw Error(reply.error);if(!quiet)notice('操作已提交，实际结果见连接状态。');return reply;}
 finally{busy=false;document.body.removeAttribute('aria-busy');}
}
async function network(action,fields={},quiet=false){return command('network',{network:{action,...fields}},quiet);}
function safe(fn){return async e=>{try{await fn(e);}catch(ex){notice(ex.message,true);}};}
async function refresh(){const reply=await api('/api/status');if(!reply.ok)throw Error(reply.error);render(reply.status);}
function text(tag,value,cls=''){const n=document.createElement(tag);n.textContent=value;if(cls)n.className=cls;return n;}
function copy(value){if(!value)throw Error('暂无可复制的地址');return navigator.clipboard.writeText(value).then(()=>notice('地址已复制'));}
function render(s){
 if(!s)return;state=s;$('backend-state').textContent=s.serviceReady?'个人后台已就绪':'后台正在准备';$('network-state').textContent=s.state||'尚未连接';$('local-ip').textContent=s.virtualIp||'—';$('peer-count').textContent=`${s.directPeers} / ${s.totalPeers}`;
 $('state-detail').textContent=s.networkId?'网络成员分别建立直连；设备页显示实际承载与失败原因。':'尚未加入网络，请先创建或输入另一台电脑的配对码。';
 $('adapter').textContent=s.adapter?.state==='Opened'?'Wintun 已打开':s.adapter?.state||'未打开';$('migration').textContent=s.migrationNotice;$('migration').hidden=!s.migrationNotice;
 $('quality-text').textContent=s.qualityText||'质量尚未测量';$('logs').textContent=(s.logs||[]).join('\n')||'暂无日志';$('version').textContent=`版本 ${s.version} · 官方 Wintun / WinDivert · 未签名个人候选`;
 $('operation').textContent=s.operation?`${s.operation.command}：${s.operation.phase}${s.operation.error?' · '+s.operation.error:''}`:'当前没有控制任务';
 const peers=s.peers||[], sent=peers.reduce((a,p)=>a+p.sentBytes,0),received=peers.reduce((a,p)=>a+p.receivedBytes,0),now=performance.now();
 if(lastTraffic&&now-lastTraffic.at>500&&sent>=lastTraffic.sent&&received>=lastTraffic.received)$('rates').textContent=`${((sent-lastTraffic.sent)*8/(now-lastTraffic.at)/1000).toFixed(2)} / ${((received-lastTraffic.received)*8/(now-lastTraffic.at)/1000).toFixed(2)}`;
 lastTraffic={sent,received,at:now};
 const list=$('peer-list');list.replaceChildren();if(!peers.length)list.append(text('p','尚无成员链路。完成配对并启动网络后显示。','empty'));
 for(const p of peers){const row=text('div','','peer'),info=text('div',''),actions=text('div','','actions');info.append(text('h3',p.name||`设备 ${p.slot}`),text('p',`${p.virtualIp} · ${p.connected?'已直连':'未直连'} · ${p.rttMs==null?'RTT 未知':p.rttMs.toFixed(1)+' ms'}`),text('p',`承载 ${p.actualTransport} · 建链 ${p.traversalMethod}`),text('p',p.phase),text('p',`质量评估：${p.quality==='Unknown'?'未测量':p.quality} · 本地丢弃 ${p.droppedPackets}`));const c=text('button','复制 IP');c.onclick=safe(()=>copy(p.virtualIp));actions.append(c);if(s.isOwner){const remove=text('button','移除');remove.onclick=safe(async()=>{if(confirm(`移除 ${p.name||p.virtualIp} 的网络授权？`))await network('revoke',{expectedNetwork:s.networkId,peerSlot:p.slot});});actions.append(remove);}row.append(info,actions);list.append(row);}
 const select=$('quality-peer'),old=select.value;select.replaceChildren();for(const p of peers.filter(p=>p.connected)){const opt=text('option',`${p.name||'设备'} · ${p.virtualIp}`);opt.value=p.slot;select.append(opt);}if([...select.options].some(o=>o.value===old))select.value=old;
 $('quality').disabled=!select.options.length||Date.now()<cooldownUntil;
 $('quality').textContent=Date.now()<cooldownUntil?'冷却 '+Math.ceil((cooldownUntil-Date.now())/1000)+' 秒':'50 Mbps / 20 秒';
 if(!connectionDirty&&s.settings){connectionBase={...s.settings,revision:s.settingsRevision};$('policy').value=s.settings.pathSelection;$('endpoint').value=s.settings.manualEndpoint;$('listen-port').value=s.settings.listenPort;$('source-port').value=s.settings.sourcePort;$('allow-quality').checked=s.settings.allowManualQualityRequests;}
 if(!metadataDirty){metadataBase={name:s.deviceName,level:s.logLevel};$('device-name').value=s.deviceName;$('log-level').value=s.logLevel;}
 if(!$('server').value&&s.settings?.service)$('server').value=s.settings.service;
 const pair=s.pairing;$('room-code').textContent=pair?.code||'— — — — — —';$('verification').textContent=pair?.verification||'等待申请';$('pair-state').textContent=pair?.state||'尚未发起配对';$('pair-peer').textContent=pair?.peerName?`对方设备：${pair.peerName}`:'';$('approve').disabled=!(pair?.active&&pair.owner&&pair.verification);$('invite').disabled=!s.isOwner;
}
document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>show(b.dataset.page));
document.querySelectorAll('[data-command]').forEach(b=>b.onclick=safe(()=>command(b.dataset.command)));
$('refresh').onclick=safe(refresh);$('copy-local').onclick=safe(()=>copy(state?.virtualIp));
$('pair-form').onsubmit=safe(async e=>{e.preventDefault();const action=e.submitter.value,existing=!!state?.networkId;let service=$('server').value.trim();if(!service.endsWith('/'))service+='/';const url=new URL(service);if(url.protocol!=='https:'||url.username||url.password)throw Error('请填写 HTTPS 协调地址');if(action==='join'&&!/^\d{6}$/.test($('pair-code').value))throw Error('请输入 6 位配对码');if(existing&&!confirm('这会替换当前网络。仅添加设备请使用“邀请下一台”。继续？'))return;await network(action,{service,certificatePin:$('pin').value.trim(),code:action==='join'?$('pair-code').value:'',mode:$('mode').value,expectedNetwork:state?.networkId||'',confirmReplace:existing});$('pair-code').value='';});
$('approve').onclick=safe(async()=>{const p=state?.pairing;if(!p?.verification)throw Error('暂无待核对的校验码');await network('approve',{verification:p.verification,candidate:p.candidate});});
$('invite').onclick=safe(()=>network('invite',{expectedNetwork:state?.networkId||''}));$('pair-cancel').onclick=safe(()=>network('pair-cancel'));
$('connection-form').oninput=()=>{connectionDirty=true;$('connection-dirty').textContent='有未保存的草稿';};
$('reset-connection').onclick=()=>{connectionDirty=false;$('connection-dirty').textContent='';render(state);};
$('connection-form').onsubmit=safe(async e=>{e.preventDefault();if(!connectionBase)throw Error('后台状态尚未就绪');const settings={...connectionBase,pathSelection:$('policy').value,manualEndpoint:$('endpoint').value.trim(),listenPort:Number($('listen-port').value),sourcePort:Number($('source-port').value),allowManualQualityRequests:$('allow-quality').checked};delete settings.revision;const restart=settings.pathSelection!==connectionBase.pathSelection||settings.manualEndpoint!==connectionBase.manualEndpoint||settings.listenPort!==connectionBase.listenPort||settings.sourcePort!==connectionBase.sourcePort;if(restart&&state.networkEnabled&&!confirm('这些连接设置会重建个人网络，是否继续？'))return;await network('settings',{settings,expectedRevision:connectionBase.revision,confirmReplace:restart});connectionDirty=false;$('connection-dirty').textContent='';render(state);notice('设置已保存。');});
$('metadata-form').oninput=()=>metadataDirty=true;$('reset-metadata').onclick=()=>{metadataDirty=false;render(state);};
$('metadata-form').onsubmit=safe(async e=>{e.preventDefault();if(!metadataBase)throw Error('后台状态尚未就绪');const patch={};if($('device-name').value!==metadataBase.name){patch.deviceName=$('device-name').value;patch.expectedDeviceName=metadataBase.name;}if($('log-level').value!==metadataBase.level){patch.logLevel=$('log-level').value;patch.expectedLogLevel=metadataBase.level;}if(!Object.keys(patch).length)return;await command('patch',{patch});metadataDirty=false;render(state);notice('设备设置已保存，当前连接保持运行。');});
$('quality').onclick=safe(async()=>{if(!$('quality-peer').value)throw Error('请先连接对端');await command('quality',{peerSlot:Number($('quality-peer').value),mbps:50});cooldownUntil=Date.now()+110000;$('quality').disabled=true;});
$('cancel-operation').onclick=safe(async()=>{if(!state?.operation?.cancelable)throw Error('没有可取消任务；资源退出阶段需要等待实际完成。');await command('cancel',{cancelOperationId:state.operation.id});});
$('export').onclick=safe(()=>{if(!state)throw Error('暂无状态');const clean={...state,pairing:undefined,exportedAt:new Date().toISOString(),physicalRouteEvidence:'NotCollected',userStreamingTrial:'PendingUserTrial'};const link=document.createElement('a');link.href=URL.createObjectURL(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}));link.download='StreamLink-diagnostics.json';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);});
$('theme').onclick=()=>{const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;localStorage.setItem('streamlink-theme',theme);};
async function boot(){try{document.documentElement.dataset.theme=localStorage.getItem('streamlink-theme')||'dark';const ticket=location.hash.slice(1);history.replaceState(null,'',location.pathname);const session=ticket?await api('/api/session',{ticket}):await api('/api/session');csrf=session.csrf;await refresh();notice('');}catch(ex){notice(ex.message,true);}}
boot();setInterval(async()=>{if(busy||!csrf)return;try{if(state?.pairing?.active)await network('pair-poll',{},true);else await refresh();}catch(ex){notice(ex.message,true);}},2500);
