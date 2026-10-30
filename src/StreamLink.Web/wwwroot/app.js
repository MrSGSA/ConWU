'use strict';
const $ = id => document.getElementById(id);
const titles = {overview:'连接', network:'添加设备', settings:'设置'};
let csrf='', state=null, busy=false, online=false, expired=false, refreshing=null;
let connectionDirty=false, metadataDirty=false, connectionBase=null, metadataBase=null;
let lastTraffic=null, cooldownUntil=0, lastStatusAt=0;
const rows=new Map();
const phaseNames={StartingAdapter:'准备网络',WaitingPeer:'等待设备',WaitingEntry:'寻找入口',Connecting:'正在连接',Preparing:'准备直连',Verifying:'验证直连',Recovering:'恢复连接',Retrying:'等待重试',Connected:'已直连'};

function notice(message,error=false) {
  $('notice').textContent=message; $('notice').hidden=!message;
  $('notice').classList.toggle('error',error);
}
function show(page) {
  notice('');
  document.querySelectorAll('.page').forEach(e=>e.hidden=e.id!==page);
  document.querySelectorAll('.nav').forEach(e=>{
    e.classList.toggle('active',e.dataset.page===page);
    if(e.dataset.page===page)e.setAttribute('aria-current','page');else e.removeAttribute('aria-current');
  });
  $('page-title').textContent=titles[page];
}
function unavailable(message) {
  online=false; lastTraffic=null;
  $('backend-state').textContent=expired?'面板授权已过期':'后台状态未更新';
  $('network-state').textContent=expired?'请重新打开面板':'面板暂未连接后台';
  $('state-detail').textContent=message;
  $('connection-card').dataset.state='stale';
  $('connection-progress').textContent='当前无法确认网络状态；后台中的串流不受面板刷新影响。';
  $('connection-steps').hidden=true; $('rates').textContent='流量未知';
  for(const row of rows.values()){row.badge.textContent='状态未更新';row.badge.classList.remove('online');row.progress.textContent='请等待后台状态恢复';}
  controls();
}
async function api(path,body) {
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),body?25000:8000);
  try {
    const response=await fetch(path,{
      method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal,
      headers:body?{'Content-Type':'application/json','X-StreamLink-CSRF':csrf}:{},
      body:body?JSON.stringify(body):undefined
    });
    if(!response.ok) {
      let detail;try{detail=await response.json();}catch{}
      if(response.status===401) {
        expired=true;csrf='';
        const message='面板授权已过期，请从托盘重新打开 WebUI。后台网络继续运行。';
        unavailable(message);throw Error(message);
      }
      if(response.status===503) {
        const message=detail?.error||'本机后台暂未响应，请稍候重试或检查 StreamLink 服务。';
        unavailable(message);throw Error(message);
      }
      if(response.status===409)throw Error('重复请求已拒绝或面板操作额度已满。请刷新状态，必要时从托盘重新打开。');
      throw Error(detail?.error||'本机面板请求未完成（'+response.status+'）');
    }
    return await response.json();
  } catch(error) {
    if(error.name==='AbortError'||error instanceof TypeError) {
      const message=body?'请求超时或面板连接中断，操作结果尚待确认。请刷新状态后再操作。':'读取后台超时或面板连接中断，将自动重试。';
      unavailable(message);throw Error(message);
    }
    throw error;
  } finally {clearTimeout(timeout);}
}
async function command(method,extra={},quiet=false) {
  if(busy)throw Error('上一项操作仍在进行，请稍候。');
  if(!online)throw Error('请先恢复面板与后台的连接。');
  busy=true;document.body.setAttribute('aria-busy','true');controls();
  try {
    const reply=await api('/api/command',{method,operationId:crypto.randomUUID(),...extra});
    if(reply.status)render(reply.status);
    if(!reply.ok)throw Error(reply.error);
    if(!quiet)notice(method==='retry'?'已请求重新探测，健康连接保持运行。':'操作已提交，请查看连接状态。');
    return reply;
  } finally {busy=false;document.body.removeAttribute('aria-busy');controls();}
}
const network=(action,fields={},quiet=false)=>command('network',{network:{action,...fields}},quiet);
function safe(fn){return async e=>{try{await fn(e);}catch(error){notice(error.message,true);}};}
function refresh() {
  if(refreshing)return refreshing;
  refreshing=(async()=>{
    const reply=await api('/api/status');
    if(!reply.ok)throw Error(reply.error);
    const wasOffline=!online;render(reply.status);
    if(wasOffline)notice('');
  })().finally(()=>refreshing=null);
  return refreshing;
}
function text(tag,value,cls='') {
  const node=document.createElement(tag);node.textContent=value;if(cls)node.className=cls;return node;
}
function copy(value) {
  if(!value)throw Error('暂无可复制的地址');
  return navigator.clipboard.writeText(value).then(()=>notice('地址已复制'));
}
function controls() {
  document.querySelectorAll('[data-backend]').forEach(e=>e.disabled=!online||busy);
  const s=state,p=s?.pairing;
  $('approve').disabled=!online||busy||!(p?.active&&p.owner&&p.verification);
  $('invite').disabled=!online||busy||!s?.isOwner;
  $('pair-cancel').disabled=!online||busy||!p?.active;
  $('quality').disabled=!online||busy||!$('quality-peer').options.length||Date.now()<cooldownUntil;
  $('cancel-operation').disabled=!online||busy||!s?.operation?.cancelable;
  for(const row of rows.values())row.remove.disabled=!online||busy;
}
function duration(ms) {
  const seconds=Math.max(0,Math.floor(ms/1000));
  return seconds<60?seconds+' 秒':Math.floor(seconds/60)+' 分 '+seconds%60+' 秒';
}
function progressText(progress,extraMs=0) {
  if(!progress)return '';
  const parts=[phaseNames[progress.phase]||'正在处理'];
  parts.push((progress.phase==='Connected'?'持续 ':'已等待 ')+duration(progress.elapsedMs+extraMs));
  if(progress.attempt>0&&progress.phase!=='Connected')parts.push('第 '+progress.attempt+' 次尝试');
  if(progress.retryInSeconds!=null)parts.push(Math.max(0,progress.retryInSeconds-Math.floor(extraMs/1000))+' 秒后重试');
  else if(progress.remainingSeconds!=null&&progress.phase!=='Connected')parts.push('本轮剩余 '+Math.max(0,progress.remainingSeconds-Math.floor(extraMs/1000))+' 秒');
  return parts.join(' · ');
}
function tick() {
  if(!online)return;
  const age=performance.now()-lastStatusAt;
  if(age>10000){unavailable('超过 10 秒未收到后台状态，正在重新读取。当前连接情况尚待确认。');return;}
  $('connection-progress').textContent=state?.networkEnabled?progressText(state.connection,age):'';
  for(const p of state?.peers||[]) {
    const row=rows.get(p.slot);
    if(row)row.timing.textContent=progressText(p.connection,age);
  }
  $('quality').textContent=Date.now()<cooldownUntil?'冷却 '+Math.ceil((cooldownUntil-Date.now())/1000)+' 秒':'50 Mbps / 20 秒';
  controls();
}
function makePeer(slot) {
  const root=text('article','','peer'),main=text('div','','peer-main'),info=text('div','');
  const title=text('div','','peer-title'),name=text('h3','','peer-name'),badge=text('span','','badge'),address=text('p','','peer-address');
  title.append(name,badge);info.append(title,address);
  const actions=text('div','','actions'),copyButton=text('button','复制 IP','quiet'),remove=text('button','移除','quiet');
  copyButton.onclick=safe(()=>copy(state?.peers.find(p=>p.slot===slot)?.virtualIp));
  remove.onclick=safe(async()=>{
    const p=state?.peers.find(p=>p.slot===slot);
    if(p&&confirm('移除 '+(p.name||p.virtualIp)+' 的网络授权？'))await network('revoke',{expectedNetwork:state.networkId,peerSlot:slot});
  });
  actions.append(copyButton,remove);main.append(info,actions);
  const progress=text('p','','peer-progress'),timing=text('p','','peer-progress'),details=text('details',''),summary=text('summary','链路详情');
  const transport=text('p',''),quality=text('p',''),liveness=text('p','');
  details.append(summary,transport,quality,liveness);root.append(main,progress,timing,details);
  return {root,name,badge,address,remove,progress,timing,transport,quality,liveness};
}
function renderPeers(peers,s) {
  const list=$('peer-list'),slots=new Set(peers.map(p=>p.slot));
  for(const [slot,row] of rows)if(!slots.has(slot)){row.root.remove();rows.delete(slot);}
  list.querySelector('.empty')?.remove();
  if(!peers.length)list.append(text('p',s.networkId?'等待其他成员上线。可在“添加设备”中邀请电脑。':'添加另一台电脑后，在这里查看连接与复制 IP。','empty'));
  for(const p of peers) {
    let row=rows.get(p.slot);
    if(!row){row=makePeer(p.slot);rows.set(p.slot,row);list.append(row.root);}
    row.name.textContent=p.name||'设备 '+p.slot;
    row.badge.textContent=p.connected?'已直连':phaseNames[p.connection?.phase]||'未连接';
    row.badge.classList.toggle('online',p.connected);
    row.address.textContent=p.virtualIp+(p.connected&&p.rttMs!=null?' · '+p.rttMs.toFixed(1)+' ms':'');
    row.progress.textContent=p.connected?'':p.connection?.detail||p.phase;
    row.progress.hidden=p.connected;
    row.transport.textContent='承载 '+p.actualTransport+' · 建链 '+p.traversalMethod;
    row.quality.textContent='质量 '+(p.quality==='Unknown'?'未测量':p.quality)+' · 本机丢弃 '+p.droppedPackets+' 包';
    row.liveness.textContent=p.liveness?'最近有效接收 '+(p.liveness.receiveAgeMs==null?'未知':duration(p.liveness.receiveAgeMs))+'前 · 最近往返 '+(p.liveness.roundTripAgeMs==null?'未知':duration(p.liveness.roundTripAgeMs))+'前':'';
    row.remove.hidden=!s.isOwner;
  }
}
function render(s) {
  if(!s)return;
  state=s;online=true;expired=false;lastStatusAt=performance.now();
  $('backend-state').textContent=s.serviceReady?'后台已就绪':'后台正在准备';
  $('network-state').textContent=s.state||'尚未连接';
  $('connection-card').dataset.state=s.directPeers>0?'connected':s.networkEnabled?'waiting':'stopped';
  $('local-ip').textContent=s.virtualIp||'—';$('device-label').textContent=s.deviceName||'本机';
  $('peer-count').textContent=s.directPeers+' / '+s.totalPeers;
  $('state-detail').textContent=!s.networkId?'先添加另一台电脑，创建或加入同一网络。':!s.networkEnabled?'网络已停止，配对与设置已保留。':s.connection?.detail||'正在读取连接进度。';
  $('connect').hidden=!!s.networkEnabled||!s.networkId;
  $('disconnect').hidden=!s.networkEnabled;
  $('retry').hidden=!s.networkEnabled||!s.connection?.canRetry;
  $('setup').hidden=!!s.networkId;
  $('copy-local').disabled=!s.virtualIp;
  $('connection-steps').hidden=!s.networkEnabled;
  const phase=s.connection?.phase;
  const step=phase==='StartingAdapter'?0:phase==='WaitingPeer'?1:2;
  document.querySelectorAll('[data-step]').forEach(e=>{
    const n=Number(e.dataset.step),done=s.directPeers>0&&s.directPeers===s.totalPeers;
    e.classList.toggle('done',done||n<step);e.classList.toggle('current',!done&&n===step);
    if(!done&&n===step)e.setAttribute('aria-current','step');else e.removeAttribute('aria-current');
  });
  $('adapter').textContent='虚拟网卡：'+(s.adapter?.state==='Opened'?'Wintun 已打开':s.adapter?.reason||'未打开');
  $('migration').textContent=s.migrationNotice;$('migration').hidden=!s.migrationNotice;
  $('quality-text').textContent=s.qualityText||'质量尚未测量';$('logs').textContent=(s.logs||[]).join('\n')||'暂无日志';
  $('version').textContent='StreamLink '+s.version.split('+')[0];
  $('status-time').textContent='状态更新 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});
  $('operation').textContent=s.operation?(s.operation.completed?'上次操作：':'当前操作：')+s.operation.phase+(s.operation.error?' · '+s.operation.error:''):'当前没有控制任务';
  const peers=s.peers||[],sent=peers.reduce((a,p)=>a+p.sentBytes,0),received=peers.reduce((a,p)=>a+p.receivedBytes,0),now=performance.now();
  if(lastTraffic&&now-lastTraffic.at>500&&sent>=lastTraffic.sent&&received>=lastTraffic.received)
    $('rates').textContent='↑ '+((sent-lastTraffic.sent)*8/(now-lastTraffic.at)/1000).toFixed(2)+'  ↓ '+((received-lastTraffic.received)*8/(now-lastTraffic.at)/1000).toFixed(2)+' Mbps';
  else if(!lastTraffic||sent<lastTraffic.sent||received<lastTraffic.received)$('rates').textContent='等待流量采样';
  lastTraffic={sent,received,at:now};renderPeers(peers,s);
  const select=$('quality-peer'),eligible=peers.filter(p=>p.connected),old=select.value;
  if(JSON.stringify([...select.options].map(o=>[o.value,o.textContent]))!==JSON.stringify(eligible.map(p=>[String(p.slot),(p.name||'设备')+' · '+p.virtualIp]))) {
    select.replaceChildren();
    for(const p of eligible){const option=text('option',(p.name||'设备')+' · '+p.virtualIp);option.value=p.slot;select.append(option);}
    if([...select.options].some(o=>o.value===old))select.value=old;
  }
  if(!connectionDirty&&s.settings) {
    connectionBase={...s.settings,revision:s.settingsRevision};
    $('policy').value=s.settings.pathSelection;$('endpoint').value=s.settings.manualEndpoint;
    $('listen-port').value=s.settings.listenPort;$('source-port').value=s.settings.sourcePort;
    $('allow-quality').checked=s.settings.allowManualQualityRequests;
  }
  if(!metadataDirty){metadataBase={name:s.deviceName,level:s.logLevel};$('device-name').value=s.deviceName;$('log-level').value=s.logLevel;}
  if(!$('server').value&&s.settings?.service)$('server').value=s.settings.service;
  const pair=s.pairing;
  $('room-code').textContent=pair?.code||'— — — — — —';$('verification').textContent=pair?.verification||'等待申请';
  $('pair-state').textContent=pair?.state||'尚未发起配对';
  $('pair-peer').textContent=pair?.peerName?'对方设备：'+pair.peerName:'';
  tick();
}
document.querySelectorAll('[data-page]').forEach(b=>b.onclick=()=>show(b.dataset.page));
document.querySelectorAll('[data-open]').forEach(b=>b.onclick=()=>show(b.dataset.open));
document.querySelectorAll('[data-command]').forEach(b=>b.onclick=safe(()=>command(b.dataset.command)));
$('refresh').onclick=safe(refresh);$('copy-local').onclick=safe(()=>copy(state?.virtualIp));
$('pair-form').onsubmit=safe(async e=>{
  e.preventDefault();const action=e.submitter.value,existing=!!state?.networkId;
  let service=$('server').value.trim();if(!service.endsWith('/'))service+='/';
  const url=new URL(service);
  if(url.protocol!=='https:'||url.username||url.password)throw Error('请填写 HTTPS 协调地址');
  if(action==='join'&&!/^\d{6}$/.test($('pair-code').value))throw Error('请输入 6 位配对码');
  if(existing&&!confirm('这会替换当前网络。仅添加设备请使用“邀请下一台”。继续？'))return;
  await network(action,{service,certificatePin:$('pin').value.trim(),code:action==='join'?$('pair-code').value:'',mode:$('mode').value,expectedNetwork:state?.networkId||'',confirmReplace:existing});
  $('pair-code').value='';
});
$('approve').onclick=safe(async()=>{
  const p=state?.pairing;if(!p?.verification)throw Error('暂无待核对的校验码');
  await network('approve',{verification:p.verification,candidate:p.candidate});
});
$('invite').onclick=safe(()=>network('invite',{expectedNetwork:state?.networkId||''}));
$('pair-cancel').onclick=safe(()=>network('pair-cancel'));
$('connection-form').oninput=()=>{connectionDirty=true;$('connection-dirty').textContent='有未保存的草稿';};
$('reset-connection').onclick=()=>{connectionDirty=false;$('connection-dirty').textContent='';if(online)render(state);};
$('connection-form').onsubmit=safe(async e=>{
  e.preventDefault();if(!connectionBase)throw Error('后台状态尚未就绪');
  const settings={...connectionBase,pathSelection:$('policy').value,manualEndpoint:$('endpoint').value.trim(),listenPort:Number($('listen-port').value),sourcePort:Number($('source-port').value),allowManualQualityRequests:$('allow-quality').checked};
  delete settings.revision;
  const restart=settings.pathSelection!==connectionBase.pathSelection||settings.manualEndpoint!==connectionBase.manualEndpoint||settings.listenPort!==connectionBase.listenPort||settings.sourcePort!==connectionBase.sourcePort;
  if(restart&&state.networkEnabled&&!confirm('这些连接设置会重建网络，是否继续？'))return;
  await network('settings',{settings,expectedRevision:connectionBase.revision,confirmReplace:restart});
  connectionDirty=false;$('connection-dirty').textContent='';render(state);notice('设置已保存。');
});
$('metadata-form').oninput=()=>{metadataDirty=true;$('metadata-dirty').textContent='有未保存的草稿';};
$('reset-metadata').onclick=()=>{metadataDirty=false;$('metadata-dirty').textContent='';if(online)render(state);};
$('metadata-form').onsubmit=safe(async e=>{
  e.preventDefault();if(!metadataBase)throw Error('后台状态尚未就绪');
  const patch={};
  if($('device-name').value!==metadataBase.name){patch.deviceName=$('device-name').value;patch.expectedDeviceName=metadataBase.name;}
  if($('log-level').value!==metadataBase.level){patch.logLevel=$('log-level').value;patch.expectedLogLevel=metadataBase.level;}
  if(!Object.keys(patch).length)return;
  await command('patch',{patch});metadataDirty=false;$('metadata-dirty').textContent='';render(state);notice('设备设置已保存，当前连接保持运行。');
});
$('quality').onclick=safe(async()=>{
  if(!$('quality-peer').value)throw Error('请先连接对端');
  await command('quality',{peerSlot:Number($('quality-peer').value),mbps:50});
  cooldownUntil=Date.now()+110000;controls();
});
$('cancel-operation').onclick=safe(async()=>{
  if(!state?.operation?.cancelable)throw Error('没有可取消任务；资源退出阶段需要等待实际完成。');
  await command('cancel',{cancelOperationId:state.operation.id});
});
$('export').onclick=safe(()=>{
  if(!state)throw Error('暂无状态');
  const clean={...state,pairing:undefined,statusFresh:online,lastStatusAgeMs:performance.now()-lastStatusAt,exportedAt:new Date().toISOString(),physicalRouteEvidence:'NotCollected',userStreamingTrial:'PendingUserTrial'};
  const link=document.createElement('a');
  link.href=URL.createObjectURL(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}));
  link.download='StreamLink-diagnostics.json';link.click();setTimeout(()=>URL.revokeObjectURL(link.href),1000);
});
$('theme').onclick=()=>{
  const theme=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;
  try{localStorage.setItem('streamlink-theme',theme);}catch{}
};
async function boot() {
  try {
    try{document.documentElement.dataset.theme=localStorage.getItem('streamlink-theme')||'dark';}catch{}
    const fragment=location.hash.slice(1),ticket=/^[a-f0-9]{64}$/i.test(fragment)?fragment:'';
    history.replaceState(null,'',location.pathname);
    const session=ticket?await api('/api/session',{ticket}):await api('/api/session');
    csrf=session.csrf;await refresh();notice('');
  } catch(error){notice(error.message,true);}
}
controls();boot();setInterval(tick,1000);
setInterval(async()=>{
  if(!csrf||expired)return;
  try {
    if(state?.pairing?.active&&!busy&&online)await network('pair-poll',{},true);
    else await refresh();
  } catch(error){notice(error.message,true);}
},2500);
