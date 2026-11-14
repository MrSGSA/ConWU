'use strict';
// Independent page and device option. All connected networks participate;
// readonly counters refresh without rebuilding the switch or other forms.
const uuTakeoverUi=(()=>{
 let pending=false,draft=null,error='',current=null,networks=[];
 const fmt=n=>`${((n||0)/1048576).toFixed(2)} MiB`;
 function section(root){
  if(root?.platform==='linux'||root?.uuTakeover?.supported===false)return '<article class="card pad"><h2>本机暂不支持 UU 通道接管</h2><p>Windows 端可自动引导 UU 使用 ConWU 直连通道。</p></article>';
  const u=root?.uuTakeover;
  return `<div class="network-columns" id="uu-takeover-section"><article class="card pad"><h2>UU远程</h2>
   <div class="switch-row"><div><h3>开启接管</h3><p>开启后重新连接 UU 会话；关闭或网络断开时撤下临时限制。</p></div><label class="switch"><input id="uu-takeover-enabled" type="checkbox" aria-label="开启 UU 远程通道接管" ${u?.settings?.enabled?'checked':''}><span class="switch-track"></span></label></div>
   <div class="row section-spacer" role="status"><span class="dot" id="uu-takeover-dot"></span><span id="uu-takeover-state"></span></div>
   <div class="field-error" id="uu-takeover-error" role="alert"></div>
  </article><article class="card pad"><h2>网络与接管状态</h2><p class="hint">网络上线后自动加入，离线后自动移除。</p><div id="uu-takeover-networks" role="list"></div></article></div>`;
 }
 function refresh(root,ready){
  current=root?.uuTakeover||null;networks=root?.networks||[];
  const toggle=document.getElementById('uu-takeover-enabled');if(!toggle)return;
  const desired=draft||current?.settings||{enabled:false};
  toggle.checked=!!desired.enabled;toggle.disabled=pending||!ready||!current?.supported;
  const names={Disabled:'未开启',Applying:'正在应用',WaitingNetwork:'等待 ConWU 直连',ChooseNetwork:'请选择网络',WaitingUu:'等待 UU 启动',Ready:'已就绪，等待 UU 连接',Idle:'已检测到 UU 数据 · 当前低流量',Transmitting:'检测到 UU 经由 ConWU 传输',Error:'接管暂不可用',Stopped:'接管已停止',Unsupported:'本机暂不支持'};
  document.getElementById('uu-takeover-state').textContent=pending?'正在保存…':!ready?'状态待刷新':names[current?.state]||'后台尚未支持此功能';
  document.getElementById('uu-takeover-dot').className='dot'+(ready&&current?.rulesActive&&current?.trafficObserved?' good':'');
  document.getElementById('uu-takeover-error').textContent=error||(current?.state==='Error'?current.message:'');
  const list=document.getElementById('uu-takeover-networks');
  const rows=networks.map(n=>{const live=current?.networks?.find(v=>v.id===n.id),connected=ready&&n.status?.directPeers>0;
   const label=!desired.enabled?'接管未开启':!connected?'等待网络直连':!current?.rulesActive?'等待 UU 启动':live?.trafficObserved?'检测到 UU 流量':'已自动就绪';
   return `<div class="method-row" role="listitem" data-uu-network="${esc(n.id)}"><div class="grow"><strong>${esc(n.name)}</strong><div class="hint mono">${esc(n.status?.virtualIp||'尚未分配虚拟 IP')}</div><div class="hint">${label}</div></div><div class="small mono">↓ ${fmt(live?.receivedBytes)}<br>↑ ${fmt(live?.sentBytes)}</div></div>`;}).join('');
  list.innerHTML=rows||'<p class="muted">尚无网络。创建或加入网络后，此处会自动显示。</p>';
 }
 async function save(){
  if(pending||!current?.supported)return;
  const toggle=document.getElementById('uu-takeover-enabled');
  draft={enabled:toggle.checked};pending=true;error='';refresh(workspaceState,true);
  try{
   const operationId=crypto.randomUUID();let reply;
   try{reply=await api('/api/command',{method:'uu-takeover',operationId,uuTakeover:{settings:draft,expectedRevision:current.revision}});}
   catch(ex){if(!ex.retryable)throw ex;reply={ok:true,operation:{id:operationId,completed:false}};}
   const deadline=Date.now()+100000;
   while(reply.operation&&!reply.operation.completed&&Date.now()<deadline){
    await new Promise(resolve=>setTimeout(resolve,500));let progress;
    try{progress=await api('/api/status?operation='+encodeURIComponent(operationId));}catch(ex){if(ex.retryable)continue;throw ex;}
    if(!progress.ok)throw Error(progress.error||'无法读取接管设置的保存结果');
    if(progress.operation?.id!==operationId)continue;
    reply=progress;
    if(reply.status)render(reply.status);
   }
   if(reply.status)render(reply.status);
   if(!reply.ok||reply.operation?.error)throw Error(reply.error||reply.operation.error||'无法保存接管设置');
   if(reply.operation&&!reply.operation.completed)throw Error('接管设置的保存结果尚待确认，请刷新状态。');
  }catch(ex){error=ex.message;}
  finally{pending=false;draft=null;controls();void refreshStatus();}
 }
 async function refreshStatus(){try{await window.refresh();}catch{}}
 document.addEventListener('change',event=>{if(event.target.id==='uu-takeover-enabled')void save();});
 return {section,refresh};
})();
