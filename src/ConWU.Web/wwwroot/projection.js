'use strict';

const projectionMode = (() => {
 const switcher = $('mode-switch');
 const deviceList = $('projection-device-list');
 const desktop = typeof window.conwuProjectionSurface === 'function';
 let lastNetworkPage = 'overview';
 let selected = '';
 let stage = null, frame = 0, poll = 0, fullscreen = false, transition = null, requests = Promise.resolve();
 let endingSession = '', endedSession = '';
 // The native host starts hidden. Retire its last placement once when leaving playback.
 let surfacePlaced = true;
 const completedJobs = new Set();
 let observedJobs = false;
 const mark = '<span class="projection-mark" aria-hidden="true"><span class="projection-lens"></span><span class="projection-beam"></span><span class="projection-screen"></span></span>';

 const covers = new Map();
 const playbackSizes = new Map();
 const device = id => workspaceState?.networks?.find(n => n.id === id);
 const identity = n => ({networkId:n.id,deviceId:n.status.peers[0].deviceId});
 const keyFor = n => JSON.stringify([n.id,n.status.peers[0].deviceId]);
 const usable = n => !!(n?.status.projection?.authorized && !n.status.networkRevoked && n.status.peers[0]?.deviceId);
 const connected = n => usable(n) && online && n.status.peers[0].connected;
 const liveTools = n => usable(n) && online && n.status.peers[0].connected && n.status.projection.companionReady;
 const sessionId = () => transition?.id || endingSession || workspaceState?.projectionMoonlight?.networkId;
 const validSize = value => Array.isArray(value) && value.length===2 &&
   value.every(n=>Number.isInteger(n)&&n>0&&n<=16384);
 const sizeSetting = key => 'conwu-projection-size-'+key;

 function lastSize(n) {
  if(!n?.status.peers[0]?.deviceId)return null;
  const key=keyFor(n);
  if(!playbackSizes.has(key)){
   let record=null;
   try{
    const saved=JSON.parse(localStorage.getItem(sizeSetting(key)));
    if(validSize(saved?.video)&&validSize(saved?.window))record=saved;
   }catch{}
   playbackSizes.set(key,record);
  }
  return playbackSizes.get(key);
 }

 function sizeStage() {
  if(!stage?.isConnected)return;
  const n=device(selected), saved=lastSize(n);
  const offline=n&&(!online||!n.status.peers[0]?.connected);
  const cover=n?.status.peers[0]?.deviceId?covers.get(keyFor(n))?.size:null;
  const playing=n&&sessionId()===n.id&&phase()!=='starting';
  const size=(offline?saved?.window:playing?saved?.video||cover:cover||saved?.video)||[16,9];
  stage.style.setProperty('--projection-ratio',String(size[0]/size[1]));
  if(offline&&saved)stage.style.setProperty('--projection-remembered-width',saved.window[0]+'px');
  else stage.style.removeProperty('--projection-remembered-width');
 }

 function rememberSize(id, video) {
  const n=device(id);
  if(!connected(n)||!stage?.isConnected||selected!==id||fullscreen||phase()!=='playing'||!validSize(video))return;
  const key=keyFor(n), prior=lastSize(n);
  stage.style.setProperty('--projection-ratio',String(video[0]/video[1]));
  const rect=stage.getBoundingClientRect();
  const windowSize=[Math.round(rect.width),Math.round(rect.height)];
  if(!validSize(windowSize))return;
  const record={video,window:windowSize};
  if(prior&&JSON.stringify(record)===JSON.stringify(prior))return;
  playbackSizes.set(key,record);
  try{localStorage.setItem(sizeSetting(key),JSON.stringify(record));}catch{}
 }

 function phase() {
  if (endedSession && endedSession===sessionId()) return 'idle';
  const player = workspaceState?.projectionMoonlight;
  if (transition) return transition.phase;
  if (endingSession) return 'stopping';
  if (!player?.networkId) return 'idle';
  if (player.stopping) return 'stopping';
  return player.opened ? 'playing' : 'starting';
 }

 async function deviceApi(path,body){
  const reply=await api('/api/projection/'+path,body);
  if(!reply.ok)throw Error(reply.error||'设备操作未完成');
  return reply.value;
 }

 function updateCover(){
  for(const [key,item] of covers){
   const n=device(item.id);
   if(!connected(n)||key!==keyFor(n))covers.delete(key);
  }
  const img=$('projection-cover'),n=device(selected);
  if(!img)return;
  const revision=n?.status.projection?.coverRevision;
  const key=usable(n)?keyFor(n):'';
  let item=covers.get(key);
  if(page!=='projection'||!connected(n)||(!revision&&!item?.url)){
   img.hidden=true;img.removeAttribute('src');return;
  }
  if(revision&&item?.revision!==revision){item={id:n.id,revision,url:item?.url,size:item?.size,loading:false,next:0};covers.set(key,item);}
  const paint=()=>{
   const view=$('projection-cover');
   if(!view||!connected(device(n.id))||covers.get(key)!==item||selected!==n.id||page!=='projection'||!item.url)return;
   if(view.getAttribute('src')!==item.url)view.src=item.url;
   view.hidden=false;
   const size=[view.naturalWidth,view.naturalHeight];
   if(validSize(size)){
    item.size=size;
    sizeStage();
   }
  };
  paint();
  if(!revision||item.loaded||item.loading||Date.now()<item.next||!liveTools(n))return;
  item.loading=true;
  deviceApi('cover',identity(n)).then(preview=>{
   if(preview?.image){
    item.url='data:image/'+(preview.image.startsWith('/9j/')?'jpeg':'bmp')+';base64,'+preview.image;
    item.loaded=true;
    paint();
   }
  }).catch(()=>{}).finally(()=>{item.loading=false;item.next=Date.now()+3000;});
 }

 function stageStatus(pending, hint) {
  if(pending==='starting'||pending==='stopping'){
   const message=pending==='starting'?'正在准备串流':'正在结束';
   return `<p id="projection-stage-status" class="projection-progress" role="status">${message}<span class="projection-progress-dots" aria-hidden="true">...</span></p>`;
  }
  const message=hint||workspaceState?.projectionMoonlight?.error;
  return message?`<p id="projection-stage-status" role="status">${esc(message)}</p>`:'';
 }

 function moonlightAction(id, ready, pending) {
  if (pending === 'starting') return '<button class="btn primary" type="button" disabled>串流</button>';
  if (!workspaceState?.projectionEmbedded) return '';
  if (!desktop) {
   return `<button class="btn primary" data-ui-action="projection-open-desktop" ${online?'':'disabled'}>打开 ConWU 桌面</button>`;
  }
  const player = workspaceState?.projectionMoonlight;
  const enabled = online && ready && player?.available && !sessionId();
  return `<button class="btn primary" data-ui-action="projection-moonlight" data-network="${esc(id)}" ${enabled?'':'disabled'}>串流</button>`;
 }

 function afterRender() {
  if (!desktop) return;
  if(page!=='projection'&&!transition&&endingSession&&!workspaceState?.projectionMoonlight?.networkId)endingSession='';
  if (!sessionId()) endedSession='';
  const player=workspaceState?.projectionMoonlight;
  if(player?.stopping&&player.networkId!==endedSession)endingSession=player.networkId;
  updateTransfer();
  void updateCover();
  const next = $('projection-stage');
  if (next !== stage) {
   resize.disconnect();
   stage = next;
   if (stage) {
    resize.observe(stage);
    $('projection-cover')?.addEventListener('load',updateCover);
   }
  }
  sizeStage();
  const active = page === 'projection' && !!sessionId();
  if (active && !poll) poll = setInterval(schedule, 150);
  if (!active && poll) { clearInterval(poll); poll = 0; }
  if (active) schedule();
  else if (surfacePlaced) void sync().catch(() => {});
 }

 function updateTransfer() {
  const jobs = workspaceState?.projectionTransfers || (workspaceState?.projectionTransfer ? [workspaceState.projectionTransfer] : []);
  if (typeof projectionFiles !== 'undefined') projectionFiles.update(jobs);
  for (const job of jobs) {
   if (job.active || completedJobs.has(job.job.id)) continue;
   completedJobs.add(job.job.id);
   if (observedJobs && page === 'projection' && job.job.record === selected) notify(job.message);
  }
  if (workspaceState) observedJobs = true;
  while (completedJobs.size > 64) completedJobs.delete(completedJobs.values().next().value);
  const container = $('projection-transfer');
  if (!container) return;
  const transfer = jobs.find(job => job.active && job.job.record === selected);
  const visible = !!transfer;
  const markup = visible ? `<p role="status">${esc(transfer.message)}${transfer.count ? ` · ${esc(transfer.name)} · ${transfer.item}/${transfer.count}` : ''}</p>
   ${transfer.destination ? `<p>${transfer.download?'本机保存位置':'对机保存位置'} · ${esc(transfer.destination)}</p>` : ''}
   ${transfer.active && transfer.count ? `<progress value="${Number(transfer.bytes) || 0}" max="${Math.max(1, Number(transfer.size) || 1)}" aria-label="文件传输进度"></progress><button class="btn compact" data-ui-action="projection-files-cancel" data-job="${esc(transfer.job.id)}">取消传输</button>` : ''}` : '';
  if (container.dataset.markup !== markup) {
   container.dataset.markup = markup;
   container.innerHTML = markup;
  }
 }

 const resize = desktop ? new ResizeObserver(schedule) : null;

 function placement() {
  const id = sessionId();
  if (!id || id===endedSession || !stage?.isConnected || page !== 'projection' || document.hidden || expired) return null;
  const rect = stage.getBoundingClientRect();
  if (rect.width < 1 || rect.height < 1 || rect.bottom<=0 || rect.right<=0 ||
      rect.top>=window.innerHeight || rect.left>=window.innerWidth) return null;
  const ratio = window.devicePixelRatio;
  const x = Math.round(rect.left * ratio);
  const y = Math.round(rect.top * ratio);
  const width = Math.round(rect.right * ratio) - x;
  const height = Math.round(rect.bottom * ratio) - y;
  const radius = Math.round(parseFloat(getComputedStyle(stage).borderTopLeftRadius) * ratio);
  const dialogs=[...document.querySelectorAll('dialog[open]')];
  const cutouts=dialogs.map(dialog=>{
   const b=dialog.getBoundingClientRect();
   return {left:Math.floor(b.left*ratio)-x,top:Math.floor(b.top*ratio)-y,
    right:Math.ceil(b.right*ratio)-x,bottom:Math.ceil(b.bottom*ratio)-y};
  });
  const active=device(sessionId());
  return {x,y,width,height,
   radius,cutouts,showViewer:connected(active),
   acceptInput:phase()==='playing'};
 }

 function sync(wantFullscreen = null, toggleStats = false) {
  if (!desktop) return Promise.resolve(null);
  const next = requests.then(async () => {
   const area = placement();
   const id = sessionId();
   if (!area && !surfacePlaced) return null;
   if (area) surfacePlaced = true;
   const reply = await window.conwuProjectionSurface(area, false, wantFullscreen, toggleStats);
   surfacePlaced = !!area;
   fullscreen = !!reply?.fullscreen;
   const endedWithoutWindow=endingSession===id&&!reply?.attached&&
    !transition&&workspaceState?.projectionMoonlight?.networkId!==id;
   if (area && (reply?.ended||endedWithoutWindow) && id===sessionId()) {
    // Replace the ending UI underneath the frozen window before closing it.
    endedSession=id;
    endingSession='';
    render();
    const cover=$('projection-cover');
    if(cover?.src)await Promise.race([cover.decode().catch(()=>{}),new Promise(resolve=>setTimeout(resolve,500))]);
    await new Promise(resolve=>{
     const deadline=setTimeout(resolve,100);
     requestAnimationFrame(()=>requestAnimationFrame(()=>{clearTimeout(deadline);resolve();}));
    });
    await window.conwuProjectionSurface(null, true);
    fullscreen=false;
    surfacePlaced=false;
    if(!busy)void refresh();
    return null;
   }
   if(area&&reply?.stopping&&id===sessionId()&&!endingSession){
    endingSession=id;
    render();
   }
   if(area?.showViewer&&id===sessionId()&&reply?.video)rememberSize(id,reply.video);
   return area;
  });
  requests = next.catch(() => {});
  return next;
 }

 let scheduled = false, dirty = false;
 function schedule() {
  if (scheduled){dirty=true;return;}
  if (frame) return;
  frame = requestAnimationFrame(() => {
   frame = 0;
   scheduled = true;
   void sync().catch(() => {}).finally(() => { scheduled = false;if(dirty){dirty=false;schedule();} });
  });
 }

 async function toggleFullscreen() {
  await sync(!fullscreen);
 }

 function updateBrand() {
  if (!desktop) return;
  const projection = page === 'projection';
  const label = projection ? '切换到 ConWU 组网' : '切换到 Projection 远控';
  switcher.closest('.sidebar').dataset.mode = projection ? 'projection' : 'network';
  switcher.setAttribute('aria-label', label);
  switcher.setAttribute('aria-pressed', String(projection));
  switcher.title = label;
 }

 function enter() {
  if (page !== 'projection') {
   lastNetworkPage = page;
   navigate('projection');
  }
 }

 if (desktop) {
  switcher.disabled = false;
  switcher.addEventListener('click', () => {
   if (page === 'projection') navigate(lastNetworkPage);
   else enter();
  });
  for (const event of ['resize','scroll','focus','pageshow']) window.addEventListener(event,schedule,{passive:true});
  document.addEventListener('visibilitychange',()=>{if(document.hidden)void sync().catch(()=>{});else schedule();});
  new MutationObserver(schedule).observe(document.body, {subtree:true, attributes:true, attributeFilter:['open']});
  window.addEventListener('keydown', event => {
   if(page!=='projection'||phase()!=='playing'||document.querySelector('dialog[open]')||
      !event.ctrlKey||!event.shiftKey||event.metaKey||event.repeat)return;
   if(!event.altKey&&event.code==='KeyS'){
    event.preventDefault();
    void sync(null,true).catch(error=>notify(error.message));
    return;
   }
   if(!event.altKey)return;
   const action=event.code==='KeyX'?toggleFullscreen:event.code==='KeyQ'?()=>stopMoonlight(sessionId()):null;
   if(!action)return;
   event.preventDefault();
   void action().catch(error=>notify(error.message));
  });
  updateBrand();
 }

 function view(devices, ready) {
  const active = sessionId();
  const entries = devices.filter(n => n.status.networkDirect && n.status.projection && !n.status.networkRevoked && n.status.peers[0]?.deviceId);
  const current = entries.find(n => n.id === active) || entries.find(n => n.id === selected) || entries[0];
  const pending = current?.id===active ? phase() : 'idle';
  selected = current?.id || '';
  deviceList.innerHTML = entries.map(n => {
   const peer = n.status.peers[0];
   const name = peer.name || n.name;
   const disabled = active && active !== n.id;
   return `<button class="projection-peer" title="${esc(name)}" type="button" data-ui-action="projection-select-device" data-network="${esc(n.id)}" aria-pressed="${n.id === selected}" ${disabled?'disabled':''}>${icon('monitor')}<span><strong>${esc(name)}</strong><small>${online && peer.connected?'已直连':'等待直连'}</small></span></button>`;
  }).join('');
  const p = current?.status.projection, peer = current?.status.peers[0];
  const canPlay = online && ready(p, peer);
  const canSend = !!(online && peer?.connected && p?.files && p?.authorized && p?.companionReady);
  const offline = !!current && (!online || !peer?.connected);
  const hint = offline ? '' : !workspaceState?.projectionEmbedded ? '当前安装缺少同窗播放组件' :
    !current ? '在 ConWU 中配对设备后，即可开始串流' :
    !p.authorized ? '在设置中允许远控' : canPlay ? '' : '等待对端 Projection 自动连接组件就绪';
  const action = pending==='stopping'?'':!current ? mark : offline ? '<button class="btn primary" type="button" disabled>未在线</button>' :
    pending==='idle'||pending==='starting' ? moonlightAction(selected,canPlay,pending) : '';
  const playback = desktop && (pending==='playing'||pending==='stopping');
  const toolbar = current || playback ? `<div class="projection-device-actions">
     ${current?`<button class="btn compact" data-ui-action="projection-settings" data-network="${esc(selected)}">设置</button>
     <button class="btn compact" data-ready="${canSend}" data-ui-action="projection-file-browser" data-network="${esc(selected)}" ${canSend?'':'disabled'}>文件互传</button>`:''}
     <div class="projection-session-actions" ${playback?'':'inert aria-hidden="true"'}>
      <button class="btn compact" data-ui-action="projection-fullscreen">全屏</button>
      <button class="btn compact" data-ui-action="projection-moonlight-stop" data-network="${esc(selected)}">结束串流</button>
     </div></div>` : '';
  const hotkeys = playback ? `<p class="hint projection-hotkeys"><span><kbd>Ctrl+Alt+Shift+X</kbd> 切换全屏</span>
     <span><kbd>Ctrl+Alt+Shift+Z</kbd> 释放或捕捉键鼠</span><span><kbd>Ctrl+Alt+Shift+Q</kbd> 结束串流</span>
     <span><kbd>Ctrl+Shift+S</kbd> 开关性能统计</span></p>` : '';
  return `<section class="projection-page" aria-labelledby="page-title"><header class="projection-header"><h1 id="page-title">${esc(peer?.name || current?.name || 'Projection')}</h1>${toolbar}</header>
   <div class="projection-stage" id="projection-stage"><img id="projection-cover" class="projection-cover" alt="" hidden><div class="projection-placeholder">${action}${pending==='playing'||offline&&pending!=='stopping'?'':stageStatus(pending,hint)}</div></div>
   ${hotkeys}
   <div class="projection-transfer" id="projection-transfer"></div></section>`;
 }

 async function connectMoonlight(id, peer) {
  if (!desktop) return openDesktop();
  if (!workspaceState?.projectionEmbedded) {
   throw Error('此安装需要更新支持内嵌播放的 Projection 组件。');
  }
  if(sessionId())return;
  selected = id;
  transition={id,phase:'starting'};
  enter();
  if (page === 'projection') render();
  window.scrollTo(0, 0);
  try {
   if (!await sync()) throw Error('Projection 播放区尚未显示，请返回页面后重试。');
   await command('projection-connect', {networkId:id, deviceId:peer.deviceId, embedded:true}, true);
  } finally {transition=null;render();}

 }

 async function stopMoonlight(id) {
  if(phase()!=='playing'||sessionId()!==id)return;
  transition={id,phase:'stopping'};
  endingSession=id;
  render();
  try {
   await command('projection-stop',{networkId:id},true);
  } catch(error){
   if(endingSession===id&&!workspaceState?.projectionMoonlight?.stopping)endingSession='';
   throw error;
  } finally {transition=null;render();}
 }

 async function openDesktop() {
  await command('projection-open-desktop', {}, true);
 }

 function selectDevice(id) {
  const network = workspaceState?.networks?.find(network=>network.id===id);
  if (!network || sessionId()) return;
  selected = id;
  render();
 }

 return {desktop, view, afterRender, updateBrand, updateCover, sessionId, phase, connectMoonlight, stopMoonlight, openDesktop, selectDevice, toggleFullscreen};
})();
