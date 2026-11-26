'use strict';

const projectionFiles = (() => {
 const dialog=$('projection-file-dialog');
 const taskList=$('projection-file-tasks');
 const error=$('projection-file-error');
 const mime='application/x-conwu-file-rows';
 const date=new Intl.DateTimeFormat('zh-CN',{dateStyle:'short',timeStyle:'short'});
 const unavailable='对机直连或文件权限已变化。';
 const panes={
  local:{element:$('projection-local-files'),label:'本机'},
  remote:{element:$('projection-remote-files'),label:'对机'},
 };
 let session=null,drag=null,copying=false,transfers=[],signature='';
 const network=id=>workspaceState?.networks?.find(network=>network.id===id);

 function available(){
  if(!session||expired||!online)return false;
  const n=network(session.id)?.status;
  return n?.projection?.authorized&&n.projection.files&&n.projection.companionReady&&
    n.peers[0]?.connected&&n.peers[0]?.deviceId===session.device;
 }

 async function request(expected,action){
  const reply=await api('/api/projection/files',{networkId:expected.id,deviceId:expected.device,request:action},()=>session===expected);
  if(!reply.ok)throw Error(reply.error||'文件操作失败');
  return reply.value;
 }

 function button(action,label,disabled=false){
  return `<button class="btn compact" type="button" data-file-action="${action}" ${disabled?'disabled':''}>${label}</button>`;
 }

 function showPane(side){
  const pane=panes[side],data=pane.data;
  const entries=data?.entries||[];
  const locked=pane.loading||!available();
  const list=entries.map((entry,index)=>{
   const size=entry.directory?'':total(entry.size);
   const modified=entry.modified!=null?date.format(new Date(entry.modified*1000)):'';
   const name=esc(entry.name);
   return `<li class="projection-file-entry" data-file-index="${index}" ${entry.directory?'':'draggable="true"'}>
    ${entry.directory?`<button class="projection-folder" type="button" data-file-action="enter" ${locked?'disabled':''} title="${name}"><span class="explorer-folder-icon" aria-hidden="true"></span><span>${name}</span></button>`:
     `<label title="${name}"><input type="checkbox" data-file-select="${index}" ${pane.selected.has(entry.path)?'checked':''}><span>${name}</span></label>`}
    <span class="projection-file-size">${esc(size)}</span><time>${esc(modified)}</time>
   </li>`;
  }).join('');
  pane.element.innerHTML=`<div class="projection-pane-heading"><strong>${pane.label}</strong><span>${esc(pane.name)}</span></div>
   <div class="explorer-toolbar"><form class="explorer-location" data-path-form>
    <button type="button" class="btn compact" data-file-action="back" title="后退" aria-label="后退" ${locked||pane.historyIndex<1?'disabled':''}>←</button><button type="button" class="btn compact" data-file-action="up" title="上一级" aria-label="上一级" ${locked||!data?.path?'disabled':''}>↑</button><input name="path" aria-label="${pane.label}目录地址" placeholder="此电脑" value="${esc(data?.path||'')}" ${locked?'disabled':''}>
    <button class="btn compact" type="submit" ${locked?'disabled':''}>转到</button>
   </form>
   <form class="explorer-search" data-search-form><input type="search" name="query" maxlength="128" aria-label="搜索${pane.label}当前目录" placeholder="搜索当前目录" value="${esc(pane.query)}" ${locked?'disabled':''}><button class="btn compact" type="submit" ${locked?'disabled':''}>搜索</button></form></div>
   <div class="explorer-body"><nav class="explorer-tree" aria-label="${pane.label}快速访问">
    ${button('drives',icon('server')+'此电脑',locked)}${button('desktop',icon('monitor')+'桌面',locked)}${button('downloads',icon('save')+'下载',locked)}${button('reload',icon('refresh')+'刷新',locked)}
   </nav><div class="explorer-details">
    <div class="explorer-columns"><label><input type="checkbox" data-file-all aria-label="全选已列出的文件" ${locked||!entries.some(e=>!e.directory)?'disabled':''}>名称</label><span>大小</span><span>修改时间</span></div>
    ${pane.problem?`<p class="projection-file-problem" role="status">${esc(pane.problem)}</p>`:''}
    <ul class="projection-file-entries">${list||`<li class="projection-file-empty">${pane.loading?'正在加载…':pane.problem?'':pane.query?'没有匹配项':'此处没有文件'}</li>`}</ul>
   </div></div>
   <div class="projection-pane-actions">
    <button type="button" class="btn compact primary" data-file-action="copy">${side==='local'?'发到对机 →':'← 下载到本机'}</button>
    ${button('more','更多',locked||!data?.next)}
    ${button('mkdir','新建文件夹',locked||!data?.path)}
   </div>
   <form data-new-folder hidden>
    <input name="folder" type="text" aria-label="新文件夹名称" placeholder="文件夹名称" maxlength="255" required>
    <button class="btn compact" type="submit">创建</button>
   </form>`;
  pane.element.setAttribute('aria-busy',String(!!pane.loading));
  syncButtons();
 }

 function syncButtons(){
  for(const side of Object.keys(panes)){
   const pane=panes[side],other=panes[side==='local'?'remote':'local'];
   const copy=pane.element.querySelector('[data-file-action="copy"]');
   const all=pane.element.querySelector('[data-file-all]'),files=pane.data?.entries.filter(e=>!e.directory)||[];
   if(all){
    all.checked=files.length>0&&files.every(e=>pane.selected.has(e.path));
    all.indeterminate=!all.checked&&pane.selected.size>0;
   }
   if(copy)copy.disabled=copying||!available()||!pane.selected.size||!other.data?.path||
     pane.loading||other.loading||!!pane.problem||!!other.problem;
  }
 }

 async function load(side,location,more=false,query='',historyIndex=null){
  const pane=panes[side],expected=session;
  if(!expected||pane.loading)return;
  if(more)query=pane.query;
  pane.loading=true;
  const previousScroll=more?pane.element.querySelector('.projection-file-entries')?.scrollTop:0;
  showPane(side);
  try{
   const data=await request(expected,{action:'list',side,location,query,after:more?pane.data?.next:null});
   if(session!==expected)return;
   if(more&&pane.data?.path===data.path)data.entries=[...pane.data.entries,...data.entries];
   else pane.selected.clear();
   if(historyIndex!==null)pane.historyIndex=historyIndex;
   else if(!more&&(pane.historyIndex<0||JSON.stringify(location)!==JSON.stringify(pane.location))){
    pane.history.splice(pane.historyIndex+1);
    pane.history.push(location);if(pane.history.length>32)pane.history.shift();
    pane.historyIndex=pane.history.length-1;
   }
   pane.query=query;pane.location=location;
   pane.data=data;
   pane.problem='';
  }catch(reason){
   if(session===expected)pane.problem=reason.message;
  }finally{
   if(session===expected){
    pane.loading=false;
    showPane(side);
    if(previousScroll)pane.element.querySelector('.projection-file-entries').scrollTop=previousScroll;
   }
  }
 }

 async function transfer(from,paths,folder){
  if(copying||!available()||!paths.length||!folder)return;
  if(paths.length>64){error.textContent='每次可传输最多 64 个文件。';return;}
  const expected=session;
  copying=true;error.textContent='';syncButtons();
  try{
   await request(expected,{action:'copy',from,paths,destination:folder});
   if(session!==expected)return;
   const pane=panes[from];
   pane.selected.clear();
   for(const checkbox of pane.element.querySelectorAll('[data-file-select]'))checkbox.checked=false;
  }catch(reason){
   if(session===expected)error.textContent=reason.message;
  }finally{
   if(session===expected){copying=false;syncButtons();}
  }
 }

 function open(id){
  const device=network(id)?.status.peers[0];
  if(!device?.deviceId||!device.connected)throw Error('等待对机直连。');
  session={id,device:device.deviceId};
  const picker=$('projection-send-files');
  picker.dataset.network=id;
  picker.dataset.ready=String(!!available());
  picker.disabled=!available()||transfers.some(job=>job.active);
  error.textContent='';signature='';copying=false;
  const starts={local:{kind:'downloads'},remote:{kind:'desktop'}};
  for(const [side,pane] of Object.entries(panes)){
   Object.assign(pane,{name:side==='local'?workspaceState?.deviceName||'':device.name||'',
    history:[],historyIndex:-1,query:'',selected:new Set(),location:starts[side],data:null,problem:'',loading:false});
  }
  dialog.showModal();
  update(transfers);
  for(const side of Object.keys(panes))void load(side,panes[side].location);
 }

 function update(jobs){
  const previous=transfers;
  transfers=jobs;
  if(!dialog.open||!session)return;
  if(!available())error.textContent=unavailable;
  else if(error.textContent===unavailable)error.textContent='';
  const relevant=jobs.filter(job=>job.job.record===session.id);
  const finished=relevant.find(job=>!job.active&&job.message==='文件传输完成'&&
   !previous.some(prior=>prior.job.id===job.job.id&&!prior.active));
  if(finished){
   const destination=finished.destination?.toLowerCase();
   for(const [side,pane] of Object.entries(panes)){
    if(destination&&destination===pane.data?.path?.toLowerCase())void load(side,pane.location,false,pane.query);
   }
  }
  syncButtons();
  $('projection-file-clear').disabled=!available()||!relevant.some(job=>!job.active);
  const state=JSON.stringify(relevant);
  if(state===signature)return;
  signature=state;
  const activeTab=document.activeElement?.dataset?.job;
  taskList.innerHTML=relevant.map(job=>{
   const count=job.count>1?` · ${job.item}/${job.count}`:'';
   const paths=[job.source,job.destination].filter(Boolean).map(esc).join(' → ');
   return `<article class="projection-file-task">
    <div><strong>${esc(job.name||'文件传输')}${count}</strong>
    ${paths?`<small title="${paths}">${paths}</small>`:''}</div>
    <div><span>${esc(job.message)}</span>
    ${job.active&&job.size?`<progress value="${Number(job.bytes)||0}" max="${Number(job.size)}" aria-label="文件传输进度"></progress>`:''}</div>
    ${job.active?`<button class="btn compact" type="button" data-file-cancel="true" data-job="${esc(job.job.id)}">取消</button>`:''}
   </article>`;
  }).join('')||'<p class="hint">暂无传输</p>';
  if(activeTab)Array.from(taskList.querySelectorAll('[data-job]')).find(button=>button.dataset.job===activeTab)?.focus({preventScroll:true});
 }

 for(const [side,pane] of Object.entries(panes)){
  const otherSide=side==='local'?'remote':'local';
  pane.element.addEventListener('click',event=>{
   const button=event.target.closest('[data-file-action]');
   if(!button)return;
   const action=button.dataset.fileAction;
   if(action==='copy')void transfer(side,[...pane.selected],panes[otherSide].data?.path);
   if(action==='more')void load(side,pane.location,true);
   if(action==='back'&&pane.historyIndex>0)void load(side,pane.history[pane.historyIndex-1],false,'',pane.historyIndex-1);
   if(action==='up'&&pane.data)void load(side,pane.data.parent);
   if(['drives','desktop','downloads'].includes(action))void load(side,{kind:action});
   if(action==='reload')void load(side,pane.location,false,pane.query);
   if(action==='enter'){
    const entry=pane.data?.entries[Number(button.closest('[data-file-index]').dataset.fileIndex)];
    if(entry?.directory)void load(side,{kind:'directory',path:entry.path});
   }
   if(action==='mkdir'){
    const form=pane.element.querySelector('[data-new-folder]');
    form.hidden=!form.hidden;
    if(!form.hidden)form.elements.folder.focus();
   }
  });
  pane.element.addEventListener('submit',async event=>{
   event.preventDefault();
   if(event.target.hasAttribute('data-path-form')){
    const path=event.target.elements.path.value.trim();
    void load(side,path?{kind:'directory',path}:{kind:'drives'});return;
   }
   if(event.target.hasAttribute('data-search-form')){
    void load(side,pane.location,false,event.target.elements.query.value.trim());return;
   }
   const expected=session,folder=pane.data?.path,name=event.target.elements.folder?.value.trim();
   if(!available()||!folder||!name)return;
   const submit=event.target.querySelector('[type="submit"]');
   submit.disabled=true;error.textContent='';
   try{
    await request(expected,{action:'create',side,folder,name});
    if(session===expected)void load(side,pane.location,false,pane.query);
   }catch(reason){
    if(session===expected){error.textContent=reason.message;submit.disabled=false;}
   }
  });
  pane.element.addEventListener('change',event=>{
   if(event.target.hasAttribute('data-file-all')){
    for(const box of pane.element.querySelectorAll('[data-file-select]')){
     box.checked=event.target.checked;
     const path=pane.data.entries[Number(box.dataset.fileSelect)].path;
     if(box.checked)pane.selected.add(path);else pane.selected.delete(path);
    }
    syncButtons();return;
   }
   const index=event.target.dataset.fileSelect;
   const file=pane.data?.entries[Number(index)];
   if(index===undefined||!file||file.directory)return;
   if(event.target.checked)pane.selected.add(file.path);
   else pane.selected.delete(file.path);
   syncButtons();
  });
  pane.element.addEventListener('dragstart',event=>{
   const element=event.target.closest('[data-file-index]');
   const file=element&&pane.data?.entries[Number(element.dataset.fileIndex)];
   if(!file||file.directory||!available()||!event.dataTransfer){event.preventDefault();return;}
   drag={from:side,paths:pane.selected.has(file.path)?[...pane.selected]:[file.path]};
   event.dataTransfer.setData(mime,side);
   event.dataTransfer.effectAllowed='copy';
  });
  pane.element.addEventListener('dragend',()=>{drag=null;});
  pane.element.addEventListener('dragover',event=>{
   if(!drag||drag.from===side||!pane.data?.path||!available()||!event.dataTransfer.types.includes(mime))return;
   event.preventDefault();event.dataTransfer.dropEffect='copy';
  });
  pane.element.addEventListener('drop',event=>{
   if(!drag||drag.from===side||!pane.data?.path||!available()||!event.dataTransfer.types.includes(mime))return;
   event.preventDefault();
   const entry=event.target.closest('[data-file-index]');
   const item=entry&&pane.data.entries[Number(entry.dataset.fileIndex)];
   void transfer(drag.from,drag.paths,item?.directory?item.path:pane.data.path);
   drag=null;
  });
 }

 $('projection-file-close').addEventListener('click',()=>dialog.close());
 dialog.addEventListener('close',()=>{session=null;drag=null;});
 $('projection-file-clear').addEventListener('click',async ()=>{
  const expected=session;if(!available())return;
  try{await request(expected,{action:'clear'});}
  catch(reason){if(session===expected)error.textContent=reason.message;}
 });
 taskList.addEventListener('click',async event=>{
  const button=event.target.closest('[data-file-cancel]');
  if(!button)return;
  try{await command('projection-files-cancel',{jobId:button.dataset.job},true);}
  catch(reason){error.textContent=reason.message;}
 });
 return {open,update};
})();
