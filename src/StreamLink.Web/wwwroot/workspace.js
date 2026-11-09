'use strict';

// Keep the familiar 1.0.5 pages; select a network independently of the saved
// configuration being edited. Polls never replace another editor's draft.
let workspaceState=null,selectedNetwork='',selectedConfiguration='',configurationName='',baseConfigurationName='',configurationRevision=0,settingsScope='configuration';
const configurationDrafts=new Map(),disclosures=new Map();
let renderedPage='overview',renderedConfiguration='';
const legacy={render,controls,settingsPage,createPage,joinPage,overviewPage,updateShell,api,baseSectionFields,refreshSettingsTools};
const configurationGroups=['network','coordination','port','certificate','stun'];
const deviceGroups=['system','identity','logging','host'];
defaults.network.coordinatorBackup=false;defaults.network.pkarrPublish=false;
sectionNames.host='本机协调服务';sectionIcons.host='server';
defaults.host={enabled:false,listenUrl:'http://127.0.0.1:47822',publicUrl:'',publicCertificatePin:'',certificateFile:'',certificateKeyFile:'',trustCloudflare:false};
function configuration(){return workspaceState?.configurations?.find(c=>c.id===selectedConfiguration);}
function configurationNameDirty(){return settingsScope==='configuration'&&configurationName.trim()!==baseConfigurationName;}
function localConfigurationStatus(raw){
 const config=configuration(),p=config?.settings||configurationDrafts.get('new')?.settings||newConfigurationSettings();
 return {...raw,networkId:'',networkEnabled:false,isOwner:false,peers:[],pairing:null,settings:p,settingsRevision:String(config?.revision||0)};
}
function newConfigurationSettings(){return {service:'',certificatePin:'',manualEndpoint:'',pathSelection:'faketcp-only',listenPort:44680,sourcePort:44691,connectionSource:'custom',directMode:false,existingEntries:[],entryRefreshSeconds:60,tcpStun:[],udpStun:[],requestedVirtualIp:''};}
function rememberDraft(){
 if(!settingsHydrated)return;
 configurationDrafts.set(settingsScope==='device'?'device':selectedConfiguration||'new',{saved:clone(saved),drafts:clone(drafts),name:configurationName,baseName:baseConfigurationName,revision:configurationRevision,history:history?clone(history):null});
}
function chooseConfiguration(id){
 rememberDraft();selectedConfiguration=id;settingsScope='configuration';hydrateEditor();render();
}
function hydrateEditor(){
 const cached=configurationDrafts.get(settingsScope==='device'?'device':selectedConfiguration||'new'),config=configuration();
 if(cached){saved=clone(cached.saved);drafts=clone(cached.drafts);configurationName=cached.name;baseConfigurationName=cached.baseName;configurationRevision=cached.revision;history=cached.history;}
 else{
  const source=settingsScope==='device'?{...workspaceState,settings:workspaceState?.deviceSettings}:localConfigurationStatus(workspaceState||state||{});
  saved=configFromStatus(source);drafts=clone(saved);history=null;configurationName=baseConfigurationName=config?.name||'新配置';configurationRevision=config?.revision||0;
  const host=source.settings?.coordinator||{};saved.host={...defaults.host,...host};drafts.host=clone(saved.host);
 }
 settingsHydrated=true;baseRevision=settingsScope==='device'?workspaceState?.deviceSettingsRevision||'':String(configurationRevision);
}
function profilePicker(){return `<article class="card pad configuration-picker"><label class="field"><span>本次使用的配置</span><select data-configuration-select aria-label="选择连接配置">${(workspaceState?.configurations||[]).map(c=>`<option value="${esc(c.id)}" ${selectedConfiguration===c.id?'selected':''}>${esc(c.name)} · ${c.networks.length?'用于 '+c.networks.length+' 个网络':'未关联网络'}</option>`).join('')}${!selectedConfiguration?'<option value="" selected>新建配置</option>':''}</select></label><div class="row wrap"><button class="btn compact" data-workspace="new-configuration">${icon('plus')}新建配置</button><button class="text-btn" data-workspace="edit-configuration">查看与编辑配置${icon('chevron')}</button></div><p class="hint">${configuration()?.networks.length?'此配置用于：'+esc(configuration().networks.map(n=>n.name).join('、'))+'。保存修改会更新这些网络。':'可以先保存配置，再创建或加入网络。'}</p></article>`;}
function usageNotice(){const users=configuration()?.networks||[];return `<div class="inline-note configuration-usage"><strong>${users.length?'用于 '+users.length+' 个网络':'未关联网络'}</strong>${users.length?`<ul>${users.map(n=>`<li><span>${esc(n.name)}</span> · ${n.state==='applied'?'设置已应用':n.state==='pending'?'等待应用':'应用失败'}${!n.enabled?' · 已停止':''}${n.error?`<p class="field-error">${esc(n.error)}</p>`:''}${n.state!=='applied'?` <button class="text-btn" data-workspace="apply-configuration">重试应用</button>`:''}</li>`).join('')}</ul><p class="hint">保存会更新以上全部网络；协议或端口变化可能需要重新连接。</p>`:'<p class="hint">保存此配置不会启动网络或打洞。</p>'}</div>`;}
function networkSelector(){return `<div class="workspace-selector row wrap"><label for="workspace-network">当前网络</label><select id="workspace-network" aria-label="选择网络"><option value="">${page==='create'?'创建另一条网络':page==='join'?'加入另一条网络':'全部网络'}</option>${(workspaceState?.networks||[]).map(n=>`<option value="${esc(n.id)}" ${selectedNetwork===n.id?'selected':''}>${esc(n.name)} · ${n.status.isOwner?'主机':'从机'}${n.status.directPeers?' · 已直连':''}</option>`).join('')}</select>${selectedNetwork?'<button class="text-btn" data-workspace="new-network">新建／加入另一网络</button>':''}</div>`;}
function configurationEditor(){
 const groups=settingsScope==='device'?deviceGroups:configurationGroups;if(!groups.includes(section))section=groups[0];
 const dirtyValue=dirtyCount(),users=configuration()?.networks||[];
 return `<div class="settings-layout"><aside class="settings-rail"><nav class="settings-nav" aria-label="设置分区">${groups.map(key=>`<button data-section="${key}" class="${section===key?'active':''}">${sectionNames[key]}<span data-section-dot="${key}" class="dirty-mark" ${dirty(key)?'':'hidden'}></span></button>`).join('')}</nav><div class="settings-tools"><div id="save-state" class="save-state" role="status"></div><button class="btn primary" id="save-section" data-action="save">${icon('save')}${settingsScope==='device'?'保存本机设置':'保存此配置'}</button><button class="btn" id="revert-section" data-action="revert">${icon('undo')}恢复刚才设置</button><button class="btn" id="default-section" data-action="defaults">${icon('refresh')}恢复默认设置</button><p class="settings-note">${settingsScope==='device'?'只影响本机设备设置。':users.length?'保存会更新全部关联网络。':'保存后可在创建或加入时使用。'}</p></div></aside><article class="card settings-panel"><div class="pad">${settingsScope==='configuration'?`<label class="field"><span>配置名称</span><input id="configuration-name" maxlength="64" value="${esc(configurationName)}" autocomplete="off"></label>${usageNotice()}`:''}<div class="settings-title">${icon(sectionIcons[section])}<h2>${sectionNames[section]}</h2></div><div id="settings-fields">${sectionFields()}</div><div id="settings-error" class="field-error" role="status"></div><div class="row wrap configuration-actions">${selectedConfiguration&&settingsScope==='configuration'?'<button class="btn" data-workspace="copy-configuration">复制为新配置</button>'+(selectedNetwork?'<button class="btn" data-workspace="assign-configuration">让当前网络使用此配置</button>':'')+'<button class="btn danger" data-workspace="delete-configuration">删除配置</button>':''}</div></div></article></div>`;
}
settingsPage=function(){return heading('设置','选择一份配置进行修改，保存后更新所有关联网络。')+`<div class="configuration-tabs row wrap"><button class="btn ${settingsScope==='configuration'?'primary':''}" data-workspace="configuration-scope">连接配置</button><button class="btn ${settingsScope==='device'?'primary':''}" data-workspace="device-scope">本机设置</button></div>`+(settingsScope==='configuration'?profilePicker():'')+configurationEditor();};
createPage=function(){
 if(selectedNetwork)return networkSelector()+`<article class="card pad"><h2>入口与连接状态</h2><p class="card-lead">${esc(state?.entryPreparation?.detail||state?.connection?.detail||state?.state||'等待入口准备')}</p>${state?.entryPreparation?.endpoint?`<div class="mono">候选入口：${esc(state.entryPreparation.endpoint)}</div>`:''}</article>`+legacy.createPage().replace('创建新网络前，需要删除或退出当前网络。','可以通过上方网络选择创建另一条连接。')+'<article class="card pad"><h2>本机移除</h2><p class="card-lead">对端或协调服务不可用时，可以只移除本机记录；远端撤销不会被标记为成功。</p><button class="btn danger" data-workspace="remove-locally">仅从本机移除</button></article>';
 return heading('创建网络','先选择连接配置，再建立一条独立的双机网络。')+networkSelector()+profilePicker()+configurationEditor()+`<article class="card pad"><label class="field"><span>网络名称</span><input id="new-network-name" maxlength="64" value="${esc(newNetworkName)}" placeholder="例如：主机—笔记本"></label>${networkAddressField()}<div class="method-rows"><div class="method-row"><span>连接策略</span><span>${saved.network.mode==='existing'?'只使用已有入口':'自主打洞'}</span></div><div class="method-row"><span>配对方式</span><span>${pairingKind()==='invite'?'直连邀请':saved.network.mode==='existing'?'经由已有入口发送短配对码':'HTTPS 协调＋短配对码'}</span></div></div><div class="form-actions"><button class="btn primary" data-action="create">${icon('plus')}保存并创建网络</button><button class="btn" data-workspace="edit-configuration">编辑连接配置</button></div><div id="create-error" class="field-error" role="status"></div></article>`;
};
let newNetworkName='',newNetworkIp='';
function networkAddressField(){return `<details class="plain-details" id="network-address-options"><summary>虚拟地址（可选）</summary><label class="field"><span>本网络的虚拟 IPv4</span><input id="new-network-ip" value="${esc(newNetworkIp)}" placeholder="留空自动分配" spellcheck="false"><span class="hint">地址属于此网络，不随共用配置一起修改；自动分配会避开已知冲突。</span></label></details>`;}
function pairingKind(){return saved.network.mode==='existing'?'code':activeRoute()==='direct'?'invite':'code';}
activeRoute=function(){return saved.network.mode==='existing'?'direct':saved.network.route;};
pairMethodTabs=function(context){const invitationMode=pairingKind()==='invite',reason=invitationMode?'无协调自主入口使用直连邀请。':'当前使用短配对码，申请由目标主机批准。';return `<div class="pair-method-tabs" role="tablist"><button role="tab" class="${invitationMode?'':'selected'}" ${invitationMode?'disabled':''} aria-selected="${!invitationMode}">${icon('shield')}配对码</button><button role="tab" class="${invitationMode?'selected':''}" ${!invitationMode?'disabled':''} aria-selected="${invitationMode}">${icon('link')}直连邀请</button></div><p class="hint">${reason}</p>`;};
joinPage=function(){
 if(joinTab==='incoming')return networkSelector()+legacy.joinPage();
 const invite=pairingKind()==='invite';return heading('加入网络','选择本次配置，输入目标主机的配对信息。')+networkSelector()+(!selectedNetwork?profilePicker():'')+`<div class="segmented"><button class="active" data-join-tab="outgoing">加入其他网络</button><button data-join-tab="incoming">收到的申请${incoming?' · 新申请':''}</button></div><div class="two-col"><article class="card pad" id="join-card">${pairMethodTabs('join')}${joinStatus?waitingView():`<form id="join-form"><label class="field"><span>${invite?'目标主机的直连邀请':'请输入目标主机生成的配对码'}</span>${invite?`<textarea id="join-invite" rows="4" wrap="off" class="mono" spellcheck="false">${esc(joinInviteValue)}</textarea>`:`<div class="digits-input">${codeDigits(joinCodeValue)}<input id="join-code" value="${esc(joinCodeValue)}" inputmode="numeric" autocomplete="off" aria-label="目标主机的六位配对码"></div>`}<span class="hint">${invite?'邀请携带入口和目标身份。':saved.network.mode==='existing'?'通过当前配置中的目标主机入口发送申请，无需协调服务器。':'双方配置须使用同一个 HTTPS 协调服务器。'}</span></label><label class="field"><span>本机设备名称</span><input id="join-device-name" value="${esc(joinName||localName())}" maxlength="64"></label>${networkAddressField()}<div class="form-actions"><button class="btn primary" type="submit" id="join-submit">请求加入${icon('join')}</button></div><div id="join-error" class="field-error" role="status">${esc(joinError)}</div></form>`}</article><div class="stack">${methodCard()}${joinMethodHelp()}</div></div>`;
};
networkFields=function(){const d=drafts.network;return `<label class="field"><span>连接协议</span><select data-key="protocol"><option value="faketcp" ${d.protocol==='faketcp'?'selected':''}>FakeTCP + HTTP</option><option value="udp" ${d.protocol==='udp'?'selected':''}>直接 UDP</option></select><span class="hint">两端使用相同协议，不自动切换。</span></label><label class="field"><span>连接策略</span><select data-key="mode"><option value="custom" ${d.mode==='custom'?'selected':''}>自主打洞</option><option value="existing" ${d.mode==='existing'?'selected':''}>只使用已有入口</option></select></label>${d.mode==='existing'?`<label class="field"><span>这些入口属于</span><select id="entry-owner" data-key="owner">${entryOwnerOptions(d)}</select></label><div class="field"><span>${d.owner==='local'?'本机入口地址':'目标主机的入口'}</span><div class="entry-rows">${(d.entries[d.owner]||['']).map((v,i)=>entryRow(v,i,(d.entries[d.owner]||[]).length)).join('')}</div><span class="hint">支持 IP:端口、域名:端口、HTTPS/TXT 等订阅链接。多主机共用内容可使用 #streamlink1 等标签筛选。</span></div><div class="test-row"><button class="btn compact" data-action="test" id="test-addresses">测试地址</button><span id="test-status" class="small muted"></span></div><div id="test-results" class="result-list"></div><p class="hint">直接向目标 ConWU 发送配对码申请；不启动自主打洞。</p><label class="field"><span>订阅检查间隔</span><div class="row"><input data-key="refresh" type="number" min="1" value="${d.refresh}"><select data-key="unit">${[[1,'秒'],[60,'分钟'],[3600,'小时']].map(([v,n])=>`<option value="${v}" ${Number(d.unit)===v?'selected':''}>${n}</option>`).join('')}</select></div></label>${formatHelp(d)}`:`<label class="field"><span>配对方式</span><select data-key="route"><option value="server" ${d.route==='server'?'selected':''}>使用 HTTPS 协调服务器</option><option value="direct" ${d.route==='direct'?'selected':''}>无协调服务器 · 直连邀请</option></select><span class="hint">无协调时无法执行需要双方同步的打洞；取得候选也不保证公网可达。</span></label><button class="text-btn" data-section="coordination">填写协调服务器${icon('chevron')}</button>`}`;};
coordinationFields=function(){return `<label class="field"><span>HTTPS 协调服务器</span><input data-key="url" value="${esc(drafts.coordination.url)}" placeholder="https://coord.example.com/" spellcheck="false" autocomplete="off"><span class="hint">自主打洞采用服务器配对时，两端填写相同地址。已有入口直接配对，不使用此项。</span></label>`;};
baseSectionFields=function(){
 if(section==='host'){const d=drafts.host;return `<div class="switch-row"><div><h3>本机提供协调服务</h3><p class="hint">供选用本机地址的设备配对和交换候选，不承载串流。</p></div>${switchControl('enabled',d.enabled,'本机提供协调服务')}</div>${[['listenUrl','监听地址'],['publicUrl','外部 HTTPS 地址'],['certificateFile','本机证书文件'],['certificateKeyFile','本机私钥文件'],['publicCertificatePin','外部证书 SHA-256 指纹']].map(([key,label])=>`<label class="field"><span>${label}</span><input data-key="${key}" value="${esc(d[key])}" autocomplete="off"></label>`).join('')}<div class="switch-row"><span>仅信任本机 Cloudflare Tunnel 转发的来源信息</span>${switchControl('trustCloudflare',d.trustCloudflare,'信任本机 Tunnel')}</div><p class="hint">${esc(workspaceState?.coordinator?.state||'状态尚未读取')}。HTTP 仅允许本机监听，公网使用 HTTPS 或反向代理。</p>`;}
 if(section==='identity')return `<label class="field"><span>本机设备名称</span><input data-key="name" value="${esc(drafts.identity.name)}" maxlength="64"><span class="hint">虚拟 IP 由各条网络独立分配，避免多网络地址冲突。</span></label>`;
 return legacy.baseSectionFields();
};
entryOwnerOptions=function(d){return [['local','本机入口 · 供其他设备连接'],['target','目标主机的入口 · 用于连接到目标主机。']].map(([v,n])=>`<option value="${v}" ${d.owner===v?'selected':''}>${n}</option>`).join('');};
const originalConfigFromStatus=configFromStatus;
configFromStatus=function(s){const c=originalConfigFromStatus(s),p=s.settings||{};c.host={...defaults.host,...p.coordinator};c.network.coordinatorBackup=!!p.coordinatorBackup;c.network.pkarrPublish=!!p.pkarrPublish;if(p.connectionSource!=='existing'&&(p.discoveryMode==='pkarr'||!p.discoveryMode&&p.directMode&&p.pkarrPublish))c.network.route='pkarr';return c;};
const originalSettingsDto=settingsDto;
settingsDto=function(){const p=originalSettingsDto();return {...p,coordinator:{...defaults.host},ddns:null,pkarrPublish:!!drafts.network.pkarrPublish,coordinatorBackup:drafts.network.mode==='existing'&&!!drafts.network.coordinatorBackup,directMode:drafts.network.mode==='existing'||drafts.network.route==='direct',sourcePort:configuration()?.settings.sourcePort||44691,requestedVirtualIp:'',existingEntries:p.existingEntries.filter(e=>e.peerSlot===0||e.peerSlot===-1)};};
const originalValidateSection=validateSection;
validateSection=function(key,configuration=drafts){if(key==='coordination'&&configuration.network.mode==='existing'){if(configuration.network.coordinatorBackup&&!configuration.coordination.url.trim())return '启用备用协调后，请填写 HTTPS 协调服务器。';if(!configuration.network.coordinatorBackup)return '';}if(key==='host')return '';const wasActive=networkActive;networkActive=false;try{return originalValidateSection(key,configuration);}finally{networkActive=wasActive;}};
const entryNetworkFields=networkFields;
networkFields=function(){
 const html=entryNetworkFields(),d=drafts.network;if(d.mode!=='existing')return html;
 const backup=`<div class="switch-row"><div><h3>备用协调服务器</h3><p class="hint">优先使用已填写的入口；失败后查询主机最新地址。两端需开启并填写同一个协调地址，不执行自主打洞。</p></div>${switchControl('coordinatorBackup',!!d.coordinatorBackup,'备用协调服务器')}</div>${d.coordinatorBackup?`<button class="text-btn" data-section="coordination">填写备用协调地址${icon('chevron')}</button>`:''}`;
 return html.replace('<label class="field"><span>这些入口属于</span>',backup+'<label class="field"><span>这些入口属于</span>');
};
coordinationFields=function(){return `<label class="field"><span>HTTPS 协调服务器</span><input data-key="url" value="${esc(drafts.coordination.url)}" placeholder="https://conwu.space4sgsa.com/" spellcheck="false" autocomplete="off"><span class="hint">${drafts.network.mode==='existing'?(drafts.network.coordinatorBackup?'双方填写相同地址。主机发布已有入口，入口连接失败时从这里查询；串流仍由两端直接传输。':'已有入口当前未开启备用协调。填写的地址会保存，开启备用协调后使用。'):'自主打洞采用服务器配对时，两端填写相同地址。'}</span></label>`;};
let aggregateTraffic=null;
overviewPage=function(){
 const all=workspaceState?.networks||[],a=workspaceState?.aggregate,connected=all.filter(n=>n.status.directPeers>0).length;
 return heading('概况','全部双机网络的连接状态与流量。')+`<div class="two-col"><article class="card pad"><h2>${connected?'与其余 '+connected+' 台设备直连':'等待设备连接'}</h2><p class="card-lead">${all.length} 个网络 · ${all.filter(n=>n.status.networkEnabled&&!n.status.directPeers).length} 个等待连接</p><div class="method-rows"><div class="method-row"><span>累计上传</span><strong>${total(a?.sentBytes||0)}</strong></div><div class="method-row"><span>累计下载</span><strong>${total(a?.receivedBytes||0)}</strong></div><div class="method-row"><span>实时上传／下载</span><span>${speed(aggregateTraffic?.up)} ／ ${speed(aggregateTraffic?.down)}</span></div></div></article><article class="card pad"><h2>${esc(localName())}</h2><p class="card-lead">本机同时可以创建和加入不同网络。</p><div class="row wrap"><button class="btn primary" data-workspace="create-network">${icon('plus')}创建网络</button><button class="btn" data-workspace="join-network">${icon('join')}加入网络</button></div></article></div><article class="card table-card"><div class="pad"><h2>设备与网络</h2></div><div class="table-scroll"><table><thead><tr><th>设备／网络</th><th>虚拟 IP</th><th>连接状态</th><th>延迟</th><th>流量</th><th>操作</th></tr></thead><tbody><tr><td>${esc(localName())}</td><td class="mono">${all.length?all.map(n=>esc(n.status.virtualIp||'待分配')).join('<br>'):'尚未分配'}</td><td colspan="4">本机</td></tr>${all.map(n=>{const s=n.status,p=s.peers[0],live=online&&p?.connected,c=(workspaceState.configurations||[]).find(c=>c.id===n.configurationId);return `<tr><td><strong>${esc(p?.name||'等待另一台设备')}</strong><div class="peer-sub">${esc(n.name)} · 本机为${s.isOwner?'主机':'从机'}<br>配置：${esc(c?.name||'待确认')}</div></td><td class="mono">${esc(p?.virtualIp||'待分配')}</td><td>${live?'已直连':s.networkEnabled?'连接中':'已停止'}<div class="peer-sub">${s.settings?.pathSelection==='udp-only'?'直接 UDP':'FakeTCP + HTTP'}<br>${live?'已直连时间：'+`<span data-network-duration="${Math.max(0,p.connection?.elapsedMs??(Date.now()/1000-(p.connectedSince||Date.now()/1000))*1000)}" data-duration-sample="${performance.now()}">${connectedDuration(p.connection?.elapsedMs??(Date.now()/1000-(p.connectedSince||Date.now()/1000))*1000)}</span>`:esc(p?.connection?.detail||s.connection?.detail||s.state)}<br>实际入口：${p?esc(p.outerTarget&&p.outerTarget!=='Unknown'?p.outerTarget:p.entryDirection==='Inbound'?'入站直连 · 本机接收端口 '+s.settings.listenPort:'尚未取得已认证入口信息'):'待验证'}</div></td><td>${p?.rttMs==null?'—':p.rttMs.toFixed(1)+' ms'}</td><td>↑ ${total(p?.sentBytes||0)}<br>↓ ${total(p?.receivedBytes||0)}</td><td><button class="text-btn" data-workspace="view-network" data-network-id="${esc(n.id)}">管理</button></td></tr>`;}).join('')}</tbody></table></div></article>`;
};
const originalNavigate=navigate;
openSettings=function(next='network'){rememberDraft();settingsScope=deviceGroups.includes(next)?'device':'configuration';section=next;hydrateEditor();originalNavigate('settings');};
navigate=function(next){if(['settings','create','join'].includes(next)&&workspaceState){rememberDraft();if(next!=='settings')settingsScope='configuration';hydrateEditor();}originalNavigate(next);};
methodCard=function(){return `<article class="card pad"><div class="row between"><h2>当前连接方式</h2><button class="text-btn" data-settings="network">更改</button></div><div class="method-rows"><div class="method-row"><span>连接策略</span><span>${saved.network.mode==='existing'?'只使用已有入口':'自主打洞'}</span></div><div class="method-row"><span>配对方式</span><span>${saved.network.mode==='existing'?'入口直接配对':activeRoute()==='direct'?'直连邀请':'HTTPS 协调＋配对码'}</span></div><div class="method-row"><span>连接协议</span><span>${protocol()}</span></div></div></article>`;};
const originalConnectedTimes=updateConnectedTimes;
updateConnectedTimes=function(){originalConnectedTimes();for(const element of document.querySelectorAll('[data-network-duration]'))element.textContent=connectedDuration(Number(element.dataset.networkDuration)+Math.max(0,performance.now()-Number(element.dataset.durationSample)));};
const originalJoinMethodHelp=joinMethodHelp;
joinMethodHelp=function(){const existing=saved.network.mode==='existing';if(!existing)return originalJoinMethodHelp();return `<details class="card disclosure-card" id="join-help"><summary>怎么加入</summary><div class="pad"><p>在当前配置中填写目标主机入口，例如 <code>txt://entry.example.com#streamlink1</code>，再输入该主机生成的六位配对码。</p><p>申请直接发送到主机上的 ConWU；双方核对校验码后，由主机同意或拒绝。无需协调服务器。</p></div></details>`;};
const originalBindJoinInput=bindJoinInput;
bindJoinInput=function(){const direct=pairingKind()==='invite',input=$(direct?'join-invite':'join-code');if(!input)return;input.oninput=()=>{if(direct)joinInviteValue=input.value;else{joinCodeValue=input.value.replace(/\D/g,'').slice(0,6);input.value=joinCodeValue;input.closest('.digits-input').querySelectorAll('.digit').forEach((e,i)=>{e.textContent=joinCodeValue[i]||'';e.classList.toggle('filled',!!joinCodeValue[i]);});}joinError='';if($('join-error'))$('join-error').textContent='';};if($('join-device-name'))$('join-device-name').oninput=e=>joinName=e.target.value;$('join-form').onsubmit=e=>{e.preventDefault();run(joinNetwork).catch(()=>{});};};
api=async function(path,body,valid,sessionRetried){
 if(path.startsWith('/api/status')&&selectedNetwork&&!path.includes('networkId='))path+=(path.includes('?')?'&':'?')+'networkId='+encodeURIComponent(selectedNetwork);
 if(body&&path==='/api/command'){
  body={networkId:selectedNetwork,...body};
  if(body.method==='network'&&['create','create-direct','join','join-target','join-direct-short','join-invitation','join-entry'].includes(body.network?.action))body={...body,networkId:'',network:{...body.network,configurationId:body.network.autoConfigure?'':selectedConfiguration,requestedVirtualIp:body.network.autoConfigure?'':newNetworkIp.trim(),name:body.network.name||newNetworkName}};
 }
 if(location.pathname.startsWith('/admin/')&&path.startsWith('/api/'))path='/admin'+path;
 const response=await legacy.api(path,body,valid,sessionRetried);
 if(body?.method==='network'&&['create','create-direct','join','join-target','join-direct-short','join-invitation','join-entry'].includes(body.network?.action)&&response.status?.selectedNetworkId)selectedNetwork=response.status.selectedNetworkId;
 return response;
};
render=function(next){
 const observed=!!next;if(!next&&workspaceState)next=workspaceState;
 if(next?.workspaceVersion){
  workspaceState=next;if(selectedNetwork&&!next.networks.some(n=>n.id===selectedNetwork))selectedNetwork='';
  if(!selectedConfiguration&&!configurationName)selectedConfiguration=next.configurations?.[0]?.id||'';
  if(selectedConfiguration&&!configuration())selectedConfiguration=next.configurations?.[0]?.id||'';
  const config=configuration();if(config&&!configurationRevision){configurationRevision=config.revision;configurationName=baseConfigurationName=config.name;}
  if(config&&configurationRevision!==config.revision&&!dirtyCount()&&!configurationNameDirty()){configurationRevision=config.revision;configurationName=baseConfigurationName=config.name;configurationDrafts.delete(selectedConfiguration);settingsHydrated=false;}
  const a=next.aggregate,now=performance.now();if(a&&observed){const previous=aggregateTraffic;aggregateTraffic={time:now,sent:a.sentBytes,received:a.receivedBytes,up:previous&&a.sentBytes>=previous.sent&&now-previous.time>=100&&now-previous.time<10000?(a.sentBytes-previous.sent)/(now-previous.time)*1000:null,down:previous&&a.receivedBytes>=previous.received&&now-previous.time>=100&&now-previous.time<10000?(a.receivedBytes-previous.received)/(now-previous.time)*1000:null};}
  const chosen=next.networks.find(n=>n.id===selectedNetwork)?.status;
  next=page==='settings'||!chosen?settingsScope==='device'?{...next,settings:next.deviceSettings}:localConfigurationStatus(next):{...next,...chosen,networks:next.networks,aggregate:next.aggregate,configurations:next.configurations};
 }
 for(const d of document.querySelectorAll('#content details'))disclosures.set(renderedPage+'|'+renderedConfiguration+'|'+(d.id||d.querySelector('summary')?.textContent),d.open);
 if(!observed&&next){state=next;networkActive=!!state.networkId;owner=!!state.isOwner;createdAt=(state.networkEstablishedAt||0)*1000;legacy.render();}else legacy.render(next);
 for(const d of document.querySelectorAll('#content details')){const key=page+'|'+selectedConfiguration+'|'+(d.id||d.querySelector('summary')?.textContent);if(disclosures.has(key))d.open=disclosures.get(key);}
 renderedPage=page;renderedConfiguration=selectedConfiguration;
};
updateShell=function(){legacy.updateShell();document.title=titles[page]+' · ConWU';const all=workspaceState?.networks||[],live=all.filter(n=>n.status.directPeers>0).length;$('sidebar-state').innerHTML=`<div class="row"><span class="dot ${live?'':'amber'}"></span><span>${all.length} 个网络</span></div><div class="small dim">与其余 ${online?live:0} 台设备直连</div>`;const requests=all.filter(n=>n.status.pairing?.active&&n.status.pairing.owner&&n.status.pairing.candidate);$('request-dot').hidden=!requests.length;document.querySelector('.nav[data-page="join"]').setAttribute('aria-label',requests.length?'加入网络，有 '+requests.length+' 条新申请':'加入网络');};
controls=function(){legacy.controls();const ready=online&&!expired&&state?.serviceReady&&!busy;
 if(page==='settings')networkActive=false;
 const create=document.querySelector('[data-action="create"]');if(create)create.disabled=!ready||!!selectedNetwork;
 if($('join-submit'))$('join-submit').disabled=!ready||!!selectedNetwork;
 if($('save-section'))$('save-section').disabled=!ready||!dirtyCount()&&!configurationNameDirty()&&!!selectedConfiguration;
 if($('configuration-name'))$('configuration-name').disabled=busy;
 const confirm=document.querySelector('[data-workspace="delete-configuration"]');if(confirm){confirm.disabled=busy||!!configuration()?.networks.length;confirm.title=configuration()?.networks.length?'请先让关联网络改用其他配置或移除网络':'';}
 for(const button of document.querySelectorAll('[data-request-network]')){const pairing=workspaceState?.networks.find(n=>n.id===button.dataset.requestNetwork)?.status.pairing;button.disabled=!ready||!pairing?.candidate||button.dataset.action==='approve'&&!pairing.verification;}
 if($('save-state')&&configurationNameDirty())$('save-state').textContent='配置名称有未保存修改';
};
dirtyCount=()=> (settingsScope==='device'?deviceGroups:configurationGroups).filter(dirty).length+(configurationNameDirty()?1:0)+(settingsScope==='configuration'&&!selectedConfiguration&&configurationName?1:0);
refreshSettingsTools=function(){
 if(!['settings','create'].includes(page)||!$('save-state'))return;const count=dirtyCount();$('save-state').className='save-state'+(count?' dirty':'');$('save-state').textContent=settingsScope==='configuration'&&!selectedConfiguration?'新配置尚未保存':count?count+' 个部分未保存':'已保存';
 for(const element of document.querySelectorAll('[data-section-dot]'))element.hidden=!dirty(element.dataset.sectionDot);
 $('settings-dirty-dot').hidden=!count;controls();
};
saveSection=async function(){
 const groups=settingsScope==='device'?deviceGroups:configurationGroups;
 for(const key of groups){const error=validateSection(key);if(error){section=key;render();$('settings-error').textContent=error;return false;}}
 if(settingsScope==='device'){
  const original=workspaceState.deviceSettings;const action={action:'settings',settings:{...original,coordinator:clone(drafts.host),ddns:null},expectedRevision:workspaceState.deviceSettingsRevision,confirmReplace:true,patch:{deviceName:drafts.identity.name.trim(),expectedDeviceName:workspaceState.deviceName,logLevel:drafts.logging.level,expectedLogLevel:workspaceState.logLevel}};
  if(drafts.system.startup!==saved.system.startup){action.autoStart=drafts.system.startup;action.expectedAutoStart=saved.system.startup;}
  await command('save-settings',{networkId:'',settingsBatch:{device:action,networks:[]}});
 }else{
  if(!configurationName.trim())throw Error('请输入配置名称。');const users=configuration()?.networks||[];
  if(users.length&&!await confirmAction('保存并更新关联网络？','将更新：'+users.map(n=>n.name).join('、')+'。协议、端口或连接策略变化会重连；不兼容的修改会给出原因。','保存并应用'))return false;
  let reply;try{reply=await command('configuration',{networkId:'',configuration:{action:'save',id:selectedConfiguration,name:configurationName.trim(),expectedRevision:configurationRevision,settings:settingsDto(),confirmReconnect:true}});}catch(error){if(error.message.startsWith('配置已保存')){configurationDrafts.delete(selectedConfiguration);configurationRevision=configuration()?.revision||configurationRevision;hydrateEditor();render();}throw error;}
  selectedConfiguration=reply.configurationId||selectedConfiguration;
 }
 configurationDrafts.delete(settingsScope==='device'?'device':selectedConfiguration);configurationRevision=configuration()?.revision||0;settingsHydrated=false;hydrateEditor();render();notify(settingsScope==='device'?'本机设置已保存':'配置已保存，关联网络状态已更新');return true;
};
createNetwork=async function(){if(selectedNetwork)throw Error('请选择“创建另一条网络”。');if(dirtyCount()||configurationNameDirty()||!selectedConfiguration){if(!await saveSection())return;}const p=configuration()?.settings;if(!p)throw Error('请先保存连接配置。');if(!p.directMode&&!p.service)throw Error('请在配置中填写 HTTPS 协调服务器，或选择无协调直连邀请。');await network(p.directMode?'create-direct':'create',{service:p.service,certificatePin:p.certificatePin,mode:p.pathSelection==='udp-only'?'udp':'faketcp',expectedNetwork:'',name:newNetworkName});settingsHydrated=false;render();notify('网络已创建');};
generate=async function(){const action=state?.networkDirect&&saved.network.mode==='existing'?'invite-short':'invite';await network(action,{expectedNetwork:state.networkId});notify(action==='invite-short'?'配对码已生成':state.networkDirect?'直连邀请已生成':'配对码已生成');};
joinNetwork=async function(){
 if(selectedNetwork)throw Error('请选择“加入另一条网络”。');if(dirtyCount()||configurationNameDirty()||!selectedConfiguration){if(!await saveSection())return;}
 const p=configuration().settings,invite=pairingKind()==='invite',code=(invite?joinInviteValue:joinCodeValue).replace(/\s/g,'');if(invite?!code.startsWith('SL6.'):!/^\d{6}$/.test(code))throw Error(invite?'请输入主机生成的直连邀请。':'请输入六位数字配对码。');
 const name=(joinName||localName()).trim();if(name!==workspaceState.deviceName)await command('patch',{networkId:'',patch:{deviceName:name,expectedDeviceName:workspaceState.deviceName}},true);
 const action=invite?'join-invitation':p.connectionSource==='existing'?'join-direct-short':'join';submittedJoin={code,direct:invite};await network(action,{service:p.service,certificatePin:p.certificatePin,code,expectedNetwork:'',mode:p.pathSelection==='udp-only'?'udp':'faketcp'});notify('申请已发送，等待主机批准');
};
leaveNetwork=async function(){
 if(!selectedNetwork)return;const row=workspaceState.networks.find(n=>n.id===selectedNetwork);if(!row)return;
 if(!await confirmAction(row.status.isOwner?'删除此网络？':'退出此网络？',row.name+'：将停止此网络，已保存配置保留。','确认','danger'))return;
 try{await network(row.status.isOwner?'delete-network':'leave',{expectedNetwork:row.status.networkId,confirmReplace:true});}
 catch(error){if(!await confirmAction('远端尚未确认','可以仅移除本机记录，保留配置；这不代表远端授权已撤销。原因：'+error.message,'仅从本机移除','danger'))return;await network('forget-network',{expectedNetwork:row.status.networkId,confirmReplace:true});}
 selectedNetwork='';settingsHydrated=false;hydrateEditor();render();notify('本机网络已移除，配置保留');
};
restoreSettings=function(){configurationDrafts.delete(settingsScope==='device'?'device':selectedConfiguration||'new');settingsHydrated=false;hydrateEditor();render();notify('未保存修改已还原');};
resetDefaults=function(){ask('恢复当前设置的默认值？','仅填入当前配置或本机设置的默认值，保存后生效。','填入默认值',()=>{for(const key of settingsScope==='device'?deviceGroups:configurationGroups)drafts[key]=clone(defaults[key]);if(settingsScope==='device')drafts.identity.name=workspaceState.deviceName;render();});};
document.addEventListener('input',e=>{if(e.target.id==='configuration-name'){configurationName=e.target.value;controls();}if(e.target.id==='new-network-name')newNetworkName=e.target.value;if(e.target.id==='new-network-ip')newNetworkIp=e.target.value;});
document.addEventListener('change',e=>{if(e.target.matches('[data-configuration-select]'))chooseConfiguration(e.target.value);if(e.target.id==='workspace-network'){rememberDraft();selectedNetwork=e.target.value;const row=workspaceState.networks.find(n=>n.id===selectedNetwork);if(row)selectedConfiguration=row.configurationId;settingsHydrated=false;if(row)configurationDrafts.delete(selectedConfiguration);hydrateEditor();void refresh();render(workspaceState);}});
document.addEventListener('click',e=>{
 const button=e.target.closest('[data-workspace]');if(!button)return;e.preventDefault();run(async()=>{switch(button.dataset.workspace){
  case 'new-configuration':rememberDraft();selectedConfiguration='';configurationName='新配置';configurationDrafts.delete('new');hydrateEditor();section='network';navigate('settings');break;
  case 'configuration-scope':rememberDraft();settingsScope='configuration';section='network';hydrateEditor();render();break;
  case 'device-scope':rememberDraft();settingsScope='device';section='system';hydrateEditor();render();break;
  case 'edit-configuration':section='network';navigate('settings');break;
  case 'new-network':case 'create-network':case 'join-network':rememberDraft();newNetworkIp='';selectedNetwork='';settingsScope='configuration';hydrateEditor();navigate(button.dataset.workspace==='join-network'?'join':'create');render(workspaceState);break;
  case 'view-network':rememberDraft();selectedNetwork=button.dataset.networkId;selectedConfiguration=workspaceState.networks.find(n=>n.id===selectedNetwork).configurationId;hydrateEditor();page='create';render(workspaceState);break;
  case 'remove-locally':{const row=workspaceState.networks.find(n=>n.id===selectedNetwork);if(!await confirmAction('仅从本机移除？','停止 '+row.name+'，保留配置，不声称远端已撤销。','移除','danger'))return;await network(row.status.networkId?'forget-network':'remove-network',{expectedNetwork:row.status.networkId,confirmReplace:true});selectedNetwork='';hydrateEditor();render(workspaceState);break;}
  case 'assign-configuration':{const c=configuration();if(!await confirmAction('更换网络使用的配置？','仅更换当前网络的配置引用，需要时重新连接。','应用'))return;await command('configuration',{networkId:selectedNetwork,configuration:{action:'assign',id:c.id,expectedRevision:c.revision,confirmReconnect:true}});notify('当前网络已改用此配置');break;}
  case 'copy-configuration':{const c=configuration();const reply=await command('configuration',{networkId:'',configuration:{action:'copy',id:c.id,expectedRevision:c.revision,name:c.name+' 副本',settings:settingsDto()}});chooseConfiguration(reply.configurationId);notify('已复制为独立配置，现有网络仍使用原配置');break;}
  case 'delete-configuration':{const c=configuration();if(!await confirmAction('删除配置？',c.name+'；未关联网络。','删除','danger'))return;await command('configuration',{networkId:'',configuration:{action:'delete',id:c.id,expectedRevision:c.revision}});configurationDrafts.delete(c.id);selectedConfiguration=workspaceState.configurations[0]?.id||'';hydrateEditor();render();break;}
  case 'apply-configuration':{const c=configuration();await command('configuration',{networkId:'',configuration:{action:'apply',id:c.id,expectedRevision:c.revision,confirmReconnect:true}});break;}
 }}).catch(()=>{});
});

incomingPage=function(){const requests=(workspaceState?.networks||[]).filter(n=>n.status.pairing?.active&&n.status.pairing.owner&&n.status.pairing.candidate);return requests.length?requests.map(n=>{const p=n.status.pairing;return `<article class="card pad request-card"><h2>${esc(p.peerName)}</h2><p class="card-lead">申请加入 ${esc(n.name)}</p><div class="request-meta"><div><span>预分配 IP</span><strong class="mono">${esc(p.proposedIp||'等待分配')}</strong></div><div><span>校验码</span><strong class="mono">${esc(p.verification)}</strong></div></div><p class="hint">请核对双方校验码一致，再批准加入。</p><div class="row"><button class="btn positive" data-action="approve" data-request-network="${esc(n.id)}">同意加入</button><button class="btn danger" data-action="reject" data-request-network="${esc(n.id)}">拒绝</button></div></article>`;}).join(''):`<article class="card pad empty-state"><h2>暂无加入申请</h2><p>各条网络收到的申请会在这里显示。</p></article>`;};
document.addEventListener('click',e=>{const button=e.target.closest('[data-request-network]');if(!button)return;rememberDraft();selectedNetwork=button.dataset.requestNetwork;const row=workspaceState.networks.find(n=>n.id===selectedNetwork);selectedConfiguration=row.configurationId;hydrateEditor();state={...state,...row.status};},true);
let pairPollCursor=0;
pollPair=async function(){
 if(!online||busy||Date.now()-lastPairPoll<2000)return;
 const pending=(workspaceState?.networks||[]).filter(n=>n.status.pairing?.active&&!n.status.pairing.direct);if(!pending.length)return;
 const target=pending[pairPollCursor++%pending.length];lastPairPoll=Date.now();
 try{await command('network',{networkId:target.id,network:{action:'pair-poll'}},true);if(noticeSource==='pair')notice('');}
 catch(error){if(error.message!==lastPairError){lastPairError=error.message;notice(target.name+'：'+error.message,true,'pair');}}
};
