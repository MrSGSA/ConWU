'use strict';
const $=id=>document.getElementById(id),esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),icon=name=>`<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`,clone=x=>JSON.parse(JSON.stringify(x)),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const titles={overview:'概况',create:'创建网络',join:'加入网络',logs:'日志',settings:'设置'},sectionNames={system:'启动与服务',identity:'本机设置',network:'连接设置',coordination:'协调服务器',publish:'提供网络入口',host:'本机协调服务',ddns:'域名自动发现',port:'端口设置',certificate:'证书设置',stun:'STUN 服务器',logging:'日志设置'},sectionIcons={system:'monitor',identity:'laptop',network:'link',coordination:'server',publish:'link',host:'server',ddns:'globe',port:'port',certificate:'shield',stun:'globe',logging:'log'};
const defaults={system:{startup:true},identity:{name:'',ipMode:'auto',ip:''},network:{protocol:'faketcp',mode:'custom',route:'server',existingRoute:'server',owner:'target',entries:{target:['']},refresh:60,unit:1},coordination:{url:''},publish:{sources:['']},host:{enabled:false,listenUrl:'http://127.0.0.1:47822',certificateFile:'',certificateKeyFile:'',trustCloudflare:false,publicUrl:'',publicCertificatePin:''},ddns:{enabled:false,domain:'',zoneId:'',publish:false,refreshSeconds:60,newToken:'',clearToken:false},port:{listen:44680},certificate:{pin:''},stun:{tcp:'',udp:''},logging:{level:'info',terminal:'auto'}};
const heading=(title,description,extra='')=>`<div class="heading"><div><h1 id="page-title">${title}</h1><p>${description}</p></div>${extra}</div>`;
let state=null,online=false,busy=false,busyKind='',expired=false,csrf='',reading=null,generation=0,lastStatusAt=0,baseRevision='',saved=clone(defaults),drafts=clone(saved),history=null;
let page='overview',section='network',networkActive=false,owner=false,pairCode='',pairExpires=0,invitation='',inviteExpires=0,joinTab='outgoing',joinCodeValue='',joinInviteValue='',joinStatus='',joinName='',joinError='',incoming=false,createdAt=0,theme='dark',toastTimer,testTimer,testGeneration=0,modalCallback=null,networkRoute='server';
let previousTraffic=null,traffic={peers:new Map(),up:null,down:null},historyTraffic=[],logLines=[],lastLogs=[],lastPairPoll=0,lastPairError='',pairNotice='',pairNoticeTimer,joinModel='',settingsHydrated=false;
let noticeSource='',noticeTimer,lastStatusFailure='',resumeGraceUntil=0,submittedJoin=null,pairPolling=null;
const settingGroups={identity:{title:'本机设置',icon:'laptop',keys:['identity'],lead:'给这台设备一个熟悉的名字。'},network:{title:'连接设置',icon:'link',keys:['network','coordination','certificate'],lead:'选择传输协议，按需使用协调入口。'},port:{title:'端口设置',icon:'port',keys:['port','publish','host'],lead:'每台 ConWU 都可以接收连接。'},ddns:{title:'DDNS',icon:'globe',keys:['ddns'],lead:'用一个域名自动发现自己的设备。'},more:{title:'更多设置',icon:'settings',keys:['system','logging','stun'],lead:'启动、日志和少用的网络选项。'}};
let joinEntryValue='',joinEntryMethod='entry',ddnsTokenVisible=false,revealedDdnsToken='',ddnsTokenReading=false,ddnsTokenReadGeneration=0;
const expanded=new Set(),dirty=key=>!same(drafts[key],saved[key]),dirtyCount=()=>Object.keys(settingGroups).filter(group=>settingGroups[group].keys.some(dirty)).length,localName=()=>state?.deviceName||'正在读取',localIp=()=>state?.virtualIp||'尚未分配',activeRoute=()=>networkActive?(state?.networkDirect?'direct':'server'):saved.coordination.url.trim()?'server':'direct',protocol=()=>saved.network.protocol==='udp'?'直接 UDP':'FakeTCP + HTTP';
const total=value=>value>=1e9?(value/1e9).toFixed(2)+' GB':value>=1e6?(value/1e6).toFixed(1)+' MB':value>=1000?(value/1000).toFixed(1)+' KB':Math.max(0,value||0)+' B';
const speed=value=>value==null?'—':(value/1e6).toFixed(2)+' MB/s',duration=ms=>{let n=Math.max(0,Math.floor(ms/1000));return String(Math.floor(n/60)).padStart(2,'0')+':'+String(n%60).padStart(2,'0');};
const connectedDuration=ms=>{const seconds=Math.max(0,Math.floor(ms/1000));return `${Math.floor(seconds/86400)} 天 ${String(Math.floor(seconds/3600)%24).padStart(2,'0')} 时 ${String(Math.floor(seconds/60)%60).padStart(2,'0')} 分 ${String(seconds%60).padStart(2,'0')} 秒`;};
function connectedTime(p){return online&&p.connected&&p.connection?.phase==='Connected'?connectedDuration((p.connection.elapsedMs||0)+Math.max(0,performance.now()-lastStatusAt)):'—';}
function updateConnectedTimes(){for(const element of document.querySelectorAll('[data-connected-slot]')){const peer=state?.peers.find(p=>p.slot===Number(element.dataset.connectedSlot));element.textContent=peer?connectedTime(peer):'—';}}
function entryDescription(p){if(p.outerTarget&&p.outerTarget!=='Unknown')return p.outerTarget;return p.entryDirection==='Inbound'?`入站直连 · 本机接收端口 ${state?.settings?.listenPort||'—'}`:'尚未取得已认证入口信息';}
const phaseNames={Idle:'网络已就绪',Offline:'设备未在线',StartingAdapter:'准备虚拟网卡',WaitingPeer:'等待设备响应',WaitingEntry:'寻找入口',EntryUnavailable:'已有入口不可用',Connecting:'正在连接',Queued:'排队连接',Preparing:'准备直连',Verifying:'验证直连',Releasing:'回收资源',Blocked:'需要处理',Recovering:'恢复连接',Retrying:'等待重试',Connected:'已直连'};
try{theme=localStorage.getItem('streamlink-theme')==='light'?'light':'dark';}catch{}

function notify(message){clearTimeout(toastTimer);$('toast').innerHTML=icon('check')+`<span>${esc(message)}</span>`;$('toast').classList.add('show');toastTimer=setTimeout(()=>$('toast').classList.remove('show'),3400);}

function ask(title,description,label,callback){$('dialog-title').textContent=title;$('dialog-description').textContent=description;$('dialog-confirm').textContent=label;modalCallback=callback;$('confirm-dialog').showModal();$('dialog-cancel').focus();}

function closeDialog(confirmed){const callback=modalCallback;modalCallback=null;$('confirm-dialog').close();if(confirmed)callback?.();}

function navigate(next){hideDdnsToken();page=titles[next]?next:'overview';render();window.scrollTo({top:0,behavior:'instant'});}

function openSettings(next='network'){section=settingGroup(next);navigate('settings');}

function methodCard(){return `<details class="card disclosure-card"><summary><span class="disclosure-title">${icon('link')}<strong>当前怎么连接</strong></span><span class="disclosure-indicator">展开${icon('chevron')}</span></summary><div class="disclosure-content"><div class="method-rows"><div class="method-row"><span>连接方式</span><span>${networkActive?state?.networkDirect?'可达入口':'HTTPS 协调':saved.coordination.url?'HTTPS 协调或可达入口':'可达入口'}</span></div><div class="method-row"><span>连接协议</span><span>${protocol()}</span></div></div></div></details>`;}

function codeDigits(code){return `<div class="digits">${Array.from({length:6},(_,i)=>`<span class="digit ${code[i]?'filled':''}">${esc(code[i]||'')}</span>`).join('')}</div>`;}

function pairMethodTabs(context){const direct=activeRoute()==='direct',reason=direct?'当前为无服务器连接，配对码不可用。':'当前使用协调服务器，直连邀请不可用。';return `<div class="pair-method-tabs" role="tablist" aria-label="${context==='join'?'加入':'邀请'}方式"><button type="button" role="tab" id="${context}-method-code" data-pair-method="code" aria-selected="${!direct}" aria-controls="${context}-method-panel" class="${!direct?'selected':''}" ${direct?'disabled':''} title="${direct?reason:'使用六位数字配对码'}">${icon('shield')}配对码</button><button type="button" role="tab" id="${context}-method-invite" data-pair-method="invite" aria-selected="${direct}" aria-controls="${context}-method-panel" class="${direct?'selected':''}" ${!direct?'disabled':''} title="${!direct?reason:'使用目标主机生成的直连邀请'}">${icon('link')}直连邀请</button></div>`;}

function canManage(){return state?.canManageNetwork??owner;}
function governanceNotice(){return state?.pendingMembership?'<div class="card pad" role="status"><strong>网络变更正在等待确认</strong><p>操作已保存，现有设置不会清空。请继续确认，避免重复申请或重复添加设备。</p><button class="btn primary" data-action="membership-resume">继续确认</button></div>':'';}
function createPage(){
 const direct=activeRoute()==='direct',canGenerate=networkActive&&canManage()&&online&&state?.networkEnabled&&!direct,activeCode=canGenerate&&state?.pairing?.method==='code'&&pairExpires>Date.now()?pairCode:'';
 return heading('创建网络','创建后，获准加入的设备可以直接通信。')+`<div class="two-col"><article class="card pad"><div class="row between pair-top"><div class="section-title">${icon(direct?'link':'shield')}<h2>${direct&&networkActive?'网络已就绪':'本机配对码'}</h2></div>${!direct?`<button class="btn compact" data-action="generate" ${canGenerate?'':'disabled'}>${activeCode?'重新生成':'生成配对码'}</button>`:''}</div>${direct?`<p class="card-lead">在另一台设备的“加入网络 → 可达入口”填写本机的可达地址:${esc(saved.port.listen)}，发送申请后由你同意。</p>`:`<p class="card-lead">在另一台设备上输入本机配对码。</p><div class="pair-display">${codeDigits(activeCode)}<button class="btn ghost icon-button" data-action="copy-code" ${activeCode?'':'disabled'} aria-label="复制本机配对码">${icon('copy')}</button></div><div class="hint">${activeCode?'5 分钟内有效 · 仍需你同意加入':'创建网络后可以生成。'}</div>`}<div class="form-actions"><button class="btn primary" data-action="create" ${networkActive?'disabled':''}>${icon('plus')}${networkActive?'当前已有网络':'创建网络'}</button>${networkActive&&canManage()?'<button class="btn danger" data-action="delete">解散当前网络</button>':''}${networkActive&&owner&&!state?.isDecentralized&&!direct?'<button class="btn" data-action="enable-equal">启用成员平等管理</button>':''}</div><div id="create-error" class="field-error" role="status"></div>${createdAt?`<div class="time">${icon('clock')}${state?.networkCreatedHere?'创建':'加入'}成功于 ${new Date(createdAt).toLocaleString('zh-CN',{hour12:false})}</div>`:''}</article><article class="card pad"><div class="section-title">${icon('laptop')}<h2>网络信息</h2></div><label class="field"><span>本机设备名称</span><div class="read-value">${esc(localName())}<button class="text-btn" data-settings="identity">更改</button></div></label><div class="field"><span>本机虚拟 IP</span><div class="read-value mono">${esc(localIp())}</div></div><div class="method-rows"><div class="method-row"><span>当前状态</span><span>${networkActive?state?.networkEnabled?'网络已启动':'本机连接已停止':'尚未创建'}</span></div><div class="method-row"><span>网络管理</span><span>${networkActive?state?.isDecentralized?'成员平等管理':owner?'本机管理审批':'由获准管理员管理':'创建或加入后显示'}</span></div></div></article></div><div class="bottom-grid"><details class="card disclosure-card"><summary><span class="disclosure-title">${icon('link')}<strong>接下来怎么连接？</strong></span><span class="disclosure-indicator">展开${icon('chevron')}</span></summary><div class="disclosure-content"><p class="hint">${direct?'把本机的可达地址和端口告诉另一台设备。对方填写地址、发送加入申请；你核对设备名称和双方校验码后同意。':'两端填写同一 HTTPS 协调入口，再用本机配对码发送申请。也可以在另一台设备的“可达入口”中直接填写本机可达地址和端口。'}</p></div></details>${methodCard()}</div>`;
}

function joinPage(){
 const entry=joinEntryMethod==='entry';
 return heading('加入网络','联系网络中的可达设备，发送加入申请。')+`<div class="segmented join-tabs" role="tablist" aria-label="加入网络方式"><button role="tab" data-join-tab="outgoing" data-entry-method="entry" aria-selected="${joinTab==='outgoing'&&entry}" class="${joinTab==='outgoing'&&entry?'active':''}">可达入口</button><button role="tab" data-join-tab="outgoing" data-entry-method="code" aria-selected="${joinTab==='outgoing'&&!entry}" class="${joinTab==='outgoing'&&!entry?'active':''}">配对码</button><button role="tab" data-join-tab="incoming" aria-selected="${joinTab==='incoming'}" class="${joinTab==='incoming'?'active':''}">收到的申请${incoming?' · 1':''}</button></div>${joinTab==='incoming'?incomingPage():`<div class="two-col"><article class="card pad" id="join-card">${joinStatus?waitingView():`<h2>${entry?'你要连接哪台设备？':'输入对方的配对码'}</h2><p class="card-lead">${entry?'填写可达地址或订阅链接，软件自动识别。':'双方使用同一个 HTTPS 协调入口。'}</p><form id="join-form"><label class="field"><span>${entry?'可达入口':'六位配对码'}</span>${entry?`<input id="join-entry" class="mono entry-prominent" value="${esc(joinEntryValue)}" placeholder="设备地址:端口，或 HTTPS/TXT 等订阅链接" spellcheck="false" autocomplete="off" maxlength="32768"><span class="hint">也兼容主机生成的完整直连邀请。</span>`:`<div class="digits-input">${codeDigits(joinCodeValue)}<input id="join-code" value="${esc(joinCodeValue)}" inputmode="numeric" autocomplete="off" aria-label="目标设备的六位配对码"></div>`}</label><label class="field"><span>本机设备名称</span><input id="join-device-name" value="${esc(joinName||localName())}" maxlength="64" autocomplete="off"></label><div class="form-actions"><button class="btn primary" id="join-submit" type="submit" ${networkActive?'disabled':''}>请求加入 ${icon('join')}</button></div>${networkActive?'<p class="hint">需要先退出当前网络，再加入其他网络。</p>':''}<div class="field-error" id="join-error" role="status">${esc(joinError)}</div></form>`}</article><div class="stack">${joinMethodHelp()}${methodCard()}</div></div>`}`;
}

function joinMethodHelp(){const entry=joinEntryMethod==='entry';return `<details class="card disclosure-card join-help" id="join-help"><summary><span class="disclosure-title">${icon(entry?'link':'shield')}<strong>怎么加入</strong></span><span class="disclosure-indicator">展开${icon('chevron')}</span></summary><div class="disclosure-content"><p class="hint">${entry?'填写网络中任一可达设备的 IP:端口、域名:端口或 HTTPS/TXT/DDNS 订阅链接。地址应通向对方 ConWU 接收端口；端口转发时填写外部端口。发送申请后，核对设备名称和双方校验码，再由对方同意。':'请对方生成六位配对码。双方在“设置 → 连接设置”填写同一 HTTPS 协调入口，再发送申请并核对校验码。'}</p>${entry?`<div class="inline-example mono">203.0.113.42:${esc(saved.port.listen)}<br>device.example.com:${esc(saved.port.listen)}</div>`:`<button class="text-btn" data-settings="network">查看协调入口 ${icon('chevron')}</button>`}</div></details>`;}

function lockNote(text='当前网络的配对方式已固定。需要退出当前网络后才能修改。'){return networkActive?`<div class="locked-note">${icon('lock')}<span>${text} <button class="text-btn" data-action="leave">退出网络</button></span></div>`:'';}

function settingsPage(){
 section=settingGroup(section);const count=dirtyCount(),group=settingGroups[section];
 return heading('设置','少填一点，连得简单一点。',`<span id="global-dirty-count" class="badge warm" ${count?'':'hidden'}>${count} 个部分有未保存更改</span>`)+`<div class="settings-layout"><aside class="settings-rail"><nav class="settings-nav" aria-label="设置分区">${Object.entries(settingGroups).map(([key,value])=>`<button data-section="${key}" class="${section===key?'active':''}" ${section===key?'aria-current="page"':''}>${icon(value.icon)}<span>${value.title}</span><span data-section-dot="${key}" class="dirty-mark" ${groupChanged(key)?'':'hidden'}></span></button>`).join('')}</nav><div class="settings-tools"><div id="save-state" class="save-state" role="status"></div><button class="btn primary" id="save-section" data-action="save">${icon('save')}保存全部设置</button><button class="btn" id="revert-section" data-action="revert">${icon('undo')}恢复刚才设置</button><button class="btn" id="default-section" data-action="defaults">${icon('refresh')}恢复默认设置</button><p class="settings-note">所有更改统一保存。</p></div></aside><div class="stack settings-body"><article class="card settings-panel"><div class="pad"><div class="settings-title">${icon(group.icon)}<h2>${group.title}</h2></div><p class="card-lead">${group.lead}</p><div id="settings-fields">${sectionFields()}</div><div id="settings-error" class="field-error" role="status"></div></div></article>${section==='port'?`<div class="quiet-note">${icon('shield')}<span>设备加入仍需你同意。只设置端口，不代表公网已经可达。</span></div>`:''}</div></div>`;
}

function effectiveDefaults(key){const value=clone(defaults[key]);if(networkActive&&key==='network'){value.route=saved.network.route;if(saved.network.route==='direct'){value.mode='existing';value.entries.target=clone(saved.network.entries.target);}}if(networkActive&&activeRoute()==='server'&&key==='coordination')value.url=saved.coordination.url;if(networkActive&&key==='certificate')value.pin=saved.certificate.pin;return value;}

function refreshSettingsTools(){
 if(page!=='settings')return;const count=dirtyCount(),changed=count>0;
 $('save-state').className='save-state'+(changed?' dirty':'');$('save-state').innerHTML=changed?`<span class="dot amber"></span>${count} 个部分未保存`:icon('check')+'全部已保存';
 $('save-section').disabled=!changed;$('revert-section').disabled=!changed&&(!history||same(history,saved));$('default-section').disabled=Object.keys(defaults).every(k=>same(drafts[k],effectiveDefaults(k)));
 for(const key of Object.keys(settingGroups)){const dot=document.querySelector(`[data-section-dot="${key}"]`);if(dot)dot.hidden=!groupChanged(key);}
 $('settings-dirty-dot').hidden=!changed;const badge=$('global-dirty-count');if(badge){badge.hidden=!changed;badge.textContent=count+' 个部分有未保存更改';}
 if($('port-example'))$('port-example').textContent=String(drafts.port.listen||'—');
 if($('ddns-role'))$('ddns-role').textContent=ddnsWillPublish()?'发现并发布':'仅发现';
 const clear=document.querySelector('[data-action="clear-ddns-token"]');if(clear)clear.disabled=!!drafts.ddns.clearToken||!state?.ddnsCredentialConfigured&&!drafts.ddns.newToken;
 refreshThirdPartyFields();
}

function baseSectionFields(){const d=drafts[section];if(section==='system')return `<div class="switch-row"><div><h3>开机启动</h3><p class="hint">登录 Windows 后启动托盘，后台连接由服务维持。</p></div>${switchControl('startup',d.startup,'开机启动')}</div><div class="switch-row"><div><div class="row"><h3>注册为服务</h3><span class="badge ${saved.system.service?'good':''}">${saved.system.service?'已注册 · 正在运行':'尚未注册'}</span></div><p class="hint">无需保持 WebUI 打开；保存时按需请求管理员权限。</p></div>${switchControl('service',d.service,'注册为服务')}</div>`;
 if(section==='identity')return `<label class="field"><span>设备名称</span><input data-key="name" id="device-name" value="${esc(d.name)}" maxlength="64" autocomplete="off"><span class="hint">用于网络设备列表和加入申请。</span></label><div class="field"><span>虚拟 IP 分配</span><div class="radio-row"><label><input type="radio" name="ip-mode" value="auto" data-key="ipMode" ${d.ipMode==='auto'?'checked':''}>自动分配</label><label><input type="radio" name="ip-mode" value="custom" data-key="ipMode" ${d.ipMode==='custom'?'checked':''}>自定义 IP</label></div></div>${d.ipMode==='custom'?`<label class="field"><span>期望的虚拟 IP</span><input data-key="ip" class="mono" value="${esc(d.ip)}" placeholder="10.171.139.1"><span class="hint">下次创建或加入网络时生效；加入时由主机统一分配，避免网段冲突。</span></label>`:''}`;
 if(section==='network')return networkFields();
 if(section==='coordination')return coordinationFields();
 if(section==='publish')return publishFields();
 if(section==='host')return coordinatorHostFields();
 if(section==='ddns')return ddnsFields();
 if(section==='port')return `<label class="field"><span>ConWU 接收端口</span><input id="listen-port" data-key="listen" type="number" min="1024" max="65535" value="${d.listen}"><span class="hint">已有映射需要转发到这个端口，两端使用相同的连接协议。</span></label><div class="forward-path"><span>公网地址:外部端口</span>${icon('chevron')}<span>本机 IP:<strong class="mono" id="port-example">${esc(d.listen)}</strong></span></div><p class="hint" data-static-style="u1">端口被其他程序占用时，请更换端口并同步修改映射。修改后保存，已有连接会重新建立。</p>`;
 if(section==='certificate')return `<label class="field"><span>协调服务器证书指纹（可选）</span><input data-key="pin" class="mono" maxlength="64" value="${esc(d.pin)}" placeholder="SHA-256 指纹，留空使用系统证书信任" ${networkActive?'disabled':''}><span class="hint">用于校验 HTTPS 协调服务器身份。</span></label>${lockNote('当前网络的协调服务器身份已固定。需要退出当前网络后才能修改证书指纹。')}<div class="inline-note" data-static-style="u3">使用有效的公开证书时，通常留空即可。此项只影响协调服务的证书校验。</div>`;
 if(section==='stun')return `<div class="stun-grid"><label class="field"><span>TCP STUN 服务器</span><textarea data-key="tcp" wrap="off" spellcheck="false" aria-label="TCP STUN 服务器">${esc(d.tcp)}</textarea><span class="hint">FakeTCP + HTTP 自主打洞时使用。</span></label><label class="field"><span>UDP STUN 服务器</span><textarea data-key="udp" wrap="off" spellcheck="false" aria-label="UDP STUN 服务器">${esc(d.udp)}</textarea><span class="hint">手动选择直接 UDP 时使用。</span></label></div><p class="hint" data-static-style="u4">每行填写一个“主机名:端口”。留空使用内置默认列表。STUN 用于发现地址，不负责转发串流。</p>`;
 return `<label class="field"><span>日志等级</span><select data-key="level">${[['error','仅错误'],['warn','警告与错误'],['info','常规'],['debug','详细'],['off','关闭记录']].map(([v,l])=>`<option value="${v}" ${d.level===v?'selected':''}>${l}</option>`).join('')}</select><span class="hint">常规等级适合日常使用；排查问题时可临时切换为详细。</span></label><label class="field"><span>日志终端外观</span><select data-key="terminal"><option value="auto" ${d.terminal==='auto'?'selected':''}>跟随 WebUI 外观</option><option value="dark" ${d.terminal==='dark'?'selected':''}>深色终端</option><option value="light" ${d.terminal==='light'?'selected':''}>浅色终端</option></select></label><div data-static-style="u5"><button class="text-btn" data-page="logs">查看日志${icon('chevron')}</button></div>`;
}

function switchControl(key,checked,label,disabled=false){return `<label class="switch-label"><input type="checkbox" data-key="${key}" ${checked?'checked':''} ${disabled?'disabled':''} aria-label="${label}"><span class="switch-track"></span></label>`;}

function coordinationFields(){const d=drafts.coordination,required=activeRoute()==='server';return `<div class="coord-status-line"><span class="badge ${required?'blue':''}">${required?'当前使用协调服务器':'当前为无服务器直连'}</span></div><label class="field"><span>HTTPS 协调服务器</span><input id="coordination-url" data-key="url" type="text" class="mono" value="${esc(d.url)}" placeholder="https://coord.example.com/" autocomplete="off" ${networkActive&&required?'disabled':''}><span class="hint">填写自选服务器域名或 IP:端口，使用 HTTPS。组网的各台设备应填写同一个地址。</span></label>${required?lockNote('当前网络的协调服务器身份已固定。需要退出当前网络后才能更换。'):''}<div class="inline-note" data-static-style="u6">${required?'协调服务器负责配对与审批，设备仍按所选协议建立直连。':'当前连接不使用协调服务器。这里可以保留地址，供之后切换为服务器配对时使用。'}</div><div data-static-style="u7"><button class="text-btn" data-settings="network">返回连接设置${icon('chevron')}</button></div>`;}

function coordinationNotice() {
  const configured = !!drafts.coordination.url.trim(), pending = dirty('coordination');
  return `<div class="coord-notice">${icon('server')}<div class="grow"><strong>${pending ? '协调服务器有待保存的更改' : configured ? '协调服务器已配置' : '尚未配置协调服务器'}</strong><p>服务器地址在“协调服务器”中设置。${pending ? '使用“保存全部设置”可统一应用所有更改。' : '组网设备需使用同一个 HTTPS 协调地址。'}</p></div><button class="btn compact" data-settings="coordination">${configured ? '查看配置' : '前往设置'}${icon('chevron')}</button></div>`;
}

function networkFields(){const d=drafts.network;return `<label class="field"><span>连接协议</span><select data-key="protocol" id="protocol"><option value="faketcp" ${d.protocol==='faketcp'?'selected':''}>FakeTCP + HTTP</option><option value="udp" ${d.protocol==='udp'?'selected':''}>直接 UDP</option></select><span class="hint">两端使用相同协议，不自动切换。</span></label><div class="connection-story"><div class="story-item">${icon('link')}<div><strong>有可达地址，直接申请加入</strong><p>在“加入网络”粘贴设备地址或 HTTPS/TXT 等订阅链接。</p><button class="text-btn" data-page="join">前往加入网络 ${icon('chevron')}</button></div></div><div class="story-item">${icon('server')}<div><strong>使用配对码时，通过协调入口联系</strong><p>双方填写同一个 HTTPS 协调地址。</p></div></div></div>${fieldsFor('coordination',()=>`<label class="field"><span>HTTPS 协调入口（可选）</span><input id="coordination-url" data-key="url" value="${esc(drafts.coordination.url)}" placeholder="https://coord.example.com/" spellcheck="false" autocomplete="off" ${networkActive&&activeRoute()==='server'?'disabled':''}><span class="hint">使用“可达入口”加入时可以不填。</span></label>`)}<details class="plain-details"><summary>连接策略与保留入口</summary><label class="field"><span>入口获取方式</span><select data-key="mode" ${networkActive&&state?.networkDirect?'disabled':''}><option value="custom" ${d.mode==='custom'?'selected':''}>自主打洞</option><option value="existing" ${d.mode==='existing'?'selected':''}>只使用已有入口</option></select><span class="hint">自主打洞由 ConWU 获取入口；已有入口读取第三方 DDNS 和手动地址，不启动自主打洞。</span></label><div class="field"><span>保留的网络入口</span><div id="entry-rows" class="entry-rows">${d.entries.target.map((v,i)=>entryRow(v,i,d.entries.target.length)).join('')}</div><div class="test-row"><button class="btn compact" data-action="test" id="test-addresses">测试地址</button><span id="test-status" class="small muted"></span></div><div id="test-results" class="result-list"></div></div><label class="field"><span>订阅检查间隔（秒）</span><input data-source-refresh type="number" min="1" max="86400" value="${Number(d.refresh)*Number(d.unit)}"><span class="hint">地址变化后更新候选，保留健康连接。范围 1 秒至 24 小时。</span></label>${formatHelp(d)}</details><details class="plain-details"><summary>证书校验</summary>${fieldsFor('certificate')}</details>`;}

function entryCoordination(d, target) {
  const direct = d.route === 'direct';
  const description = direct
    ? target ? '已关闭：首次加入请使用直连邀请，加入后会核验并维护网络入口。' : '已关闭：本机使用已有入口，生成直连邀请。'
    : target ? '已开启：通过协调入口配对，再认证网络入口并发现成员。' : '已开启：本机通过服务器配对，已有入口负责直连。';
  return `<div class="entry-coordination" aria-label="此入口的协调方式">
    <div class="switch-row"><div><h3>使用 HTTPS 协调服务器</h3><p class="hint">${description}</p></div>${switchControl('useServer', !direct, '使用 HTTPS 协调服务器', networkActive)}</div>
    ${lockNote()}
    ${!direct ? coordinationNotice() : ''}
  </div>`;
}

function entryEditor(d, target) {
  const values = d.entries[d.owner] || [''], invitationOnly = false;
  return `<section class="entry-source-panel ${target ? 'coordination-first' : ''}" aria-labelledby="entry-source-title">
    ${target ? entryCoordination(d, target) : ''}
    <h3 class="entry-source-title" id="entry-source-title">${icon('link')}网络入口地址</h3>
    ${invitationOnly ? `<div class="inline-note entry-invite-note">请在“加入网络”中输入目标主机所生成的直连邀请链接。</div><button class="text-btn" data-page="join" data-static-style="u8">前往加入网络${icon('chevron')}</button>` : `<div id="entry-rows" class="entry-rows">${values.map((v, i) => entryRow(v, i, values.length)).join('')}</div><p class="hint">${target ? '填写这个网络中任一可达成员的 IP:端口或 HTTPS/TXT 等订阅链接。软件会验证它的成员身份，不要求它是创建者。' : '输入本机的公网地址:端口、您自己打洞得到的地址:端口或相关的更新/订阅链接。'}</p><div class="test-row"><button class="btn compact" data-action="test" id="test-addresses" ${values.some(v => v.trim()) ? '' : 'disabled'}>${icon('refresh')}测试地址</button><span class="small muted" id="test-status" role="status">${values.filter(v => v.trim()).length} 个地址来源</span></div><div id="test-results" class="result-list" aria-live="polite"></div>`}
    ${!target ? entryCoordination(d, target) : ''}
  </section>`;
}

function entryRow(value,index,length){const total=[...drafts.publish.sources,...Object.values(drafts.network.entries).flat()].filter(v=>v.trim()).length;return `<div class="entry-row"><input value="${esc(value)}" data-entry-index="${index}" aria-label="入口地址 ${index+1}" spellcheck="false" autocomplete="off" placeholder="IP:端口、域名:端口或 HTTPS/TXT 等订阅链接">${length>1?`<button class="btn icon-button remove" data-remove-entry="${index}" aria-label="删除第 ${index+1} 个地址">${icon('x')}</button>`:''}${index===length-1?`<button class="btn icon-button" data-action="add-entry" aria-label="添加入口地址" ${total>=12?'disabled':''}>${icon('plus')}</button>`:''}</div>`;}

function formatHelp(){return `<details class="plain-details"><summary>支持的格式与转发要求</summary><div class="details-body"><p>支持公网 IP:端口、域名:端口、HTTPS/TXT 等订阅，以及 ConWU 生成的签名 DDNS 入口链接。</p><pre>203.0.113.42:44680\nhttps://entry.example.com/streamlink?token=只读凭据\ntxt://entry.example.com</pre><p>订阅可以返回纯地址或 JSON 地址列表。多个应用共用一个订阅时，ConWU 地址前使用 <code>streamlink=</code>，订阅链接末尾使用 <code>#streamlink</code>。</p><p>端口转发应通向对应设备的 ConWU 接收端口，本机当前为 <code>${esc(saved.port.listen)}</code>；设备协议需要一致。接入方无需拥有公网入口。</p><p>订阅按检查间隔更新；固定地址变化时需要手动修改。只使用已有入口时不会改走自主打洞。测试地址成功表示取得候选，建立连接仍需设备认证和双向验证。</p></div></details>`;}

function bindSectionValidation(){document.querySelectorAll('#settings-fields input,#settings-fields select,#settings-fields textarea').forEach(el=>el.addEventListener('invalid',()=>{$('settings-error').textContent='请检查输入内容。';}));}

function renderFields(){
 if(!$('settings-fields'))return;section=settingGroup(section);
 const focused=document.activeElement,key=focused?.dataset?.key,group=focused?.closest('[data-settings-group]')?.dataset.settingsGroup;
 const open=new Set([...document.querySelectorAll('#settings-fields details[open]')].map(d=>d.querySelector(':scope > summary')?.textContent));
 clearTimeout(testTimer);testGeneration++;$('settings-fields').innerHTML=sectionFields();$('settings-error').textContent='';
 for(const detail of document.querySelectorAll('#settings-fields details'))if(open.has(detail.querySelector(':scope > summary')?.textContent))detail.open=true;
 refreshSettingsTools();bindSectionValidation();controls();
 if(key)document.querySelector(`#settings-fields ${group?'[data-settings-group="'+group+'"] ':''}[data-key="${CSS.escape(key)}"]`)?.focus({preventScroll:true});
}

function inputChange(el){
 if(page!=='settings')return;const key=el.dataset.key,group=el.closest('[data-settings-group]')?.dataset.settingsGroup||section;
 if(el.matches('[data-source-refresh]')){drafts.network.refresh=el.value===''?'':Number(el.value);drafts.network.unit=1;}
 else if(el.matches('[data-entry-index]')){editingEntries()[Number(el.dataset.entryIndex)]=el.value;clearTimeout(testTimer);testGeneration++;if($('test-results'))$('test-results').innerHTML='';}
 else if(key){const value=el.type==='checkbox'?el.checked:el.type==='number'?el.value===''?'':Number(el.value):el.value;drafts[group][key]=value;if(group==='identity'&&key==='ip')drafts.identity.ipMode=value.trim()?'custom':'auto';if(group==='ddns'&&key==='newToken'){drafts.ddns.clearToken=false;revealedDdnsToken='';}if(group==='host')drafts.host.enabled=true;}
 refreshSettingsTools();if($('test-addresses'))$('test-addresses').disabled=!editingEntries().some(v=>v.trim());if($('settings-error'))$('settings-error').textContent='';
}

function validateSection(key = section, configuration = drafts) {
  const d = configuration[key];
  if (key === 'identity') {
    if (!d.name.trim()) return '请输入设备名称。';
    if (d.ipMode === 'custom') { const parts = d.ip.split('.').map(Number); if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(d.ip) || parts.some(value => value > 255) || !(parts[0] === 10 || parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31 || parts[0] === 192 && parts[1] === 168)) return '请填写有效的私有 IPv4 地址，例如 10.171.139.1。'; }
  }
  if (key === 'port' && (!Number.isInteger(d.listen) || d.listen < 1024 || d.listen > 65535)) return '接收端口应为 1024～65535 之间的整数。';
  if (key === 'coordination') {
    if (d.url.trim()) { try { const url = new URL(d.url.trim()); if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) throw Error(); } catch { return '请填写有效的 HTTPS 协调服务器地址。'; } }
    if (networkActive && activeRoute() === 'server' && d.url !== saved.coordination.url) return '需要退出当前网络后才能更换协调服务器。';
  }
  if(key==='host'){
    try{const u=new URL(d.listenUrl);if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error();if(u.protocol==='http:'&&!['127.0.0.1','[::1]'].includes(u.hostname))return 'HTTP 监听仅允许本机地址；公网使用 HTTPS。';if(d.enabled&&u.protocol==='https:'&&(!d.certificateFile.trim()||!d.certificateKeyFile.trim()))return 'HTTPS 监听需要本机证书和私钥文件。';}catch{return '请填写有效的本机监听地址。';}
    if(d.publicUrl){try{const u=new URL(d.publicUrl);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||!u.pathname.endsWith('/'))throw Error();}catch{return '外部地址需为以 / 结尾的 HTTPS 地址，不能带账号或查询参数。';}}
    if(d.publicCertificatePin&&!/^[a-fA-F0-9]{64}$/.test(d.publicCertificatePin))return '外部证书指纹应为 64 位十六进制字符。';
  }
  if(key==='ddns'){
    const domain=d.domain.trim();if((d.enabled&&!domain)||domain&&(domain.length>160||!domain.includes('.')||!domain.split('.').every(label=>/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))))return '请填写完整域名，例如 conwu.space4sgsa.com，不带网址、端口或路径。';
    if(d.zoneId.trim()&&!/^[a-fA-F0-9]{32}$/.test(d.zoneId.trim())||d.enabled&&!d.clearToken&&(state?.ddnsCredentialConfigured||d.newToken.trim())&&!d.zoneId.trim())return '发布入口需要 32 位 Cloudflare Zone ID。';
    if(!Number.isInteger(Number(d.refreshSeconds))||Number(d.refreshSeconds)<30||Number(d.refreshSeconds)>600)return '检查间隔需为 30–600 秒。';
    if(d.newToken.trim()&&!/^[A-Za-z0-9_-]{20,512}$/.test(d.newToken.trim()))return '请输入有效的 Cloudflare API Token。';
    if(d.clearToken&&d.newToken.trim())return '替换令牌与清除令牌只能选择一种操作。';
  }
  if(key==='publish'&&[...d.sources,...Object.values(configuration.network.entries).flat()].filter(value=>value.trim()).length>12)return '最多保存 12 项地址来源。';
  if (key === 'network') {
    if (networkActive && !state?.networkDirect && saved.coordination.url.trim() && !configuration.coordination.url.trim()) return '需要退出当前网络后才能清空协调入口。';
    const interval = Number(d.refresh) * Number(d.unit);
    if (!Number.isInteger(interval) || interval < 1 || interval > 86400) return '自动更新间隔应为 1 秒至 24 小时。';
    if ([...configuration.publish.sources,...Object.values(d.entries).flat()].filter(value => value.trim()).length > 12) return '最多保存 12 项地址来源。';
    if (networkActive && d.route !== saved.network.route) return '需要退出当前网络后才能更改配对方式。';
  }
  if (key === 'certificate' && d.pin && !/^[a-fA-F0-9]{64}$/.test(d.pin.replace(/\s/g, ''))) return 'SHA-256 证书指纹应为 64 位十六进制字符。';
  return '';
}
async function api(path,body,valid=()=>true,sessionRetried=false){
 const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),body?.method==='register-service'?65000:body?25000:8000);
 try{
  const result=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',cache:'no-store',headers:body?{'Content-Type':'application/json','X-StreamLink-CSRF':csrf}:{},body:body?JSON.stringify(body):undefined,signal:abort.signal});
  if(!result.ok){let problem;try{problem=await result.json();}catch{}
   if(result.status===403&&problem?.code==='SessionChanged'&&body&&!sessionRetried){const session=await api('/api/session',undefined,valid);if(!session.csrf)throw Error('未取得当前面板会话，请从托盘重新打开。');csrf=session.csrf;return await api(path,body,valid,true);}
   if(result.status===401){if(valid()){expired=true;csrf='';unavailable('请从 ConWU 托盘重新打开 WebUI，后台连接继续运行。');}throw Error('面板授权已过期，请从托盘重新打开 WebUI。');}
   const error=Error(problem?.error||'请求未完成（HTTP '+result.status+'），请刷新状态后再操作。');error.retryable=[429,502,503,504].includes(result.status)&&problem?.code!=='AccessDenied';error.backendCode=problem?.code||'';throw error;
  }
  return await result.json();
 }catch(error){if(error.name==='AbortError'||error instanceof TypeError){const pending=Error('本机后台暂未响应，操作结果尚待确认；正在自动刷新。');pending.retryable=true;throw pending;}throw error;}finally{clearTimeout(timer);}
}

async function requestCommand(method,extra={},quiet=false,valid=()=>true,receive=render){
  const operationId=crypto.randomUUID();let reply;
  try{reply=await api('/api/command',{method,operationId,...extra},valid);}
  catch(error){
   if(!error.retryable||method==='register-service')throw error;
   // A lost HTTP/IPC reply does not prove that the mutation was rejected.
   // Observe the original ID; never submit that mutation a second time.
   reply={ok:true,operation:{id:operationId,completed:false,phase:'确认操作受理状态'}};
  }
  const operation=reply.operation;
  if(operation&&!operation.completed){
   if(!quiet)notice('后台正在'+(operation.phase||'处理')+'，请稍候…');
   const until=Date.now()+100000;
   while(Date.now()<until){
    if(!valid())return null;
    await new Promise(r=>setTimeout(r,700));let progress;
    if(!valid())return null;
    try{progress=await api('/api/status?operation='+encodeURIComponent(operation.id),undefined,valid);}
    catch(error){
     if(!error.retryable)throw error;
     // Retry observation only. An accepted mutation must never be resubmitted.
     if(!quiet)notice('后台已受理，暂时无法读取进度，正在重试…');continue;
    }
    if(!valid())return null;
    if(!progress.ok)throw Error(progress.error||'无法读取操作结果');
    if(progress.status)receive(progress.status);
    if(!quiet&&progress.operation?.id===operation.id&&!progress.operation.completed)notice(progress.operation.phase||'后台正在处理，请稍候…');
    if(progress.operation?.id===operation.id&&progress.operation.completed){reply={...progress,ok:!progress.operation.error,error:progress.operation.error};break;}
   }
   if(!reply.operation?.completed)throw Error('后台结果尚未确认，请刷新状态确认结果后再操作。');
  }
  return valid()?reply:null;
}
async function command(method,extra={},quiet=false){
 if(busy)throw Error('上一项操作仍在进行，请稍候。');if(!online)throw Error('请先恢复面板与后台的连接。');
 busy=true;busyKind=method==='network'&&extra.network?.action==='settings'?'settings-save':quiet?'background':'action';generation++;clearTimeout(toastTimer);$('toast').classList.remove('show');
 try{
  joinError='';if($('join-error'))$('join-error').textContent='';controls();if(!quiet)notice(method==='register-service'?'请在 Windows 授权窗口确认服务操作…':'正在处理，请稍候…');
  const reply=await requestCommand(method,extra,quiet);
  generation++;if(reply.status)render(reply.status);else if(reply.statusNotice)unavailable(reply.statusNotice);
  if(!reply.ok)throw Error(reply.error||'操作未完成');if(!quiet&&online)notice('');return reply;
 }
 finally{busy=false;busyKind='';controls();}
}

async function refresh(){
 if(reading||expired||!csrf)return reading;const version=generation;
 reading=(async()=>{try{const reply=await api('/api/status',undefined,()=>version===generation);if(version!==generation)return;if(!reply.ok||!reply.status)throw Error(reply.error||reply.statusNotice||'未收到完整状态');render(reply.status);}catch(error){if(version!==generation)return;lastStatusFailure=error.message;if(!error.retryable||['NotInstalled','Stopped','AccessDenied'].includes(error.backendCode)||!lastStatusAt||!document.hidden&&performance.now()>=resumeGraceUntil&&performance.now()-lastStatusAt>10000)unavailable(error.message);}})().finally(()=>reading=null);return reading;
}

function checkStatusFreshness(){if(!document.hidden&&performance.now()>=resumeGraceUntil&&online&&performance.now()-lastStatusAt>10000)unavailable(lastStatusFailure||'超过 10 秒未收到后台状态，正在自动重试。');}
function resumeStatus(){if(document.hidden||expired)return;resumeGraceUntil=performance.now()+10000;void refresh();}

function rates(s){
 const now=performance.now(),previous=previousTraffic,peers=new Map();let up=0,down=0;const valid=previous&&previous.network===s.networkId&&now-previous.time>=100&&now-previous.time<10000;
 for(const p of s.peers){const old=previous?.peers.get(p.slot);const rate={up:null,down:null};if(valid&&old&&p.sentBytes>=old.sentBytes&&p.receivedBytes>=old.receivedBytes){const dt=(now-previous.time)/1000;rate.up=(p.sentBytes-old.sentBytes)/dt;rate.down=(p.receivedBytes-old.receivedBytes)/dt;up+=rate.up;down+=rate.down;}peers.set(p.slot,rate);}
 previousTraffic={time:now,network:s.networkId,peers:new Map(s.peers.map(p=>[p.slot,p]))};
 if(valid){historyTraffic.push({time:now,up,down});historyTraffic=historyTraffic.filter(v=>now-v.time<=60000);}
 return {peers,up:valid?up:null,down:valid?down:null};
}
function notice(message,error=false,source='action'){
 clearTimeout(noticeTimer);noticeSource=message?source:'';$('notice').textContent=message;$('notice').hidden=!message;$('notice').classList.toggle('error',error);
 if(message&&error&&source==='action')noticeTimer=setTimeout(()=>{if(noticeSource==='action'&&$('notice').textContent===message)notice('');if(joinError===message){joinError='';if($('join-error'))$('join-error').textContent='';}},12000);
}
function unavailable(message){online=false;previousTraffic=null;$('backend-state').textContent=expired?'面板授权已过期':'后台状态未更新';notice(message,true,expired?'authorization':'backend');if(page==='overview')render();else controls();}
function configFromStatus(s){
 const p=s.settings||{},entries={target:[]},published=[];
 for(const e of p.existingEntries||[]){if(e.peerSlot===0)published.push(e.source);else entries.target.push(e.source);}
 if(!entries.target.length)entries.target=[''];
 let selected='target',terminal='auto',existingRoute=p.directMode?'direct':'server',preferredUnit=0;try{terminal=localStorage.getItem('streamlink-terminal-theme')||'auto';if(p.connectionSource!=='existing')existingRoute=localStorage.getItem('streamlink-existing-route')||existingRoute;preferredUnit=Number(localStorage.getItem('streamlink-entry-refresh-unit'));}catch{}
 const seconds=p.entryRefreshSeconds||60,unit=[1,60,3600].includes(preferredUnit)&&seconds%preferredUnit===0?preferredUnit:seconds%3600===0?3600:seconds%60===0?60:1;
 return {system:{startup:!!s.desktop?.autoStart},identity:{name:s.deviceName,ipMode:p.requestedVirtualIp?'custom':'auto',ip:p.requestedVirtualIp||''},network:{protocol:p.pathSelection==='udp-only'?'udp':'faketcp',mode:p.connectionSource||'custom',route:p.directMode?'direct':'server',existingRoute:['direct','server'].includes(existingRoute)?existingRoute:'server',owner:selected,entries,refresh:seconds/unit,unit},coordination:{url:p.service||''},publish:{sources:published.length?published:['']},host:{...defaults.host,...p.coordinator},ddns:{...defaults.ddns,...p.ddns},port:{listen:p.listenPort||44680},certificate:{pin:p.certificatePin||''},stun:{tcp:(p.tcpStun||[]).join('\n'),udp:(p.udpStun||[]).join('\n')},logging:{level:s.logLevel||'info',terminal:['auto','light','dark'].includes(terminal)?terminal:'auto'}};
}
function refreshEntryTargets(){}
function editingEntries(){return settingGroup(section)==='port'?drafts.publish.sources:drafts.network.entries.target;}

function publishFields(){const values=drafts.publish.sources;return `<p class="hint">无需填写也能接收连接。这里保留本机备用地址或订阅；仅在已有入口模式下启用，不覆盖第三方 DDNS 记录。</p><div id="entry-rows" class="entry-rows">${values.map((v,i)=>entryRow(v,i,values.length)).join('')}</div><div class="test-row"><button class="btn compact" data-action="test" id="test-addresses">测试地址</button><span id="test-status" class="small muted"></span></div><div id="test-results" class="result-list"></div><label class="field"><span>订阅检查间隔（秒）</span><input data-source-refresh type="number" min="1" max="86400" value="${Number(drafts.network.refresh)*Number(drafts.network.unit)}"></label>`;}

function coordinatorDiagnostics(){const c=state?.coordinator;if(!c?.enabled)return '<p class="hint">保存代理监听设置后显示检查结果。</p>';const external=c.external;return `<div class="inline-note" role="status"><strong>外部 HTTPS 检查</strong><p>${esc(external?.detail||(c.running?'等待检查':'协调监听尚未启动，外部地址暂不检查'))}</p>${external?`<p class="hint">检查于 ${esc(new Date(external.checkedAt).toLocaleString('zh-CN',{hour12:false}))} · 每 60 秒更新</p>`:''}${c.certificateExpires?`<p class="hint">监听证书到期：${esc(new Date(c.certificateExpires).toLocaleString('zh-CN',{hour12:false}))}</p>`:''}${c.retryAt?`<p class="hint">下次启动重试：${esc(new Date(c.retryAt).toLocaleTimeString('zh-CN',{hour12:false}))}</p>`:''}</div>`;}
function refreshCoordinatorStatus(){const c=$('coordinator-live-status');if(c){c.textContent=state?.coordinator?.state||'未启用';c.classList.toggle('blue',!!state?.coordinator?.running);}const diagnostic=$('coordinator-diagnostics');if(diagnostic)diagnostic.innerHTML=coordinatorDiagnostics();}
function ddnsDiagnostics(){const d=state?.ddns;return `<div class="inline-note" role="status"><strong>${esc(d?.state||'未启用')}</strong>${d?.thirdPartyReadState?`<p>${esc(d.thirdPartyReadState)}</p>`:''}<p>${esc(d?.publishState||'保存并启动网络后自动发布。')}</p><p>${esc(d?.readState||'通过 DNS 读取已授权成员的入口，并核验设备签名。')}</p>${d?.peerEntries?`<p>已验证 ${Number(d.peerEntries)} 个成员入口 · 尚需直连验证</p>`:''}${d?.publishedAt?`<p class="hint">上次发布：${esc(new Date(d.publishedAt*1000).toLocaleString('zh-CN',{hour12:false}))}</p>`:''}${d?.entryLink?`<p><strong>本机 DDNS 入口</strong></p><p class="hint">可粘贴到其他设备的“加入网络 → 可达入口”发送申请；已有成员也可保存在连接设置的高级入口中。首次加入仍需批准并核对校验码。${d.publishedAt?'DNS 可能仍有缓存，请在接收设备上测试地址。':'尚未确认发布成功，复制后暂时可能解析不到地址。'}</p><button class="btn compact" data-action="copy-ddns-entry">复制 DDNS 入口链接</button>`:''}</div>`;}
function refreshDdnsStatus(){const el=$('ddns-live-status');if(el)el.innerHTML=ddnsDiagnostics();if($('ddns-role'))$('ddns-role').textContent=ddnsWillPublish()?'发现并发布':'仅发现';}

function thirdPartyDnsFields(){
 const external=drafts.network.mode==='existing',record=drafts.ddns.domain.trim().toLowerCase()===saved.ddns.domain.trim().toLowerCase()?state?.ddns?.thirdPartyRecordName:'';
 if(!external)return '<div class="inline-note"><strong>自主打洞</strong><p>ConWU 自行获取入口并更新 DDNS；保存过的第三方入口和手动地址不会启用。</p></div>';
 return '<div class="inline-note"><strong>已有入口 · 第三方更新</strong><p>ConWU 停止自主打洞，自动读取本设备的第三方 TXT 记录。手动地址或订阅仍可作为备用。</p>'+ (record?'<label class="field"><span>第三方更新记录名 · TXT</span><input id="thirdparty-dns-name" readonly class="mono" value="'+esc(record)+'"></label><div class="row wrap"><button class="btn compact" data-action="copy-thirdparty-record">复制记录名</button><button class="btn compact" data-action="copy-thirdparty-link">复制入口链接</button></div><p>在 Lucky 等工具中更新此记录，内容使用 <code>streamlink=公网IPv4:外部端口</code>。转发目标为本机 ConWU 接收端口 '+esc(saved.port.listen)+'。</p>':'<p>保存 DDNS 域名并创建或加入网络后，自动生成本设备的记录名。</p>')+'<p class="hint">同一共用域名下各设备使用自己的记录；无需再提供 HTTPS 更新页面。ConWU 自己管理的签名记录由软件维护。</p></div>';
}
function ddnsFields(){const d=drafts.ddns;return `<div class="switch-row"><div><h3>启用 DDNS</h3><p class="hint">地址变化时自动更新，让自己的设备重新找到彼此。</p></div>${switchControl('enabled',d.enabled,'启用 DDNS')}</div><div class="ddns-fields"><label class="field"><span>共用域名</span><input data-key="domain" value="${esc(d.domain)}" placeholder="conwu.space4sgsa.com" spellcheck="false" autocomplete="off"><span class="hint">自己的设备使用同一个域名。</span></label><label class="field"><span>Cloudflare Zone ID</span><input data-key="zoneId" value="${esc(d.zoneId)}" maxlength="32" spellcheck="false"><span class="hint">在对应域名的 Cloudflare 概述页获取。</span></label><div class="field"><span>Cloudflare API Token</span>${ddnsCredential()}<span class="hint">有令牌时自动发布本机可用入口；未填令牌时只发现其他设备。</span>${d.clearToken?'<span class="hint">已准备清除，保存全部设置后生效。</span>':''}</div><div id="thirdparty-dns-fields">${thirdPartyDnsFields()}</div><div class="ddns-summary"><div class="row between"><strong>自动管理</strong><span class="badge blue" id="ddns-role">${ddnsWillPublish()?'发现并发布':'仅发现'}</span></div><p>取得可用入口后自动发布和续期，无需另外创建更新任务。</p></div><details class="plain-details"><summary>更新周期与状态</summary><label class="field"><span>检查间隔（秒）</span><input data-key="refreshSeconds" type="number" min="30" max="600" value="${d.refreshSeconds}"></label><div id="ddns-live-status">${ddnsDiagnostics()}</div></details></div>`;}

function coordinatorHostFields(){const d=drafts.host;return `<p class="hint">设备入口直接接收加入申请。需要让 Cloudflare Tunnel 等代理提供 HTTPS 配对码服务时，使用以下本机监听地址；原有配置会保留。</p><label class="field"><span>代理目标监听地址</span><input data-key="listenUrl" value="${esc(d.listenUrl)}" placeholder="http://127.0.0.1:47822"><span class="hint">HTTP 只监听本机；对外保持 HTTPS。</span></label><label class="field"><span>外部 HTTPS 地址（可选）</span><input data-key="publicUrl" value="${esc(d.publicUrl)}" placeholder="https://coord.example.com/"></label><label class="field"><span>HTTPS 证书文件（直接监听 HTTPS 时填写）</span><input data-key="certificateFile" value="${esc(d.certificateFile)}" placeholder="PEM 证书绝对路径"></label><label class="field"><span>HTTPS 私钥文件</span><input data-key="certificateKeyFile" value="${esc(d.certificateKeyFile)}" placeholder="PEM 私钥绝对路径"></label><div id="coordinator-diagnostics">${coordinatorDiagnostics()}</div>`;}

function settingsDto(){
 const n=drafts.network,lines=value=>value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),slot=key=>key==='local'?0:key==='target'?-1:Number(key.slice(4));
 let service=drafts.coordination.url.trim();if(service&&!service.includes('://'))service='https://'+service;
 if(service){let uri=new URL(service);if(uri.protocol!=='https:'||uri.username||uri.password||uri.search||uri.hash)throw Error('协调地址需使用 HTTPS，且不能包含账号、查询参数或片段。');if(!uri.pathname.endsWith('/'))uri.pathname+='/';service=uri.toString();}
 return {...state.settings,service,certificatePin:drafts.certificate.pin.trim(),manualEndpoint:'',pathSelection:n.protocol==='udp'?'udp-only':'faketcp-only',connectionSource:n.mode,directMode:n.mode==='existing'&&n.route==='direct',coordinator:clone(drafts.host),ddns:{enabled:!!drafts.ddns.enabled,domain:drafts.ddns.domain.trim().toLowerCase(),zoneId:drafts.ddns.zoneId.trim(),publish:ddnsWillPublish(),refreshSeconds:Number(drafts.ddns.refreshSeconds)},existingEntries:[...drafts.publish.sources.map(v=>v.trim()).filter(Boolean).map(source=>({peerSlot:0,source})),...n.entries.target.map(v=>v.trim()).filter(Boolean).map(source=>({peerSlot:(state.settings.existingEntries||[]).find(e=>e.peerSlot!==0&&e.source===source)?.peerSlot??-2,source}))],entryRefreshSeconds:Number(n.refresh)*Number(n.unit),listenPort:Number(drafts.port.listen),requestedVirtualIp:drafts.identity.ipMode==='custom'?drafts.identity.ip.trim():'',tcpStun:lines(drafts.stun.tcp),udpStun:lines(drafts.stun.udp)};
}
function updateShell(){
 document.querySelectorAll('.nav[data-page]').forEach(e=>{const active=e.dataset.page===page;e.classList.toggle('active',active);if(active)e.setAttribute('aria-current','page');else e.removeAttribute('aria-current');});
 $('breadcrumb').textContent=titles[page];document.title=titles[page]+' · ConWU';$('sidebar-name').textContent=localName();$('sidebar-initials').textContent=(localName().slice(0,2)||'CW').toUpperCase();
 const peers=state?.peers||[],live=peers.filter(p=>p.connected).length;
 $('sidebar-state').innerHTML=networkActive?`<div class="row"><span class="dot ${live?'':'amber'}"></span><span>${state?.isDecentralized?'成员平等网络':owner?'本机创建的网络':'已加入的网络'}</span></div><div class="small dim">${peers.length+1} 台设备</div><div class="small dim">与其余 ${online?live:0} 台设备直连</div>`:'<div class="row"><span class="dot amber"></span><span>尚未加入网络</span></div>';
 $('request-dot').hidden=!incoming;document.querySelector('.nav[data-page="join"]').setAttribute('aria-label',incoming?'加入网络，有新加入申请':'加入网络');$('settings-dirty-dot').hidden=!dirtyCount();document.body.classList.toggle('settings-open',page==='settings');
 $('backend-state').textContent=expired?'面板授权已过期':!online?'后台状态未更新':state?.serviceReady?'后台运行中':state?.state||'正在读取后台';$('app-version').textContent=state?.version?'v'+state.version.split('+')[0]:'';
}
function render(next){
 if(expired&&next){controls();return;}
 let settingsChanged=false;
 if(next&&typeof next==='object'&&'deviceName'in next){
  const first=!state,oldNetwork=state?.networkId,priorPending=state?.pendingMembership,priorJoin=joinModel,priorCredential=state?.ddnsCredentialConfigured;if(state&&state.settingsRevision!==next.settingsRevision)hideDdnsToken();state=next;online=true;lastStatusAt=performance.now();lastStatusFailure='';networkActive=!!state.networkId;owner=!!state.isOwner;createdAt=(state.networkEstablishedAt||0)*1000;
  if(noticeSource==='backend')notice('');
  if(noticeSource==='pair'&&!state.pairing?.active){lastPairError='';notice('');}
  if(oldNetwork!==state.networkId){previousTraffic=null;historyTraffic=[];expanded.clear();pairNotice='';if(submittedJoin){if(submittedJoin.direct&&joinInviteValue.replace(/\s/g,'')===submittedJoin.code)joinInviteValue='';if(!submittedJoin.direct&&joinCodeValue.replace(/\s/g,'')===submittedJoin.code)joinCodeValue='';}if(submittedJoin||joinStatus==='waiting')joinName='';submittedJoin=null;joinError=lastPairError='';joinTab='outgoing';lastPairPoll=0;clearTimeout(pairNoticeTimer);}
  traffic=rates(state);appendLogs(state.logs||[]);
  if(!settingsHydrated||!dirtyCount()){const configuration=configFromStatus(state);settingsChanged=!same(saved,configuration)||priorCredential!==state.ddnsCredentialConfigured;saved=configuration;drafts=clone(saved);baseRevision=state.settingsRevision||'';settingsHydrated=true;if(!defaults.identity.name)defaults.identity.name=state.deviceName;}
  const p=state.pairing,live=p?.active&&p.expires*1000>Date.now();pairCode=live&&p.owner&&!p.code.startsWith('SL')?p.code:'';pairExpires=live?p.expires*1000:0;invitation=live&&p.owner&&p.code.startsWith('SL6.')?p.code:'';inviteExpires=pairExpires;
  incoming=!!(live&&p.owner&&p.candidate);joinStatus=live&&!p.owner?'waiting':'';joinModel=JSON.stringify([state.networkId,state.networkEnabled,state.settings?.directMode,state.settings?.connectionSource,state.isDecentralized,state.canManageNetwork,state.pendingMembership,p]);updateShell();
  if(page==='settings'&&!first&&oldNetwork===state.networkId&&priorPending===state.pendingMembership){if(settingsChanged)renderFields();else{refreshSettingsTools();refreshEntryTargets();refreshCoordinatorStatus();refreshDdnsStatus();}const service=$('service-live-status');if(service)service.textContent=state.desktop?.serviceRegistered?(state.serviceReady?'已注册 · 正在运行':'已注册 · 已停止'):'尚未注册';controls();return;}
  if(page==='join'&&!first&&priorJoin===joinModel){controls();return;}
  if(page==='logs'&&!first&&$('terminal-lines')){updateLogView();controls();return;}
 }
 updateShell();const focused=document.activeElement,restore=focused&&$('content').contains(focused)?focused.dataset?.action:null;
 $('content').innerHTML=governanceNotice()+({overview:overviewPage,create:createPage,join:joinPage,logs:logsPage,settings:settingsPage})[page]();
 if(page==='settings'){refreshSettingsTools();refreshEntryTargets();bindSectionValidation();}if(page==='join')bindJoinInput();if(page==='logs')updateLogView();controls();
 if(restore)$('content').querySelector(`[data-action="${CSS.escape(restore)}"]:not(:disabled)`)?.focus({preventScroll:true});
}
function refreshThirdPartyFields(){
 const externalFields=$('thirdparty-dns-fields');if(externalFields){const key=JSON.stringify([drafts.network.mode,drafts.ddns.domain,saved.ddns.domain,state?.ddns?.thirdPartyRecordName,saved.port.listen]);if(externalFields.dataset.renderKey!==key){externalFields.innerHTML=thirdPartyDnsFields();externalFields.dataset.renderKey=key;}}
}
function controls(){
 refreshThirdPartyFields();
 const ready=online&&!expired&&state?.serviceReady&&!busy;
 document.querySelectorAll('[data-action="enable-equal"],[data-action="membership-resume"],[data-action="create"],[data-action="generate"],[data-action="delete"],[data-action="leave"],[data-action="approve"],[data-action="reject"],[data-action="cancel-join"],[data-action="network-toggle"],[data-action="retry"],#join-submit,#save-section').forEach(e=>{e.disabled=!ready;});
 if($('save-section'))$('save-section').disabled=!ready||!dirtyCount();if($('revert-section'))$('revert-section').disabled=busy||!dirtyCount()&&(!history||same(history,saved));if($('default-section'))$('default-section').disabled=busy||Object.keys(defaults).every(k=>same(drafts[k],effectiveDefaults(k)));
 const fields=$('settings-fields');if(fields){const locked=busy&&busyKind==='settings-save';fields.inert=locked;fields.classList.toggle('global-busy',locked);}
 document.querySelector('.nav[data-action="leave"]').disabled=!ready||!networkActive;
 for(const key of ['create','generate','delete']){const b=document.querySelector(`[data-action="${key}"]`);if(b)b.disabled=!ready||(key==='create'?networkActive:!networkActive||key==='generate'&&(!canManage()||!state.networkEnabled&&!state.isDecentralized));}
 if($('join-submit'))$('join-submit').disabled=!ready||networkActive;
 const approve=document.querySelector('[data-action="approve"]');if(approve)approve.disabled=!ready||!state.pairing?.verification;
 const service=document.querySelector('[data-action="register-service"]');if(service)service.disabled=busy||!online||!!state?.serviceReady;
 const retry=document.querySelector('[data-action="retry"]');if(retry)retry.disabled=!ready||!state?.networkEnabled;
 const test=$('test-addresses');if(test)test.disabled=!ready||!editingEntries().some(v=>v.trim());
 document.querySelectorAll('[data-action="revoke"]').forEach(e=>e.disabled=!ready||!canManage());
 if(state?.pendingMembership)document.querySelectorAll('[data-action="create"],[data-action="generate"],[data-action="approve"],[data-action="reject"],[data-action="revoke"],[data-action="delete"],[data-action="leave"],[data-action="enable-equal"],#join-submit').forEach(e=>e.disabled=true);
}
function sectionFields(){
 section=settingGroup(section);
 if(section==='identity'){const d=drafts.identity;return `<div data-settings-group="identity"><label class="field"><span>设备名称</span><input data-key="name" id="device-name" value="${esc(d.name)}" maxlength="64" autocomplete="off"></label><details class="plain-details"><summary>虚拟 IP</summary><label class="field"><span>自定义虚拟 IP（可选）</span><input data-key="ip" class="mono" value="${esc(d.ipMode==='custom'?d.ip:'')}" placeholder="自动分配"><span class="hint">留空时自动分配。下次创建或加入网络时生效。</span></label></details></div>`;}
 if(section==='network')return fieldsFor('network',networkFields);
 if(section==='port')return `<div class="section-status"><span class="badge good">${icon('check')}默认接收连接</span><span class="small muted">无需单独开启</span></div><div data-settings-group="port"><label class="field"><span>本机接收端口</span><div class="port-input"><input id="listen-port" data-key="listen" type="number" min="1024" max="65535" value="${drafts.port.listen}"><span class="port-unit">端口</span></div><span class="hint">接收其他设备的连接与加入申请。</span></label></div><div class="address-example"><div class="small muted">其他设备在“加入网络 → 可达入口”填写</div><div class="example-row"><span class="mono">设备可达地址:<strong id="port-example">${drafts.port.listen}</strong></span><button class="text-btn" data-action="copy-port-format" aria-label="复制地址格式">${icon('copy')}</button></div><p class="hint">例如公网 IP、动态域名或已有打洞地址。有端口转发时，填写映射后的外部端口。</p></div><div class="port-foot"><div>${icon('laptop')}<span>接收加入申请</span></div><div>${icon('link')}<span>建立设备直连</span></div><div>${icon('server')}<span>为自己的网络提供协调</span></div></div><details class="plain-details"><summary>本机的可达地址（可选）</summary>${fieldsFor('publish',publishFields)}</details><details class="plain-details"><summary>HTTPS 反向代理与证书（可选）</summary>${fieldsFor('host',coordinatorHostFields)}</details>`;
 if(section==='ddns')return fieldsFor('ddns',ddnsFields);
 return fieldsFor('system',systemFields)+fieldsFor('logging')+`<details class="plain-details"><summary>STUN 服务器</summary>${fieldsFor('stun')}</details>`;
}

function coordinatorRoleCard(){return '';}

function overviewPage(){
 const peers=state?.peers||[],live=peers.filter(p=>p.connected),status=online?(state?.state||'正在读取后台'):'状态待确认';
 if(!networkActive)return heading('概况','所有设备与连接状态，尽在这里。')+coordinatorRoleCard()+`<article class="card pad empty-state">${icon('link')}<h2>${state?.serviceReady?'先把设备连起来':'正在等待后台就绪'}</h2><p>${state?.serviceReady?'创建一个网络，或加入目标主机的网络。':esc(state?.state||'正在读取本机后台状态。')}</p><div class="form-actions" data-static-style="u9"><button class="btn primary" data-page="create">创建网络</button><button class="btn" data-page="join">加入网络</button></div></article>`;
 const steps=state.connection,progress=state.networkEnabled&&steps&&!['Idle','Connected'].includes(steps.phase),up=peers.reduce((n,p)=>n+p.sentBytes,0),down=peers.reduce((n,p)=>n+p.receivedBytes,0);
 return heading('概况','本机与网络内设备的连接状态。',`<div class="row wrap"><span class="badge ${live.length?'good':''}">${esc(status)}</span><button class="btn compact" data-action="network-toggle">${state.networkEnabled?'断开网络':'连接网络'}</button>${steps?.canRetry?'<button class="btn compact" data-action="retry">重新尝试</button>':''}</div>`)+
 coordinatorRoleCard()+(progress?`<article class="card pad" data-static-style="u10" role="status"><div class="row between"><h2>${esc(phaseNames[steps.phase]||steps.phase)}</h2><span class="small muted">${duration(steps.elapsedMs||0)}</span></div><p class="hint" data-static-style="u11">${esc(steps.detail||'正在准备连接')}</p></article>`:'')+
 `<div class="overview-top"><article class="card pad"><div class="device-head"><div class="avatar">${esc(localName().slice(0,2).toUpperCase())}</div><div class="grow"><h2>${esc(localName())}</h2><div class="small muted">本机 · ${owner?'网络创建者':'网络成员'}</div></div><button class="text-btn" data-settings="identity" aria-label="修改本机设置">${icon('settings')}</button></div><div class="identity-ip"><span class="small muted">虚拟网络 IP</span><div class="row between"><strong class="mono">${esc(localIp())}</strong><button class="text-btn" data-action="copy-ip" aria-label="复制本机虚拟 IP">${icon('copy')}</button></div></div><div class="small muted" data-static-style="u12">${protocol()} · ${state.networkEnabled?'网络已启动':'网络已停止'}</div></article>
 <article class="card pad"><div class="metrics"><div><div class="metric-label">往返延迟</div><div class="metric-value">${online&&live[0]?.rttMs!=null?live[0].rttMs.toFixed(0):'—'}<span>ms</span></div><div class="metric-sub">${live[0]?'至 '+esc(live[0].name):'等待直连'}</div></div><div><div class="metric-label">实时上传</div><div class="metric-value">${online&&traffic.up!=null?(traffic.up/1e6).toFixed(2):'—'}<span>MB/s</span></div><div class="metric-sub">累计 ${total(up)}</div></div><div><div class="metric-label">实时下载</div><div class="metric-value">${online&&traffic.down!=null?(traffic.down/1e6).toFixed(2):'—'}<span>MB/s</span></div><div class="metric-sub">累计 ${total(down)}</div></div></div>${trafficChart()}</article></div>
 <article class="card table-card"><div class="table-head row between"><h2>网络设备<span>${peers.length+1} 台（含本机）</span></h2><span class="small muted">${online?'自动更新':'状态未更新'}</span></div><div class="table-scroll"><table><thead><tr><th>设备</th><th>虚拟 IP</th><th>连接状态 / 协议</th><th>延迟</th><th>上传</th><th>下载</th><th>操作</th></tr></thead><tbody><tr><td><div class="peer-device">${icon('laptop')}<div><div class="peer-name">${esc(localName())}</div><div class="peer-sub">${owner?'网络创建者':'网络成员'}</div></div></div></td><td class="mono">${esc(localIp())}</td><td colspan="5" class="self-cell"><span class="badge">本机</span></td></tr>${peers.map(p=>peerRow(p)).join('')}</tbody></table></div><div class="table-foot row between"><span>流量按本次网络运行统计</span><span>${online?'与其余 '+live.length+' 台设备直连':'连接状态待确认'}</span></div></article>`;
}
function trafficChart(){const values=historyTraffic,max=Math.max(1,...values.map(p=>Math.max(p.up,p.down))),now=performance.now(),points=field=>values.map(p=>(700-Math.min(60000,now-p.time)/60000*700).toFixed(1)+','+(63-p[field]/max*56).toFixed(1)).join(' ');return `<svg class="traffic-chart" viewBox="0 0 700 68" preserveAspectRatio="none" role="img" aria-label="最近一分钟的上下行速度"><path d="M0 63H700M0 30H700" stroke="var(--line)" stroke-width=".6" fill="none"/><polyline points="${points('down')}" stroke="var(--green)" stroke-width="1.5" fill="none"/><polyline points="${points('up')}" stroke="var(--accent)" stroke-width="1.3" fill="none"/></svg><div class="small muted">最近 60 秒 · 下载 / 上传</div>`;}
function peerRow(p){const rate=traffic.peers.get(p.slot),live=online&&p.connected;return `<tr><td><div class="peer-device">${icon('monitor')}<div><div class="peer-name">${esc(p.name)}</div><div class="peer-sub">${esc(live?'已认证直连':online?phaseNames[p.connection?.phase]||p.phase||'未在线':'状态未更新')}</div></div></div></td><td class="mono">${esc(p.virtualIp)}</td><td>${live?'已直连':online?'未连接':'待确认'}<div class="peer-sub">${live?esc(/udp/i.test(p.actualTransport)?'直接 UDP':'FakeTCP + HTTP'):'—'}</div></td><td>${live&&p.rttMs!=null?p.rttMs.toFixed(0)+' ms':'—'}</td><td>${speed(online?rate?.up:null)}<div class="peer-sub">累计 ${total(p.sentBytes)}</div></td><td>${speed(online?rate?.down:null)}<div class="peer-sub">累计 ${total(p.receivedBytes)}</div></td><td><button class="btn ghost icon-button" data-peer-details="${p.slot}" aria-label="查看 ${esc(p.name)} 详情" aria-expanded="${expanded.has(p.slot)}">${icon('settings')}</button></td></tr>${expanded.has(p.slot)?`<tr class="peer-detail"><td colspan="7"><p>${esc(p.connection?.detail||p.phase||'等待设备上线')}</p><p>${live?'实际入口':'上次确认入口'}：${esc(entryDescription(p))}</p><p>已直连时间：<span class="mono" data-connected-slot="${p.slot}">${connectedTime(p)}</span></p><div class="row"><button class="btn compact" data-peer-copy="${p.slot}">复制 IP</button>${canManage()?`<button class="btn compact danger" data-action="revoke" data-slot="${p.slot}">移出网络</button>`:''}</div></td></tr>`:''}`;}
function waitingView(){const p=state?.pairing;return `<div class="waiting"><div class="waiting-symbol">${icon('clock')}</div><h2>正在等待设备同意</h2><p>${esc(p?.peerName||'目标主机')} 将核对你的设备信息。</p><div class="mono" data-static-style="u13">${esc(p?.verification||'正在交换校验码')}</div><p>${esc(p?.state||'申请已发送')}</p><button class="btn" data-action="cancel-join">取消申请</button></div>`;}
function incomingPage(){const p=state?.pairing;if(!incoming)return `<article class="card pad empty-state">${icon('shield')}<h2>暂无加入申请</h2><p>${canManage()?'收到新申请后，会显示设备信息和校验码。':'加入申请由网络创建者处理。'}</p></article>`;return `<article class="card pad request-card"><div class="section-title">${icon('laptop')}<div><h2>${esc(p.peerName)}</h2><p class="small muted">请求加入本机网络</p></div></div><div class="request-meta"><div><span class="small muted">预分配 IP</span><strong class="mono">${esc(p.proposedIp||'正在分配')}</strong></div><div><span class="small muted">加入方式</span><strong>${p.method==='entry'?'可达入口':p.method==='direct'?'直连邀请':'配对码'}</strong></div><div><span class="small muted">双方校验码</span><strong class="mono">${esc(p.verification||'正在交换')}</strong></div></div><div class="request-footer"><span class="hint">${p.replacingSlot?'此设备正在重新加入；同意后会替换旧成员授权。':'请核对设备名称与校验码，再处理申请。'}</span><div class="row"><button class="btn positive" data-action="approve" ${p.verification?'':'disabled'}>同意</button><button class="btn danger" data-action="reject">拒绝</button></div></div></article>`;}
async function saveSection(){
 const changed=Object.keys(defaults).filter(dirty);if(!changed.length)return;
 const validation=clone(drafts);if(validation.coordination.url.trim()&&!validation.coordination.url.includes("://"))validation.coordination.url="https://"+validation.coordination.url.trim();
 for(const key of changed){const error=validateSection(key,validation);if(error){section=key;render();$('settings-error').textContent=sectionNames[key]+'：'+error;return;}}
 let settings;try{settings=settingsDto();}catch(error){section='coordination';render();$('settings-error').textContent=error.message;return;}
 const reconnect=state.networkEnabled&&(drafts.port.listen!==saved.port.listen||drafts.network.protocol!==saved.network.protocol||drafts.network.mode!==saved.network.mode);
 if(reconnect&&!await confirmAction('保存全部设置并重新连接？','连接方式、协议或接收端口的修改会短暂中断连接，其他修改会一起保存。','保存并重连'))return;
 const before=clone(saved),patch={};if(drafts.identity.name.trim()!==saved.identity.name){patch.deviceName=drafts.identity.name.trim();patch.expectedDeviceName=saved.identity.name;}if(drafts.logging.level!==saved.logging.level){patch.logLevel=drafts.logging.level;patch.expectedLogLevel=saved.logging.level;}
 const action={action:'settings',settings,expectedRevision:baseRevision,confirmReplace:reconnect};if(Object.keys(patch).length)action.patch=patch;if(drafts.system.startup!==saved.system.startup){action.autoStart=drafts.system.startup;action.expectedAutoStart=saved.system.startup;}
 if(drafts.ddns.newToken.trim())action.ddnsToken=drafts.ddns.newToken.trim();if(drafts.ddns.clearToken)action.clearDdnsToken=true;
 const uiOwner=drafts.network.owner,terminal=drafts.logging.terminal,existingRoute=drafts.network.existingRoute,refreshUnit=drafts.network.unit;
 await command('network',{network:action});
 try{localStorage.setItem('streamlink-entry-owner',uiOwner);localStorage.setItem('streamlink-terminal-theme',terminal);localStorage.setItem('streamlink-existing-route',existingRoute);localStorage.setItem('streamlink-entry-refresh-unit',String(refreshUnit));}catch{}
 hideDdnsToken();history=before;saved=configFromStatus(state);drafts=clone(saved);baseRevision=state.settingsRevision||'';render();notice('');notify('全部设置已保存');
}
function restoreSettings(){hideDdnsToken();if(dirtyCount()){saved=configFromStatus(state);drafts=clone(saved);baseRevision=state.settingsRevision||'';render();notify('所有未保存的修改已还原');}else if(history&&!same(history,saved)){drafts=clone(history);render();notify('已恢复前一组完整设置，保存后生效');}}
function resetDefaults(){ask('恢复全部默认设置？','将全部分区填为默认值，保存后生效。当前网络固定的身份设置保持锁定。','填入默认值',()=>{hideDdnsToken();drafts=Object.fromEntries(Object.keys(defaults).map(k=>[k,effectiveDefaults(k)]));render();notify('已填入默认设置，保存后生效');});}
function confirmAction(title,text,label,tone='neutral'){return new Promise(resolve=>ask(title,text,label,()=>resolve(true),resolve,tone));}
function ask(title,text,label,callback,cancel,tone='neutral'){if(modalCallback)throw Error('请先处理当前确认窗口');$('dialog-title').textContent=title;$('dialog-description').textContent=text;$('dialog-confirm').textContent=label;$('dialog-confirm').classList.toggle('danger',tone==='danger');$('dialog-confirm').classList.toggle('positive',tone==='positive');modalCallback=callback;modalCancel=cancel||null;$('confirm-dialog').showModal();$('dialog-cancel').focus();}
let modalCancel=null;
function closeDialog(yes){const callback=modalCallback,cancel=modalCancel;modalCallback=modalCancel=null;$('confirm-dialog').close();if(yes)callback?.();else cancel?.(false);}
function requireApplied(){if(dirtyCount())throw Error('设置有未保存的更改，请先保存全部设置，或恢复刚才设置。');}
function coordination(){const p=state.settings;if(!p?.service){openSettings('coordination');throw Error('请先填写并保存 HTTPS 协调服务器地址。');}return {service:p.service,certificatePin:p.certificatePin};}
async function createNetwork(){requireApplied();if(networkActive)throw Error('需要退出当前网络后才能创建。');const direct=activeRoute()==='direct';await network(direct?'create-direct':'create',{...(direct?{}:coordination()),mode:saved.network.protocol,expectedNetwork:state.networkId});notify('网络已创建');}
async function generate(){requireApplied();if(state.pairing?.candidate&&!await confirmAction('重新生成邀请？','将取消当前尚未处理的加入申请。','重新生成'))return;await network('invite',{expectedNetwork:state.networkId});notify(activeRoute()==='direct'?'直连邀请已生成':'配对码已生成');}
async function leaveNetwork(deleting=false){
 if(!networkActive)return;
 const pause=owner&&!state?.isDecentralized&&!deleting,action=deleting?'delete-network':pause?'pause-network':'leave';
 const title=deleting?'删除整个网络？':pause?'暂时离开网络？':'退出当前网络？';
 const text=deleting?'将撤销其他成员并删除本机网络凭据。所有成员需要重新组网；本机设置和入口保留。':pause?'仅停止本机连接，保留网络身份、成员和设置。其余设备的相互直连可以继续；返回后在概况中点击连接。新的加入申请需要本机上线审批。':'将停止本机连接并移除本机网络凭据，不影响其他成员之间的直连；再次加入需要重新申请。';
 const label=deleting?'删除整个网络':pause?'暂时离开':'退出网络';
 if(!await confirmAction(title,text,label,pause?'primary':'danger'))return;
 await network(action,{expectedNetwork:state.networkId,confirmReplace:true});
 notify(deleting?'当前网络已删除':pause?'已暂时离开，网络和成员已保留':'已退出当前网络');
}
const network=(action,fields={},quiet=false)=>command('network',{network:{action,...fields}},quiet);
async function joinNetwork(){
 requireApplied();if(networkActive)throw Error('需要退出当前网络后才能申请加入。');const entry=joinEntryMethod==='entry',value=(entry?joinEntryValue:joinCodeValue).trim(),invite=entry&&value.startsWith('SL6.');
 if(!value)throw Error(entry?'请填写对方的可达入口。':'请输入六位数字配对码。');if(!entry&&!/^\d{6}$/.test(value))throw Error('请输入六位数字配对码。');
 const name=(joinName||localName()).trim();if(!name)throw Error('请输入本机设备名称。');if(name!==state.deviceName)await command('patch',{patch:{deviceName:name,expectedDeviceName:state.deviceName}},true);
 submittedJoin={code:value,direct:invite,entry};
 try{await network(entry?invite?'join-invitation':'join-entry':'join',{...(!entry?coordination():{}),...(entry&&!invite?{entry:value}:{code:invite?value.replace(/\s/g,''):value}),expectedNetwork:state.networkId,mode:saved.network.protocol});}
 catch(error){if(!state?.pairing?.active)submittedJoin=null;throw error;}notify('申请已发送，等待设备同意');
}

function bindJoinInput(){const entry=joinEntryMethod==='entry',input=$(entry?'join-entry':'join-code');if(!input)return;input.oninput=()=>{if(entry)joinEntryValue=input.value;else{joinCodeValue=input.value.replace(/\D/g,'').slice(0,6);input.value=joinCodeValue;input.closest('.digits-input').querySelectorAll('.digit').forEach((el,i)=>{const digit=joinCodeValue[i]||'';el.textContent=digit;el.classList.toggle('filled',!!digit);});}joinError='';$('join-error').textContent='';};$('join-device-name').oninput=e=>joinName=e.target.value;$('join-form').onsubmit=e=>{e.preventDefault();run(joinNetwork).catch(()=>{});};}

async function testAddresses(){const settings=settingsDto(),local=settingGroup(section)==='port',entries=settings.existingEntries.filter(e=>local?e.peerSlot===0:e.peerSlot!==0);if(!entries.length)throw Error('请先填写地址来源。');const version=++testGeneration,selected=section;await network('resolve-entries',{settings:{...settings,existingEntries:entries}});if(page!=='settings'||section!==selected||version!==testGeneration||!$('test-results'))return;const results=state.entryResolutions||[];$('test-status').textContent=results.filter(r=>!r.error).length+'/'+results.length+' 个来源解析成功';$('test-results').innerHTML=results.map(r=>`<div class="test-result ${r.error?'error':''}">${icon(r.error?'x':'check')}<div class="grow"><div>${esc(r.error||(r.endpoints.length?r.endpoints.join('、'):'来源已确认，目前没有可连接入口'))}</div><p>${r.error?'请检查来源或稍后重试；现有健康连接继续保持。':'已解析。实际连接还需核验设备身份和双向通信。'}</p></div></div>`).join('');}

async function pollPair(){
 if(!online||expired||busy||pairPolling||state?.pendingMembership||!state?.pairing?.active||state.pairing.direct||Date.now()-lastPairPoll<2500)return;
 let version=generation;const attempt={};pairPolling=attempt;lastPairPoll=Date.now();
 const valid=()=>version===generation&&!expired;
 const receive=next=>{if(valid()){version=++generation;render(next);}};
 try{
  // Routine pairing discovery must not disable leave, approve, save or other
  // explicit actions. Accepted polls yield to them at the service mutation gate.
  const reply=await requestCommand('network',{network:{action:'pair-poll',background:true}},true,valid,receive);
  if(!reply||!valid())return;
  if(!reply.ok)throw Error(reply.error||'配对状态暂未更新');
  if(reply.status)receive(reply.status);
  if(lastPairError&&noticeSource==='pair')notice('');lastPairError='';
  if(!state.pairing?.active&&state.pairing?.state)notify(state.pairing.state);
 }catch(e){if(!valid())return;lastPairPoll=Date.now()+10000;if(e.message!==lastPairError){lastPairError=e.message;notice(e.message,true,'pair');}}
 finally{if(pairPolling===attempt)pairPolling=null;}
}
function appendLogs(lines){let overlap=0;for(let n=Math.min(lastLogs.length,lines.length);n>0;n--)if(lastLogs.slice(-n).every((v,i)=>v===lines[i])){overlap=n;break;}for(const line of lines.slice(overlap)){const m=line.match(/^(\d\d:\d\d:\d\d) (?:\[(INFO|WARN|ERROR|DEBUG)\] )?(.*)$/);logLines.push({time:m?.[1]||'',level:m?.[2]||'INFO',message:m?.[3]||line});}lastLogs=lines.slice();if(logLines.length>500)logLines.splice(0,logLines.length-500);}
let logFilter='ALL',logSearch='',autoScroll=true;
function visibleLogs(){return logLines.filter(l=>(logFilter==='ALL'||l.level===logFilter)&&(!logSearch||l.message.toLowerCase().includes(logSearch.toLowerCase())));}
function logsPage(){return heading('日志','查看连接与操作记录，定位发生问题的阶段。')+`<article class="card" data-static-style="u14"><div class="terminal-actions row between wrap"><div class="row"><select class="preview-select" id="log-filter" aria-label="日志等级筛选">${['ALL','INFO','WARN','ERROR','DEBUG'].map(v=>`<option ${logFilter===v?'selected':''} value="${v}">${v==='ALL'?'全部等级':v}</option>`).join('')}</select><input id="log-search" class="preview-select" aria-label="搜索日志" value="${esc(logSearch)}" placeholder="搜索日志"></div><div class="row"><button class="text-btn" data-action="copy-logs">复制日志</button><button class="text-btn" data-action="download-logs">导出</button><button class="text-btn" data-settings="logging">日志设置</button></div></div><div class="terminal terminal-content" id="terminal-content"><div id="terminal-lines" role="log" aria-label="当前后台日志"></div></div><div class="table-foot row between"><span id="log-count"></span><label><input type="checkbox" id="auto-scroll" ${autoScroll?'checked':''}>自动滚动</label></div></article>`;}
function updateLogView(){const terminal=$('terminal-content');if(!terminal)return;const value=saved.logging.terminal,light=value==='light'||value==='auto'&&theme==='light';terminal.classList.toggle('light',light);const scroll=terminal.scrollTop,lines=visibleLogs();$('terminal-lines').innerHTML=lines.map(l=>`<div class="log-entry"><span class="dim">${esc(l.time)}</span><span class="${l.level==='ERROR'?'warn':l.level==='WARN'?'warn':'info'}">[${esc(l.level)}]</span><span class="message">${esc(l.message)}</span></div>`).join('');$('log-count').textContent=lines.length+' 条 · 最多保留 500 条面板日志';terminal.scrollTop=autoScroll?terminal.scrollHeight:scroll;}
async function copyText(value){if(!value)return;await navigator.clipboard.writeText(value);notify('已复制');}
async function run(action){try{return await action();}catch(error){notice(error.message,true,expired?'authorization':'action');if(page==='join'){joinError=error.message;if($('join-error'))$('join-error').textContent=joinError;}throw error;}}
document.addEventListener('input',e=>{if(e.target.matches('#settings-fields input:not([type=checkbox]):not([type=radio]),#settings-fields textarea'))inputChange(e.target);if(e.target.id==='log-search'){logSearch=e.target.value;updateLogView();}});
document.addEventListener('change',e=>{if(e.target.matches('#settings-fields select,#settings-fields input[type=radio],#settings-fields input[type=checkbox]'))inputChange(e.target);if(e.target.id==='log-filter'){logFilter=e.target.value;updateLogView();}if(e.target.id==='auto-scroll')autoScroll=e.target.checked;});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b||b.disabled)return;run(async()=>{
 if(b.dataset.page)return navigate(b.dataset.page);if(b.dataset.settings)return openSettings(b.dataset.settings);if(b.dataset.section){hideDdnsToken();section=settingGroup(b.dataset.section);render();return;}if(b.dataset.joinTab){joinTab=b.dataset.joinTab;if(b.dataset.entryMethod)joinEntryMethod=b.dataset.entryMethod;joinError='';render();return;}
 if(b.dataset.peerDetails){const slot=Number(b.dataset.peerDetails);expanded.has(slot)?expanded.delete(slot):expanded.add(slot);return render();}if(b.dataset.peerCopy)return copyText(state.peers.find(p=>p.slot===Number(b.dataset.peerCopy))?.virtualIp);
 if(b.dataset.removeEntry!==undefined){const list=editingEntries();list.splice(Number(b.dataset.removeEntry),1);if(!list.length)list.push('');renderFields();return;}
 switch(b.dataset.action){
 case 'theme':theme=theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('streamlink-theme',theme);}catch{}$('theme-button').innerHTML=icon(theme==='dark'?'sun':'moon');if(page==='logs')updateLogView();break;
 case 'membership-resume':await network('membership-resume');break;case 'enable-equal':if(await confirmAction('启用成员平等管理？','所有已批准成员都能邀请、审批、移除成员及解散网络，创建者可离开。请先更新所有设备；启用后不能退回旧版管理方式。','启用'))await network('enable-equal',{expectedNetwork:state.networkId,confirmReplace:true});break;
 case 'save':await saveSection();break;case 'revert':restoreSettings();break;case 'defaults':resetDefaults();break;case 'create':await createNetwork();break;case 'generate':await generate();break;case 'leave':await leaveNetwork();break;case 'delete':await leaveNetwork(true);break;
 case 'copy-code':await copyText(pairCode);break;case 'copy-invite':await copyText(invitation);break;case 'copy-ip':await copyText(state?.virtualIp);break;
 case 'copy-thirdparty-record':await copyText(state?.ddns?.thirdPartyRecordName);break;
 case 'copy-thirdparty-link':if(state?.ddns?.thirdPartyRecordName)await copyText('txt://'+state.ddns.thirdPartyRecordName+'#streamlink');break;
 case 'copy-ddns-entry':await copyText(state?.ddns?.entryLink);break;
 case 'show-ddns-token':await showDdnsToken();break;
 case 'clear-ddns-token':if(await confirmAction('清除令牌？','保存后停止发布本机地址。域名发现仍可使用。','清除','danger')){hideDdnsToken();drafts.ddns.newToken='';drafts.ddns.clearToken=!!state?.ddnsCredentialConfigured;drafts.ddns.publish=false;renderFields();}break;
 case 'copy-port-format':await copyText('设备可达地址:'+drafts.port.listen);break;
 case 'add-entry':{const values=editingEntries();if([...drafts.publish.sources,...Object.values(drafts.network.entries).flat()].filter(v=>v.trim()).length>=12||values.length>=12)throw Error('最多保存 12 项地址来源。');values.push('');renderFields();document.querySelector('.entry-row:last-child input').focus();break;}
 case 'test':await testAddresses();break;
 case 'cancel-join':await network('pair-cancel');submittedJoin=null;notify('已取消加入申请');break;
 case 'approve':case 'reject':{const p=state.pairing;if(b.dataset.action==='approve'&&!await confirmAction('确认双方校验码','请确认 '+p.peerName+' 显示的校验码也是 '+p.verification+'。'+(state.isDecentralized?'同意后，该设备将获得与本机相同的网络管理权限。':''),'同意加入','positive'))return;await network(b.dataset.action,{candidate:p.candidate,verification:p.verification,proposedIp:p.proposedIp});notify(b.dataset.action==='approve'?'已同意加入':'已拒绝申请');break;}
 case 'revoke':{const peer=state.peers.find(p=>p.slot===Number(b.dataset.slot));if(peer&&await confirmAction('移出设备？','将撤销 '+peer.name+' 的网络授权。','移出设备','danger'))await network('revoke',{expectedNetwork:state.networkId,peerSlot:peer.slot});break;}
 case 'network-toggle':if(state.networkEnabled&&!await confirmAction('断开网络？','本机串流会中断，网络身份和设置保留。其他成员之间的直连不受影响。','断开'))return;await command(state.networkEnabled?'stop':'start');break;
 case 'retry':await command('retry');break;case 'register-service':await command('register-service');break;
 case 'copy-logs':await copyText(visibleLogs().map(l=>l.time+' ['+l.level+'] '+l.message).join('\n'));break;
 case 'download-logs':{const blob=new Blob([visibleLogs().map(l=>l.time+' ['+l.level+'] '+l.message).join('\n')],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='ConWU-'+new Date().toISOString().slice(0,10)+'.log';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);break;}
 }
}).catch(()=>{});});
$('dialog-cancel').onclick=()=>closeDialog(false);$('dialog-confirm').onclick=()=>closeDialog(true);$('confirm-dialog').addEventListener('cancel',e=>{e.preventDefault();closeDialog(false);});
window.addEventListener('beforeunload',e=>{if(dirtyCount()){e.preventDefault();e.returnValue='';}});
function settingGroup(key){return settingGroups[key]?key:Object.keys(settingGroups).find(group=>settingGroups[group].keys.includes(key))||'network';}

function groupChanged(key){return settingGroups[key].keys.some(dirty);}

function fieldsFor(key,renderer=baseSectionFields){const previous=section;try{section=key;return `<div data-settings-group="${key}">${renderer()}</div>`;}finally{section=previous;}}

function systemFields(){const linux=state?.platform==='linux',registered=!!state?.desktop?.serviceRegistered;return `<div class="switch-row"><div><h3>开机启动</h3><p class="hint">${linux?'随系统启动 ConWU 后台。':'随系统启动后台，登录后显示托盘。'}</p></div>${switchControl('startup',drafts.system.startup,'开机启动',linux&&!registered)}</div><div class="switch-row"><div><h3>后台服务</h3><p class="hint" id="service-live-status">${registered?state.serviceReady?'已注册 · 正在运行':'已注册 · 已停止':'尚未注册'}</p></div>${linux?'<span class="badge">systemd</span>':`<button class="btn compact" data-action="register-service" ${state?.serviceReady?'disabled':''}>${registered?'启动服务':'注册服务'}</button>`}</div>`;}

function ddnsWillPublish(){return !drafts.ddns.clearToken&&(!!state?.ddnsCredentialConfigured||!!drafts.ddns.newToken.trim());}

function ddnsCredential(){const d=drafts.ddns,stored=state?.ddnsCredentialConfigured&&!d.clearToken&&!d.newToken;return `<div class="credential ${stored?'':'new-credential'}">${stored?`<div class="credential-value ${ddnsTokenVisible?'mono revealed':''}">${ddnsTokenVisible?esc(revealedDdnsToken):'已填写'}</div>`:`<input id="ddns-token-input" data-key="newToken" type="${ddnsTokenVisible?'text':'password'}" value="${esc(d.newToken)}" placeholder="${d.clearToken?'保存后清除，可填入新令牌替换':'填入 API Token'}" maxlength="512" autocomplete="new-password">`}<button class="btn compact" data-action="show-ddns-token" ${ddnsTokenReading?'disabled':''}>${icon(ddnsTokenVisible?'eye-off':'eye')}${ddnsTokenReading?'读取中':ddnsTokenVisible?'隐藏':'显示'}</button><button class="btn compact" data-action="clear-ddns-token" ${d.clearToken||!state?.ddnsCredentialConfigured&&!d.newToken?'disabled':''}>${icon('x')}清除</button></div>`;}

function hideDdnsToken(){ddnsTokenVisible=false;revealedDdnsToken='';ddnsTokenReading=false;ddnsTokenReadGeneration++;const shown=document.querySelector?.('.credential-value');if(shown){shown.textContent='已填写';shown.classList.remove('mono','revealed');}const input=$('ddns-token-input');if(input)input.type='password';}

async function showDdnsToken(){
 if(ddnsTokenVisible){hideDdnsToken();renderFields();return;}if(ddnsTokenReading)return;
 if(drafts.ddns.newToken){ddnsTokenVisible=true;renderFields();return;}
 if(drafts.ddns.clearToken||!state?.ddnsCredentialConfigured)return;
 const version=++ddnsTokenReadGeneration;ddnsTokenReading=true;renderFields();
 try{const reply=await api('/api/command',{method:'ddns-token',operationId:crypto.randomUUID()});if(version!==ddnsTokenReadGeneration||page!=='settings'||section!=='ddns')return;if(!reply.ok)throw Error(reply.error||'暂时无法读取令牌');revealedDdnsToken=reply.credential||'';ddnsTokenVisible=!!revealedDdnsToken;}
 finally{if(version===ddnsTokenReadGeneration){ddnsTokenReading=false;if(page==='settings'&&section==='ddns')renderFields();}}
}

async function boot(){document.documentElement.dataset.theme=theme;$('theme-button').innerHTML=icon(theme==='dark'?'sun':'moon');render();try{const ticket=location.hash.slice(1);window.history.replaceState(null,'',location.pathname);const session=await api('/api/session',/^[A-F0-9]{64}$/.test(ticket)?{ticket}:undefined);csrf=session.csrf;await refresh();}catch(e){unavailable(e.message);}setInterval(async()=>{if(expired)return;await refresh();await pollPair();},2000);setInterval(()=>{checkStatusFreshness();updateConnectedTimes();},1000);document.addEventListener('visibilitychange',resumeStatus);window.addEventListener('pageshow',resumeStatus);}
boot();
