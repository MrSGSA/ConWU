'use strict';
const $=id=>document.getElementById(id),esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),icon=name=>`<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`,clone=x=>JSON.parse(JSON.stringify(x)),same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const titles={overview:'概况',create:'创建网络',join:'加入网络',logs:'日志',settings:'设置'},sectionNames={system:'启动与服务',identity:'本机设置',network:'连接设置',coordination:'协调服务器',port:'端口设置',certificate:'证书设置',stun:'STUN 服务器',logging:'日志设置'},sectionIcons={system:'monitor',identity:'laptop',network:'link',coordination:'server',port:'port',certificate:'shield',stun:'globe',logging:'log'};
const defaults={system:{startup:true},identity:{name:'',ipMode:'auto',ip:''},network:{streamFlowLanes:false,protocol:'faketcp',mode:'custom',route:'server',existingRoute:'server',owner:'local',entries:{local:[''],target:['']},refresh:60,unit:1},coordination:{url:''},port:{listen:44680,portControlMapping:false},certificate:{pin:''},stun:{tcp:'',udp:''},logging:{level:'info',terminal:'auto'}};
const heading=(title,description,extra='')=>`<div class="heading"><div><h1 id="page-title">${title}</h1><p>${description}</p></div>${extra}</div>`;
let state=null,online=false,busy=false,busyKind='',expired=false,csrf='',reading=null,generation=0,lastStatusAt=0,lastBackendAt=0,baseRevision='',saved=clone(defaults),drafts=clone(saved),history=null;
let page='overview',section='network',networkActive=false,owner=false,pairCode='',pairExpires=0,invitation='',inviteExpires=0,joinTab='outgoing',joinCodeValue='',joinInviteValue='',joinStatus='',joinName='',joinError='',incoming=false,createdAt=0,theme='dark',toastTimer,testTimer,testGeneration=0,modalCallback=null,networkRoute='server';
let previousTraffic=null,traffic={peers:new Map(),up:null,down:null},historyTraffic=[],logLines=[],lastPairPoll=0,lastPairError='',pairNotice='',pairNoticeTimer,joinModel='',settingsHydrated=false;
let noticeSource='',noticeTimer,lastStatusFailure='',resumeGraceUntil=0,submittedJoin=null;
let expanded=new Set(),dirty=key=>!same(drafts[key],saved[key]),dirtyCount=()=>Object.keys(defaults).filter(dirty).length,localName=()=>state?.deviceName||'正在读取',localIp=()=>state?.virtualIp||'尚未分配',activeRoute=()=>saved.network.mode==='custom'?'server':saved.network.route,protocol=()=>({udp:'直接 UDP',tcp:'纯 TCP',https:'HTTPS'})[saved.network.protocol]||'FakeTCP + HTTP';
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

function navigate(next){page=titles[next]?next:'overview';render();window.scrollTo({top:0,behavior:'instant'});}

function openSettings(next='network'){section=next;navigate('settings');}

function methodCard(){const n=saved.network,mode=n.mode==='existing'?'已有可达入口':'自选服务器',route=activeRoute()==='direct'?'无服务器直连':'自选服务器';return `<article class="card pad"><div class="row between"><div class="section-title">${icon('server')}<h2>当前连接方式</h2></div><button class="text-btn" data-settings="network">更改</button></div><div class="method-rows"><div class="method-row"><span>连接方式</span><span>${mode}</span></div><div class="method-row"><span>网络管理</span><span>${route}</span></div><div class="method-row"><span>连接协议</span><span>${protocol()}</span></div></div></article>`;}

function codeDigits(code){return `<div class="digits">${Array.from({length:6},(_,i)=>`<span class="digit ${code[i]?'filled':''}">${esc(code[i]||'')}</span>`).join('')}</div>`;}

function pairMethodTabs(context){const direct=activeRoute()==='direct',reason=direct?'当前为无服务器连接，配对码不可用。':'当前使用协调服务器，直连邀请不可用。';return `<div class="pair-method-tabs" role="tablist" aria-label="${context==='join'?'加入':'邀请'}方式"><button type="button" role="tab" id="${context}-method-code" data-pair-method="code" aria-selected="${!direct}" aria-controls="${context}-method-panel" class="${!direct?'selected':''}" ${direct?'disabled':''} title="${direct?reason:'使用六位数字配对码'}">${icon('shield')}配对码</button><button type="button" role="tab" id="${context}-method-invite" data-pair-method="invite" aria-selected="${direct}" aria-controls="${context}-method-panel" class="${direct?'selected':''}" ${!direct?'disabled':''} title="${!direct?reason:'使用目标主机生成的直连邀请'}">${icon('link')}直连邀请</button></div>`;}

function createPage(){const isDirect=pairingKind()==='invite',canGenerate=networkActive&&owner&&online&&state?.networkEnabled,leftTitle=isDirect?'本机直连邀请':'本机配对码',activeCode=canGenerate&&pairExpires>Date.now()?pairCode:'';return heading('创建网络','从本机开始，建立你的设备网络。',networkActive?'<span class="badge good"><span class="dot"></span>当前已有网络</span>':'')+`<div class="two-col"><article class="card pad">${pairMethodTabs('create')}<div id="create-method-panel" role="tabpanel" aria-labelledby="create-method-${isDirect?'invite':'code'}"><div class="row between pair-top"><div class="section-title">${icon(isDirect?'link':'shield')}<h2>${leftTitle}</h2></div><button class="btn compact" data-action="generate" ${canGenerate?'':'disabled'}>${isDirect?'生成直连邀请':activeCode?'重新生成':'生成配对码'}</button></div><p class="card-lead">${isDirect?'将邀请私下发送给要加入的设备，收到申请后由你批准。':'将六位配对码发送给要加入的设备，由你确认申请。'}</p>${isDirect?`<div class="pair-display"><div class="invite-display mono" id="generated-invite">${esc(invitation||'生成后，直连邀请会显示在这里')}</div><button class="btn ghost icon-button" data-action="copy-invite" aria-label="复制直连邀请" ${invitation?'':'disabled'}>${icon('copy')}</button></div>`:`<div class="pair-display">${codeDigits(activeCode)}<button class="btn ghost icon-button" data-action="copy-code" aria-label="复制本机配对码" ${activeCode?'':'disabled'}>${icon('copy')}</button></div>`}<div class="hint" id="pair-expiry">${!networkActive?'创建网络后即可生成。':!owner?'由网络创建者生成。':isDirect?(invitation?'5 分钟内有效 · 仍需主机批准加入':'每份邀请用于一台设备；生成后 5 分钟内有效。'):activeCode?'5 分钟内有效 · 仍需主机批准加入':state?.pairing?.expires?'配对码已过期，请重新生成。':'点击生成配对码，再交给另一台设备。'}</div><div class="line"></div><div class="form-actions" data-static-style="u0"><button class="btn primary" data-action="create" ${networkActive?'disabled':''}>${icon('plus')}${networkActive?'当前已有网络':'创建网络'}</button>${networkActive&&owner?'<button class="btn danger" data-action="delete">删除当前网络</button>':''}</div>${networkActive?`<div class="inline-note" data-static-style="u1">${owner?'本机已创建网络。创建新网络前，需要删除或退出当前网络。':'已加入其他设备的网络；需要退出当前网络后才能创建新网络。'}</div><div class="time">${icon('clock')}<span>${owner?'创建':'加入'}成功于 ${new Date(createdAt).toLocaleString('zh-CN',{hour12:false})}</span></div>`:''}<div id="create-error" class="field-error" role="status"></div></div></article><article class="card pad"><div class="section-title">${icon('laptop')}<h2>网络信息</h2></div><p class="card-lead">本机在此网络中的身份与地址。</p><label class="field"><span>本机设备名称</span><div class="read-value"><span>${esc(localName())}</span><button class="text-btn" data-settings="identity">更改</button></div><span class="hint">其他设备会通过这个名称识别你。</span></label><div class="field"><span>本机虚拟 IP</span><div class="read-value mono"><span>${localIp()}</span>${networkActive?`<button class="text-btn" data-action="copy-ip" aria-label="复制本机虚拟 IP">${icon('copy')}</button>`:''}</div></div><div class="method-rows"><div class="method-row"><span>网络角色</span><span>${networkActive?owner?'网络创建者':'网络成员':'尚未组网'}</span></div><div class="method-row"><span>当前状态</span><span>${networkActive?'网络已就绪':'等待创建或加入'}</span></div></div></article></div><div class="bottom-grid"><details class="card disclosure-card" id="create-help"><summary><span class="disclosure-title">${icon('link')}<strong>接下来怎么连接？</strong></span><span class="disclosure-indicator"><span class="when-closed">展开</span><span class="when-open">收起</span>${icon('chevron')}</span></summary><div class="disclosure-content"><ol class="help-steps"><li><span class="step-number">1</span><div><strong>在本机创建网络</strong><p>ConWU 会准备虚拟 IP，随后你可以生成${isDirect?'直连邀请':'本机配对码'}。</p></div></li><li><span class="step-number">2</span><div><strong>${isDirect?'在另一台设备上粘贴本机直连邀请':'在另一台设备上输入本机配对码'}</strong><p>${isDirect?'在要加入本机网络的设备上的“加入网络”部分中，选择“直连邀请”，粘贴本机生成的链接。':'在要加入本机网络的设备上的“加入网络”部分中，选择“配对码”，输入本机配对码。'}</p></div></li><li><span class="step-number">3</span><div><strong>核对申请，再同意加入</strong><p>收到申请后，确认设备名称与校验码，再批准加入。</p></div></li></ol></div></details>${methodCard()}</div>`;}

function joinPage(){
 const direct=activeRoute()==='direct';
 return heading('加入网络','加入目标主机的网络，或处理收到的加入申请。')+`<div class="segmented" role="tablist" aria-label="加入网络方式"><button role="tab" data-join-tab="outgoing" aria-selected="${joinTab==='outgoing'}" class="${joinTab==='outgoing'?'active':''}">加入其他网络</button><button role="tab" data-join-tab="incoming" aria-selected="${joinTab==='incoming'}" class="${joinTab==='incoming'?'active':''}">收到的申请${incoming&&owner&&networkActive?' · 1':''}</button></div>${joinTab==='incoming'?incomingPage():`<div class="two-col"><article class="card pad" id="join-card">${pairMethodTabs('join')}<div id="join-method-panel" class="pair-method-panel" role="tabpanel" aria-labelledby="join-method-${direct?'invite':'code'}">${joinStatus?waitingView():`<h2>${direct?'输入目标主机的直连邀请':'输入目标主机的配对码'}</h2><p class="card-lead">${direct?'粘贴主机生成的邀请，发送申请后等待主机批准。':'双方使用同一个 HTTPS 协调服务器，再发送加入申请。'}</p><form id="join-form"><label class="field"><span id="join-input-label">${direct?'目标主机的直连邀请':'请输入目标主机生成的配对码'}</span>${direct?`<textarea id="join-invite" rows="4" wrap="off" class="mono" spellcheck="false" placeholder="粘贴目标主机生成的直连邀请" aria-label="目标主机的直连邀请">${esc(joinInviteValue)}</textarea>`:`<div class="digits-input">${codeDigits(/^\d*$/.test(joinCodeValue)?joinCodeValue:'')}<input id="join-code" value="${esc(joinCodeValue)}" inputmode="numeric" autocomplete="off" aria-label="目标主机的六位配对码"></div>`}<span class="hint" id="join-input-hint">${direct?'邀请会带入主机入口；本机无需填写公网入口。':'仅接受六位数字配对码，支持直接粘贴。'}</span></label><label class="field"><span>本机设备名称</span><input id="join-device-name" value="${esc(joinName||localName())}" maxlength="64" autocomplete="off"></label>${networkActive?`<div class="field"><span>本机当前虚拟 IP</span><div class="read-value mono">${localIp()}</div></div><div class="locked-note">${icon('lock')}<span>需要退出当前网络后，才能申请加入其他网络。</span></div>`:''}<div class="form-actions"><button class="btn primary" id="join-submit" type="submit" ${networkActive?'disabled':''}>请求加入${icon('join')}</button></div><div class="field-error" id="join-error" role="status">${esc(joinError)}</div></form>`}</div></article><div class="stack">${methodCard()}${joinMethodHelp()}</div></div>`}`;
}

function joinMethodHelp() {
  const direct = activeRoute() === 'direct';
  const steps = direct ? [
    ['获取目标主机的直连邀请', '请目标主机在“创建网络”中生成直连邀请，并私下发送给你。'],
    ['粘贴邀请，发送申请', '在本页“直连邀请”中粘贴链接，填写本机设备名称，再点击“请求加入”。主机入口会由邀请自动带入。'],
    ['核对申请，等待主机批准', '与主机核对设备名称和校验码。主机同意后，ConWU 会建立直连并显示连接进度。']
  ] : [
    ['确认使用同一个协调服务器', '各台设备在“设置 → 协调服务器”中填写同一个 HTTPS 地址。'],
    ['输入目标主机的配对码', '请目标主机生成六位配对码，在本页输入，填写本机设备名称，再点击“请求加入”。'],
    ['核对申请，等待主机批准', '与主机核对设备名称和校验码。主机同意后，ConWU 会建立直连并显示连接进度。']
  ];
  return `<details class="card disclosure-card join-help" id="join-help"><summary><span class="disclosure-title">${icon('shield')}<strong>加入方式</strong></span><span class="disclosure-indicator"><span class="when-closed">展开</span><span class="when-open">收起</span>${icon('chevron')}</span></summary><div class="disclosure-content"><ol class="help-steps">${steps.map(([title, text], index) => `<li><span class="step-number">${index + 1}</span><div><strong>${title}</strong><p>${text}</p></div></li>`).join('')}</ol></div></details>`;
}

function lockNote(text='当前网络的配对方式已固定。需要退出当前网络后才能修改。'){return networkActive?`<div class="locked-note">${icon('lock')}<span>${text} <button class="text-btn" data-action="leave">退出网络</button></span></div>`:'';}

function settingsPage() {
  const count = dirtyCount();
  return heading('设置', '统一保存所有分区的更改。', `<span id="global-dirty-count" class="badge warm" ${count ? '' : 'hidden'}>${count} 个部分有未保存更改</span>`) + `<div class="settings-layout">
    <aside class="settings-rail"><nav class="settings-nav" aria-label="设置分区">${Object.entries(sectionNames).map(([key, title]) => `<button class="${section === key ? 'active' : ''}" data-section="${key}" ${section === key ? 'aria-current="page"' : ''}>${title}<span data-section-dot="${key}" class="dirty-mark" ${dirty(key) ? '' : 'hidden'}></span></button>`).join('')}</nav>
    <div class="settings-tools"><div id="save-state" class="save-state" role="status"></div><button class="btn primary" id="save-section" data-action="save">${icon('save')}保存全部设置</button><button class="btn" id="revert-section" data-action="revert" title="恢复所有分区尚未保存的修改；保存后可调回前一组完整设置">${icon('undo')}恢复刚才设置</button><button class="btn" id="default-section" data-action="defaults" title="填入全部分区的默认设置，保存后才会生效">${icon('refresh')}恢复默认设置</button><p class="settings-note">统一保存全部更改。<br>恢复设置后也需点击保存。</p></div></aside>
    <article class="card settings-panel"><div class="pad"><div class="settings-title">${icon(sectionIcons[section])}<h2>${sectionNames[section]}</h2></div><p class="card-lead">${{system:'管理开机启动与后台服务。',identity:'设置设备名称与虚拟网络地址。',network:'选择连接协议、组网方式和已有入口。',coordination:'配置各台设备用于配对与审批的 HTTPS 协调地址。',port:'设置本机接收连接的端口。',certificate:'管理 HTTPS 协调服务器的证书校验。',stun:'自主打洞时使用的地址发现服务。',logging:'选择日志详细程度与终端外观。'}[section]}</p><div id="settings-fields" data-static-style="u2">${sectionFields()}</div><div id="settings-error" class="field-error" role="status"></div></div></article>
  </div>`;
}

function effectiveDefaults(key){const value=clone(defaults[key]);if(networkActive&&key==='network'){value.route=saved.network.route;if(saved.network.route==='direct'){value.mode='existing';value.entries.local=clone(saved.network.entries.local);}}if(networkActive&&activeRoute()==='server'&&key==='coordination')value.url=saved.coordination.url;if(networkActive&&key==='certificate')value.pin=saved.certificate.pin;return value;}

function refreshSettingsTools() {
  if (page !== 'settings') return;
  const count = dirtyCount(), changed = count > 0, canUndo = !!history && !same(history, saved);
  $('save-state').className = 'save-state' + (changed ? ' dirty' : '');
  $('save-state').innerHTML = changed ? `<span class="dot amber"></span>${count} 个部分未保存` : icon('check') + '全部已保存';
  $('save-section').disabled = !changed;
  $('revert-section').disabled = !changed && !canUndo;
  $('default-section').disabled = Object.keys(defaults).every(key => same(drafts[key], effectiveDefaults(key)));
  for (const key of Object.keys(sectionNames)) document.querySelector(`[data-section-dot="${key}"]`).hidden = !dirty(key);
  $('settings-dirty-dot').hidden = !changed;
  const badge = $('global-dirty-count');
  badge.hidden = !changed;
  badge.textContent = count + ' 个部分有未保存更改';
}

function baseSectionFields(){const d=drafts[section];if(section==='system')return `<div class="switch-row"><div><h3>开机启动</h3><p class="hint">登录 Windows 后启动托盘，后台连接由服务维持。</p></div>${switchControl('startup',d.startup,'开机启动')}</div><div class="switch-row"><div><div class="row"><h3>注册为服务</h3><span class="badge ${saved.system.service?'good':''}">${saved.system.service?'已注册 · 正在运行':'尚未注册'}</span></div><p class="hint">无需保持 WebUI 打开；保存时按需请求管理员权限。</p></div>${switchControl('service',d.service,'注册为服务')}</div>`;
 if(section==='identity')return `<label class="field"><span>设备名称</span><input data-key="name" id="device-name" value="${esc(d.name)}" maxlength="64" autocomplete="off"><span class="hint">用于网络设备列表和加入申请。</span></label><div class="field"><span>虚拟 IP 分配</span><div class="radio-row"><label><input type="radio" name="ip-mode" value="auto" data-key="ipMode" ${d.ipMode==='auto'?'checked':''}>自动分配</label><label><input type="radio" name="ip-mode" value="custom" data-key="ipMode" ${d.ipMode==='custom'?'checked':''}>自定义 IP</label></div></div>${d.ipMode==='custom'?`<label class="field"><span>期望的虚拟 IP</span><input data-key="ip" class="mono" value="${esc(d.ip)}" placeholder="10.171.139.1"><span class="hint">下次创建或加入网络时生效；加入时由主机统一分配，避免网段冲突。</span></label>`:''}`;
 if(section==='network')return networkFields();
 if(section==='coordination')return coordinationFields();
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

function networkFields() {
  const d = drafts.network, existing = d.mode === 'existing', target = d.owner !== 'local', direct = d.route === 'direct';
  return `<label class="field"><span>连接协议</span><select data-key="protocol" id="protocol"><option value="faketcp" ${d.protocol === 'faketcp' ? 'selected' : ''}>FakeTCP + HTTP</option><option value="phantun" ${d.protocol === 'phantun' ? 'selected' : ''}>Phantun</option><option value="mimic" ${d.protocol === 'mimic' ? 'selected' : ''}>Mimic（实验）</option><option value="tcpraw" ${d.protocol === 'tcpraw' ? 'selected' : ''}>TCPRAW（实验）</option><option value="tcp" ${d.protocol === 'tcp' ? 'selected' : ''}>纯 TCP</option><option value="https" ${d.protocol === 'https' ? 'selected' : ''}>HTTPS</option><option value="udp" ${d.protocol === 'udp' ? 'selected' : ''}>直接 UDP</option></select><span class="hint">两端保持一致。仅使用所选协议，不自动回退。</span></label>
  <div class="field"><span>连接方式</span><div class="mode-choices" role="radiogroup" aria-label="连接方式">
    <label class="mode-choice disabled"><input type="radio" name="mode" value="public" disabled><span class="choice-check"></span>${icon('globe')}<strong>公共服务器</strong><span class="choice-detail">暂未提供</span></label>
    <label class="mode-choice ${d.mode === 'custom' ? 'selected' : ''}"><input type="radio" name="mode" data-key="mode" value="custom" ${d.mode === 'custom' ? 'checked' : ''}><span class="choice-check"></span>${icon('server')}<strong>自选服务器</strong><span class="choice-detail">使用自定义服务器来创建/加入网络</span></label>
    <label class="mode-choice ${existing ? 'selected' : ''}"><input type="radio" name="mode" data-key="mode" value="existing" ${existing ? 'checked' : ''}><span class="choice-check"></span>${icon('link')}<strong>已有可达入口</strong><span class="choice-detail">使用公网、端口映射或已有打洞地址</span></label>
  </div></div>
  ${!existing ? coordinationNotice() : `<section class="entry-box" aria-labelledby="entry-title">
    <h3 id="entry-title">已有可达入口</h3>
    <label class="field"><span>这些入口属于</span><select data-key="owner" id="entry-owner">${entryOwnerOptions(d)}</select></label>
    ${entryEditor(d, target)}
    ${!(target && direct) ? `<div class="field"><span>订阅自动更新间隔</span><div class="refresh-grid"><input type="number" data-key="refresh" aria-label="自动更新间隔数值" min="1" max="86400" value="${d.refresh}"><select data-key="unit" aria-label="自动更新间隔单位"><option value="1" ${Number(d.unit) === 1 ? 'selected' : ''}>秒</option><option value="60" ${Number(d.unit) === 60 ? 'selected' : ''}>分钟</option><option value="3600" ${Number(d.unit) === 3600 ? 'selected' : ''}>小时</option></select></div><span class="hint">范围 1 秒至 24 小时。订阅和域名定时更新；地址变化时更新候选，保持健康连接。</span></div>` : ''}
    ${formatHelp(d)}
  </section>`}`;
}

function entryCoordination(d, target) {
  const direct = d.route === 'direct';
  const description = direct
    ? target ? '已关闭：在“加入网络”中使用目标主机生成的直连邀请。' : '已关闭：本机使用已有入口，生成直连邀请。'
    : target ? '已开启：通过协调服务器配对，目标主机入口用于直连。' : '已开启：本机通过服务器配对，已有入口负责直连。';
  return `<div class="entry-coordination" aria-label="此入口的协调方式">
    <div class="switch-row"><div><h3>使用 HTTPS 协调服务器</h3><p class="hint">${description}</p></div>${switchControl('useServer', !direct, '使用 HTTPS 协调服务器', networkActive)}</div>
    ${lockNote()}
    ${!direct ? coordinationNotice() : ''}
  </div>`;
}

function entryEditor(d, target) {
  const values = d.entries[d.owner] || [''], invitationOnly = target && d.route === 'direct';
  return `<section class="entry-source-panel ${target ? 'coordination-first' : ''}" aria-labelledby="entry-source-title">
    ${target ? entryCoordination(d, target) : ''}
    <h3 class="entry-source-title" id="entry-source-title">${icon('link')}${target ? '目标主机入口' : '本机入口地址'}</h3>
    ${invitationOnly ? `<div class="inline-note entry-invite-note">请在“加入网络”中输入目标主机所生成的直连邀请链接。</div><button class="text-btn" data-page="join" data-static-style="u8">前往加入网络${icon('chevron')}</button>` : `<div id="entry-rows" class="entry-rows">${values.map((v, i) => entryRow(v, i, values.length)).join('')}</div><p class="hint">${target ? '填写目标主机的入口：如目标主机的公网 IP:端口、您自己打洞得到的地址:端口或相关的更新/订阅链接。' : '输入本机的公网地址:端口、您自己打洞得到的地址:端口或相关的更新/订阅链接。'}</p><div class="test-row"><button class="btn compact" data-action="test" id="test-addresses" ${values.some(v => v.trim()) ? '' : 'disabled'}>${icon('refresh')}测试地址</button><span class="small muted" id="test-status" role="status">${values.filter(v => v.trim()).length} 个地址来源</span></div><div id="test-results" class="result-list" aria-live="polite"></div>`}
    ${!target ? entryCoordination(d, target) : ''}
  </section>`;
}

function entryRow(value,index,length){const total=Object.values(drafts.network.entries).flat().filter(v=>v.trim()).length;return `<div class="entry-row"><input value="${esc(value)}" data-entry-index="${index}" aria-label="入口地址 ${index+1}" spellcheck="false" autocomplete="off" placeholder="IP:端口、域名:端口或 HTTPS/TXT 等订阅链接">${length>1?`<button class="btn icon-button remove" data-remove-entry="${index}" aria-label="删除第 ${index+1} 个地址">${icon('x')}</button>`:''}${index===length-1?`<button class="btn icon-button" data-action="add-entry" aria-label="添加入口地址" ${total>=12?'disabled':''}>${icon('plus')}</button>`:''}</div>`;}

function formatHelp(d){return `<details><summary>支持的格式与转发要求</summary><div class="details-body"><h4>1. 直接填写可达地址</h4><p>填写实际通向对应设备 ConWU 的地址，不限定打洞工具，也支持本身有公网地址的设备。</p><pre>203.0.113.42:44680\nedge.example.com:44680</pre><h4>2. 地址会变时，填写更新/订阅链接</h4><p>推荐使用有读取凭据的 HTTPS 链接。软件按更新间隔读取最新地址；也兼容 TXT 来源。</p><pre>https://entry.example.com/streamlink?token=只读凭据\ntxt://entry.example.com</pre><p>专用订阅可以返回纯地址列表或 JSON：<code>{"endpoints":["203.0.113.42:44680"]}</code>。</p><p>多个应用共用一个订阅时，在 ConWU 地址前加 <code>streamlink=</code>；在订阅链接末尾加 <code>#streamlink</code>，只读取带该标签的地址。找不到标签会明确报错。</p><pre>streamlink=203.0.113.42:44680\nhttps://entry.example.com/entries?token=只读凭据#streamlink</pre><h4>3. 映射到 ConWU 接收端口</h4><p>端口映射应转发到对应设备的 ConWU 接收端口（本机当前为 <code>${esc(saved.port.listen)}</code>），并兼容所选协议。映射工具自身的管理端口不能用来代替它。</p><p>加入端无需拥有自己的公网入口。最多保存 12 项地址来源。${d.route==='server'?'此模式只通过已有入口连接，不执行 STUN、自动映射或自主打洞。入口不可用时，请检查入口，或手动切换到自选服务器模式。':'无服务器时，主机在直连邀请中提供入口。'}</p><p>“测试地址”帮助检查来源，连接后仍需通过设备认证和双向通信验证。</p></div></details>`;}

function bindSectionValidation(){document.querySelectorAll('#settings-fields input,#settings-fields select,#settings-fields textarea').forEach(el=>el.addEventListener('invalid',()=>{$('settings-error').textContent='请检查输入内容。';}));}

function renderFields() {
  const focused = document.activeElement, key = focused?.dataset?.key;
  clearTimeout(testTimer); testGeneration++;
  $('settings-fields').innerHTML = sectionFields(); $('settings-error').textContent = '';
  refreshEntryTargets();
  refreshSettingsTools(); bindSectionValidation();
  if (key) document.querySelector(`#settings-fields [data-key="${CSS.escape(key)}"]`)?.focus({ preventScroll: true });
}

function inputChange(el){if(!['settings','create'].includes(page))return;if(el.matches('[data-entry-index]')){drafts.network.entries[drafts.network.owner][Number(el.dataset.entryIndex)]=el.value;refreshSettingsTools();if($('test-addresses'))$('test-addresses').disabled=!drafts.network.entries[drafts.network.owner].some(v=>v.trim());if($('test-status'))$('test-status').textContent=drafts.network.entries[drafts.network.owner].filter(v=>v.trim()).length+' 个地址来源';if($('test-results'))$('test-results').innerHTML='';clearTimeout(testTimer);testGeneration++;return;}const key=el.dataset.key;if(!key)return;const before=clone(drafts[section]);let value=el.type==='checkbox'?el.checked:el.type==='number'?el.value===''?'':Number(el.value):el.value;if(key==='useServer'){drafts.network.route=value?'server':'direct';drafts.network.existingRoute=drafts.network.route;}else drafts[section][key]=value;if(key==="owner"&&!drafts.network.entries[value])drafts.network.entries[value]=[""];if(section==='network'&&key==='mode'){if(value==='custom'){drafts.network.existingRoute=before.route;drafts.network.route='server';}else drafts.network.route=networkActive?saved.network.route:drafts.network.existingRoute||'server';}if(networkActive&&section==='network'&&drafts.network.route!==saved.network.route){drafts.network=before;notify('需要退出当前网络后才能更改配对方式。');renderFields();return;}if(['mode','route','owner','useServer','ipMode'].includes(key)){renderFields();return;}if(section==='port'&&$('port-example'))$('port-example').textContent=String(value||'—');refreshSettingsTools();if($('settings-error'))$('settings-error').textContent='';}

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
  if (key === 'network') {
    if (networkActive && (d.mode === 'custom' || d.route === 'server') && !configuration.coordination.url.trim()) return '当前网络需要有效的协调地址，请在“协调服务器”中填写。';
    const interval = Number(d.refresh) * Number(d.unit);
    if (!Number.isInteger(interval) || interval < 1 || interval > 86400) return '自动更新间隔应为 1 秒至 24 小时。';
    if (Object.values(d.entries).flat().filter(value => value.trim()).length > 12) return '最多保存 12 项地址来源。';
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
  const reply=await result.json();
  // A valid reply still proves backend responsiveness when its state belongs
  // to a superseded UI generation. Never apply that older state to the form.
  if(/^\/(?:admin\/)?api\/(?:status(?:\?|$)|command$)/.test(path)&&typeof reply?.ok==='boolean'&&reply.status)lastBackendAt=performance.now();
  return reply;
 }catch(error){if(error.name==='AbortError'||error instanceof TypeError){const pending=Error('本机后台暂未响应，操作结果尚待确认；正在自动刷新。');pending.retryable=true;throw pending;}throw error;}finally{clearTimeout(timer);}
}

async function command(method,extra={},quiet=false){
 if(busy)throw Error('上一项操作仍在进行，请稍候。');if(!online)throw Error('请先恢复面板与后台的连接。');
 busy=true;busyKind=method==='network'&&extra.network?.action==='settings'?'settings-save':quiet?'background':'action';generation++;joinError='';if($('join-error'))$('join-error').textContent='';controls();if(!quiet)notice(method==='register-service'?'请在 Windows 授权窗口确认服务操作…':'正在处理，请稍候…');
 try{
  const operationId=crypto.randomUUID();let reply;
  try{reply=await api('/api/command',{method,operationId,...extra});}
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
    await new Promise(r=>setTimeout(r,700));let progress;
    try{progress=await api('/api/status?operation='+encodeURIComponent(operation.id));}
    catch(error){
     if(!error.retryable)throw error;
     // Retry observation only. An accepted mutation must never be resubmitted.
     if(!quiet)notice('后台已受理，暂时无法读取进度，正在重试…');continue;
    }
    if(!progress.ok)throw Error(progress.error||'无法读取操作结果');
    if(progress.status)render(progress.status);
    if(!quiet&&progress.operation?.id===operation.id&&!progress.operation.completed)notice(progress.operation.phase||'后台正在处理，请稍候…');
    if(progress.operation?.id===operation.id&&progress.operation.completed){reply={...progress,ok:!progress.operation.error,error:progress.operation.error};break;}
   }
   if(!reply.operation?.completed)throw Error('后台结果尚未确认，请刷新状态确认结果后再操作。');
  }
  generation++;if(reply.status)render(reply.status);else if(reply.statusNotice)unavailable(reply.statusNotice);
  if(!reply.ok)throw Error(reply.error||'操作未完成');if(!quiet&&online)notice('');return reply;
 }
 finally{busy=false;busyKind='';controls();void refresh();}
}

async function refresh(){
 if(reading||expired||!csrf)return reading;const version=generation;
 reading=(async()=>{try{const reply=await api('/api/status',undefined,()=>version===generation);if(version!==generation)return;if(!reply.ok||!reply.status)throw Error(reply.error||reply.statusNotice||'未收到完整状态');render(reply.status);}catch(error){if(version!==generation)return;lastStatusFailure=error.message;if(!error.retryable||['NotInstalled','Stopped','AccessDenied'].includes(error.backendCode)||!lastStatusAt||!document.hidden&&performance.now()>=resumeGraceUntil&&performance.now()-Math.max(lastStatusAt,lastBackendAt)>10000)unavailable(error.message);}})().finally(()=>{reading=null;if(!expired&&version!==generation)queueMicrotask(()=>void refresh());});return reading;
}

function checkStatusFreshness(){if(!document.hidden&&performance.now()>=resumeGraceUntil&&online&&performance.now()-Math.max(lastStatusAt,lastBackendAt)>10000)unavailable(lastStatusFailure||'超过 10 秒未收到后台状态，正在自动重试。');}
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
 const p=s.settings||{},entries={local:[''],target:['']};
 for(const e of p.existingEntries||[]){const key=e.peerSlot===0?'local':(e.peerSlot===-1||e.peerSlot===1&&!s.isOwner)?'target':'peer'+e.peerSlot;if(!entries[key]||entries[key].length===1&&!entries[key][0])entries[key]=[];entries[key].push(e.source);}
 let selected='local',terminal='auto',existingRoute=p.directMode?'direct':'server',preferredUnit=0;try{selected=localStorage.getItem('streamlink-entry-owner')||'local';terminal=localStorage.getItem('streamlink-terminal-theme')||'auto';if(p.connectionSource!=='existing')existingRoute=existingRoute;preferredUnit=Number(localStorage.getItem('streamlink-entry-refresh-unit'));}catch{}
 if(!entries[selected])selected='local';if(!entries.local.some(v=>v.trim())&&entries.target.some(v=>v.trim()))selected='target';
 const seconds=p.entryRefreshSeconds||60,unit=[1,60,3600].includes(preferredUnit)&&seconds%preferredUnit===0?preferredUnit:seconds%3600===0?3600:seconds%60===0?60:1;
 return {system:{startup:!!s.desktop?.autoStart},identity:{name:s.deviceName,ipMode:p.requestedVirtualIp?'custom':'auto',ip:p.requestedVirtualIp||''},network:{streamFlowLanes:p.streamFlowLanes===true,protocol:({'udp-only':'udp','tcp-only':'tcp','https-only':'https','phantun-only':'phantun','mimic-only':'mimic','tcpraw-only':'tcpraw'})[p.pathSelection]||'faketcp',mode:p.connectionSource||'custom',route:p.directMode?'direct':'server',existingRoute:['direct','server'].includes(existingRoute)?existingRoute:'server',owner:selected,entries,refresh:seconds/unit,unit},coordination:{url:p.service||''},port:{listen:p.listenPort||44680,portControlMapping:p.portControlMapping===true},certificate:{pin:p.certificatePin||''},stun:{tcp:(p.tcpStun||[]).join('\n'),udp:(p.udpStun||[]).join('\n')},logging:{level:s.logLevel||'info',terminal:['auto','light','dark'].includes(terminal)?terminal:'auto'}};
}
function entryOwnerOptions(d){
 const options=[['local','本机入口 · 供其他设备连接'],['target','目标主机的入口 · 用于连接到目标主机。']];
 for(const peer of state?.peers||[])if((state.isOwner||peer.slot!==1)&&!(state.inactiveEntrySlots||[]).includes(peer.slot))options.push(['peer'+peer.slot,peer.name+' · 用于连接到这台设备']);
 for(const key of Object.keys(d.entries))if(key.startsWith('peer')&&!options.some(o=>o[0]===key))options.push([key,'已移出设备 '+key.slice(4)+' · 清空地址可删除']);
 return options.map(([key,label])=>`<option value="${esc(key)}" ${d.owner===key?'selected':''}>${esc(label)}</option>`).join('');
}
function refreshEntryTargets(){const targets=$('entry-owner');if(!targets)return;const options=entryOwnerOptions(drafts.network);if(targets.dataset.options!==options){targets.innerHTML=options;targets.dataset.options=options;}}
function settingsDto(){
 const n=drafts.network,lines=value=>value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),slot=key=>key==='local'?0:key==='target'?-1:Number(key.slice(4));
 let service=drafts.coordination.url.trim();if(service&&!service.includes('://'))service='https://'+service;
 if(service){let uri=new URL(service);if(uri.protocol!=='https:'||uri.username||uri.password||uri.search||uri.hash)throw Error('协调地址需使用 HTTPS，且不能包含账号、查询参数或片段。');if(!uri.pathname.endsWith('/'))uri.pathname+='/';service=uri.toString();}
 return {...state.settings,service,certificatePin:drafts.certificate.pin.trim(),manualEndpoint:'',streamFlowLanes:n.streamFlowLanes===true,portControlMapping:drafts.port.portControlMapping===true,pathSelection:({faketcp:'faketcp-only',udp:'udp-only',tcp:'tcp-only',https:'https-only',phantun:'phantun-only',mimic:'mimic-only',tcpraw:'tcpraw-only'})[n.protocol],connectionSource:n.mode,directMode:n.mode==='existing'&&n.route==='direct',existingEntries:Object.entries(n.entries).flatMap(([key,values])=>values.map(v=>v.trim()).filter(Boolean).map(source=>({peerSlot:slot(key),source}))),entryRefreshSeconds:Number(n.refresh)*Number(n.unit),listenPort:Number(drafts.port.listen),requestedVirtualIp:drafts.identity.ipMode==='custom'?drafts.identity.ip.trim():'',tcpStun:lines(drafts.stun.tcp),udpStun:lines(drafts.stun.udp)};
}
function updateShell(){
 document.querySelectorAll('.nav[data-page]').forEach(e=>{const active=e.dataset.page===page;e.classList.toggle('active',active);if(active)e.setAttribute('aria-current','page');else e.removeAttribute('aria-current');});
 $('breadcrumb').textContent=titles[page];document.title=titles[page]+' · ConWU';$('sidebar-name').textContent=localName();$('sidebar-initials').textContent=(localName().slice(0,2)||'SL').toUpperCase();
 const peers=state?.peers||[],live=peers.filter(p=>p.connected).length;
 $('sidebar-state').innerHTML=networkActive?`<div class="row"><span class="dot ${live?'':'amber'}"></span><span>${owner?'本机创建的网络':'已加入的网络'}</span></div><div class="small dim">${peers.length+1} 台设备</div><div class="small dim">与其余 ${online?live:0} 台设备直连</div>`:'<div class="row"><span class="dot amber"></span><span>尚未加入网络</span></div>';
 $('request-dot').hidden=!incoming;document.querySelector('.nav[data-page="join"]').setAttribute('aria-label',incoming?'加入网络，有新加入申请':'加入网络');$('settings-dirty-dot').hidden=!dirtyCount();document.body.classList.toggle('settings-open',page==='settings');
 $('backend-state').textContent=expired?'面板授权已过期':!online?'后台状态未更新':state?.serviceReady?'后台运行中':state?.state||'正在读取后台';$('app-version').textContent=state?.version?'v'+state.version.split('+')[0]:'';
}
function render(next){
 if(expired&&next){controls();return;}
 let settingsChanged=false;
 if(next&&typeof next==='object'&&'deviceName'in next){
  const first=!state,oldNetwork=state?.networkId,priorJoin=joinModel;state=next;online=true;lastStatusAt=performance.now();lastStatusFailure='';networkActive=!!state.networkId;owner=!!state.isOwner;createdAt=(state.networkEstablishedAt||0)*1000;
  if(noticeSource==='backend')notice('');
  if(noticeSource==='pair'&&!state.pairing?.active){lastPairError='';notice('');}
  if(oldNetwork!==state.networkId){previousTraffic=null;historyTraffic=[];expanded.clear();pairNotice='';if(submittedJoin){if(submittedJoin.direct&&joinInviteValue.replace(/\s/g,'')===submittedJoin.code)joinInviteValue='';if(!submittedJoin.direct&&joinCodeValue.replace(/\s/g,'')===submittedJoin.code)joinCodeValue='';}if(submittedJoin||joinStatus==='waiting')joinName='';submittedJoin=null;joinError=lastPairError='';joinTab='outgoing';lastPairPoll=0;clearTimeout(pairNoticeTimer);}
  traffic=rates(state);appendStatusLogs(state);
  if(!settingsHydrated||!dirtyCount()){const configuration=configFromStatus(state);settingsChanged=!same(saved,configuration);saved=configuration;drafts=clone(saved);baseRevision=state.settingsRevision||'';settingsHydrated=true;if(!defaults.identity.name)defaults.identity.name=state.deviceName;}
  const p=state.pairing,live=p?.active&&p.expires*1000>Date.now();pairCode=live&&p.owner&&!p.code.startsWith('SL')?p.code:'';pairExpires=live?p.expires*1000:0;invitation=live&&p.owner&&p.code.startsWith('SL6.')?p.code:'';inviteExpires=pairExpires;
  incoming=!!(live&&p.owner&&p.candidate);joinStatus=live&&!p.owner?'waiting':'';joinModel=JSON.stringify([state.networkId,state.networkEnabled,state.settings?.directMode,state.settings?.connectionSource,p]);updateShell();
  if((page==='settings'||page==='create')&&!first&&oldNetwork===state.networkId&&$('settings-fields')){if(settingsChanged)renderFields();else{refreshSettingsTools();refreshEntryTargets();}const service=$('service-live-status');if(service)service.textContent=state.desktop?.serviceRegistered?(state.serviceReady?'已注册 · 正在运行':'已注册 · 已停止'):'尚未注册';controls();return;}
  if(page==='join'&&!first&&priorJoin===joinModel&&$('join-card')){controls();return;}
  if(page==='logs'&&!first&&$('terminal-lines')){updateLogView();controls();return;}
 }
 updateShell();const focused=document.activeElement,restore=focused&&$('content').contains(focused)?focused.dataset?.action:null;
 $('content').innerHTML=({overview:overviewPage,create:createPage,join:joinPage,logs:logsPage,settings:settingsPage})[page]();
 if((page==='settings'||page==='create')&&$('settings-fields')){refreshSettingsTools();refreshEntryTargets();bindSectionValidation();}if(page==='join')bindJoinInput();if(page==='logs')updateLogView();controls();
 if(restore)$('content').querySelector(`[data-action="${CSS.escape(restore)}"]:not(:disabled)`)?.focus({preventScroll:true});
}
function controls(){
 const ready=online&&!expired&&state?.serviceReady&&!busy;
 document.querySelectorAll('[data-action="create"],[data-action="generate"],[data-action="delete"],[data-action="leave"],[data-action="approve"],[data-action="reject"],[data-action="cancel-join"],[data-action="network-toggle"],[data-action="retry"],#join-submit,#save-section').forEach(e=>{e.disabled=!ready;});
 if($('save-section'))$('save-section').disabled=!ready||!dirtyCount();if($('revert-section'))$('revert-section').disabled=busy||!dirtyCount()&&(!history||same(history,saved));if($('default-section'))$('default-section').disabled=busy||Object.keys(defaults).every(k=>same(drafts[k],effectiveDefaults(k)));
 const fields=$('settings-fields');if(fields){const locked=busy&&busyKind==='settings-save';fields.inert=locked;fields.classList.toggle('global-busy',locked);}
 document.querySelector('.nav[data-action="leave"]').disabled=!ready||!networkActive;
 for(const key of ['create','generate','delete']){const b=document.querySelector(`[data-action="${key}"]`);if(b)b.disabled=!ready||(key==='create'?networkActive:!networkActive||key==='generate'&&(!owner||!state.networkEnabled));}
 if($('join-submit'))$('join-submit').disabled=!ready||networkActive;
 const approve=document.querySelector('[data-action="approve"]');if(approve)approve.disabled=!ready||!state.pairing?.verification;
 const service=document.querySelector('[data-action="register-service"]');if(service)service.disabled=busy||!online||!!state?.serviceReady;
 const retry=document.querySelector('[data-action="retry"]');if(retry)retry.disabled=!ready||!state?.networkEnabled;
 const test=$('test-addresses');if(test)test.disabled=!ready||!(drafts.network.entries[drafts.network.owner]||[]).some(v=>v.trim());
 document.querySelectorAll('[data-action="revoke"]').forEach(e=>e.disabled=!ready||!owner);
}
function sectionFields(){
 if(section!=='system')return baseSectionFields();
 const d=state?.desktop,registered=!!d?.serviceRegistered;
 return `<div class="switch-row"><div><h3>开机启动</h3><p class="hint">随 Windows 启动后台服务，登录后显示托盘。</p></div>${switchControl('startup',drafts.system.startup,'开机启动')}</div><div class="switch-row"><div><div class="row"><h3>后台服务</h3><span class="badge ${state?.serviceReady?'good':''}" id="service-live-status">${registered?(state.serviceReady?'已注册 · 正在运行':'已注册 · 已停止'):'尚未注册'}</span></div><p class="hint">注册或启动服务时，Windows 会请求管理员确认。</p></div><button class="btn compact" data-action="register-service" ${state?.serviceReady?'disabled':''}>${registered?'启动服务':'注册服务'}</button></div>`;
}
function overviewPage(){
 const peers=state?.peers||[],live=peers.filter(p=>p.connected),status=online?(state?.state||'正在读取后台'):'状态待确认';
 if(!networkActive)return heading('概况','所有设备与连接状态，尽在这里。')+`<article class="card pad empty-state">${icon('link')}<h2>${state?.serviceReady?'先把设备连起来':'正在等待后台就绪'}</h2><p>${state?.serviceReady?'创建一个网络，或加入目标主机的网络。':esc(state?.state||'正在读取本机后台状态。')}</p><div class="form-actions" data-static-style="u9"><button class="btn primary" data-page="create">创建网络</button><button class="btn" data-page="join">加入网络</button></div></article>`;
 const steps=state.connection,progress=state.networkEnabled&&steps&&!['Idle','Connected'].includes(steps.phase),up=peers.reduce((n,p)=>n+p.sentBytes,0),down=peers.reduce((n,p)=>n+p.receivedBytes,0);
 return heading('概况','本机与网络内设备的连接状态。',`<div class="row wrap"><span class="badge ${live.length?'good':''}">${esc(status)}</span><button class="btn compact" data-action="network-toggle">${state.networkEnabled?'断开网络':'连接网络'}</button>${steps?.canRetry?'<button class="btn compact" data-action="retry">重新尝试</button>':''}</div>`)+
 (progress?`<article class="card pad" data-static-style="u10" role="status"><div class="row between"><h2>${esc(phaseNames[steps.phase]||steps.phase)}</h2><span class="small muted">${duration(steps.elapsedMs||0)}</span></div><p class="hint" data-static-style="u11">${esc(steps.detail||'正在准备连接')}</p></article>`:'')+
 `<div class="overview-top"><article class="card pad"><div class="device-head"><div class="avatar">${esc(localName().slice(0,2).toUpperCase())}</div><div class="grow"><h2>${esc(localName())}</h2><div class="small muted">本机 · ${owner?'网络创建者':'网络成员'}</div></div><button class="text-btn" data-settings="identity" aria-label="修改本机设置">${icon('settings')}</button></div><div class="identity-ip"><span class="small muted">虚拟网络 IP</span><div class="row between"><strong class="mono">${esc(localIp())}</strong><button class="text-btn" data-action="copy-ip" aria-label="复制本机虚拟 IP">${icon('copy')}</button></div></div><div class="small muted" data-static-style="u12">${protocol()} · ${state.networkEnabled?'网络已启动':'网络已停止'}</div></article>
 <article class="card pad"><div class="metrics"><div><div class="metric-label">往返延迟</div><div class="metric-value">${online&&live[0]?.rttMs!=null?live[0].rttMs.toFixed(0):'—'}<span>ms</span></div><div class="metric-sub">${live[0]?'至 '+esc(live[0].name):'等待直连'}</div></div><div><div class="metric-label">实时上传</div><div class="metric-value">${online&&traffic.up!=null?(traffic.up/1e6).toFixed(2):'—'}<span>MB/s</span></div><div class="metric-sub">累计 ${total(up)}</div></div><div><div class="metric-label">实时下载</div><div class="metric-value">${online&&traffic.down!=null?(traffic.down/1e6).toFixed(2):'—'}<span>MB/s</span></div><div class="metric-sub">累计 ${total(down)}</div></div></div>${trafficChart()}</article></div>
 <article class="card table-card"><div class="table-head row between"><h2>网络设备<span>${peers.length+1} 台（含本机）</span></h2><span class="small muted">${online?'自动更新':'状态未更新'}</span></div><div class="table-scroll"><table><thead><tr><th>设备</th><th>虚拟 IP</th><th>连接状态 / 协议</th><th>延迟</th><th>上传</th><th>下载</th><th>操作</th></tr></thead><tbody><tr><td><div class="peer-device">${icon('laptop')}<div><div class="peer-name">${esc(localName())}</div><div class="peer-sub">${owner?'网络创建者':'网络成员'}</div></div></div></td><td class="mono">${esc(localIp())}</td><td colspan="5" class="self-cell"><span class="badge">本机</span></td></tr>${peers.map(p=>peerRow(p)).join('')}</tbody></table></div><div class="table-foot row between"><span>流量按本次网络运行统计</span><span>${online?'与其余 '+live.length+' 台设备直连':'连接状态待确认'}</span></div></article>`;
}
function trafficChart(){const values=historyTraffic,max=Math.max(1,...values.map(p=>Math.max(p.up,p.down))),now=performance.now(),points=field=>values.map(p=>(700-Math.min(60000,now-p.time)/60000*700).toFixed(1)+','+(63-p[field]/max*56).toFixed(1)).join(' ');return `<svg class="traffic-chart" viewBox="0 0 700 68" preserveAspectRatio="none" role="img" aria-label="最近一分钟的上下行速度"><path d="M0 63H700M0 30H700" stroke="var(--line)" stroke-width=".6" fill="none"/><polyline points="${points('down')}" stroke="var(--green)" stroke-width="1.5" fill="none"/><polyline points="${points('up')}" stroke="var(--accent)" stroke-width="1.3" fill="none"/></svg><div class="small muted">最近 60 秒 · 下载 / 上传</div>`;}
function peerRow(p){const rate=traffic.peers.get(p.slot),live=online&&p.connected;return `<tr><td><div class="peer-device">${icon('monitor')}<div><div class="peer-name">${esc(p.name)}</div><div class="peer-sub">${esc(live?'已认证直连':online?phaseNames[p.connection?.phase]||p.phase||'未在线':'状态未更新')}</div></div></div></td><td class="mono">${esc(p.virtualIp)}</td><td>${live?'已直连':online?'未连接':'待确认'}<div class="peer-sub">${live?esc(/udp/i.test(p.actualTransport)?'直接 UDP':'FakeTCP + HTTP'):'—'}</div></td><td>${live&&p.rttMs!=null?p.rttMs.toFixed(0)+' ms':'—'}</td><td>${speed(online?rate?.up:null)}<div class="peer-sub">累计 ${total(p.sentBytes)}</div></td><td>${speed(online?rate?.down:null)}<div class="peer-sub">累计 ${total(p.receivedBytes)}</div></td><td><button class="btn ghost icon-button" data-peer-details="${p.slot}" aria-label="查看 ${esc(p.name)} 详情" aria-expanded="${expanded.has(p.slot)}">${icon('settings')}</button></td></tr>${expanded.has(p.slot)?`<tr class="peer-detail"><td colspan="7"><p>${esc(p.connection?.detail||p.phase||'等待设备上线')}</p><p>${live?'实际入口':'上次确认入口'}：${esc(entryDescription(p))}</p><p>已直连时间：<span class="mono" data-connected-slot="${p.slot}">${connectedTime(p)}</span></p><div class="row"><button class="btn compact" data-peer-copy="${p.slot}">复制 IP</button>${owner?`<button class="btn compact danger" data-action="revoke" data-slot="${p.slot}">移出网络</button>`:''}</div></td></tr>`:''}`;}
function waitingView(){const p=state?.pairing;return `<div class="waiting"><div class="waiting-symbol">${icon('clock')}</div><h2>正在等待主机同意</h2><p>${esc(p?.peerName||'目标主机')} 将核对你的设备信息。</p><div class="mono" data-static-style="u13">${esc(p?.verification||'正在交换校验码')}</div><p>${esc(p?.state||'申请已发送')}</p><button class="btn" data-action="cancel-join">取消申请</button></div>`;}
function incomingPage(){const p=state?.pairing;if(!incoming)return `<article class="card pad empty-state">${icon('shield')}<h2>暂无加入申请</h2><p>${owner?'收到新申请后，会显示设备信息和校验码。':'加入申请由网络创建者处理。'}</p></article>`;return `<article class="card pad request-card"><div class="section-title">${icon('laptop')}<div><h2>${esc(p.peerName)}</h2><p class="small muted">请求加入本机网络</p></div></div><div class="request-meta"><div><span class="small muted">预分配 IP</span><strong class="mono">${esc(p.proposedIp||'正在分配')}</strong></div><div><span class="small muted">加入方式</span><strong>${activeRoute()==='direct'?'直连邀请':'配对码'}</strong></div><div><span class="small muted">双方校验码</span><strong class="mono">${esc(p.verification||'正在交换')}</strong></div></div><div class="request-footer"><span class="hint">${p.replacingSlot?'此设备正在重新加入；同意后会替换旧成员授权。':'请核对设备名称与校验码，再处理申请。'}</span><div class="row"><button class="btn positive" data-action="approve" ${p.verification?'':'disabled'}>同意</button><button class="btn danger" data-action="reject">拒绝</button></div></div></article>`;}
async function saveSection(){
 const changed=Object.keys(defaults).filter(dirty);if(!changed.length)return;
 const validation=clone(drafts);if(validation.coordination.url.trim()&&!validation.coordination.url.includes("://"))validation.coordination.url="https://"+validation.coordination.url.trim();
 for(const key of changed){const error=validateSection(key,validation);if(error){section=key;render();$('settings-error').textContent=sectionNames[key]+'：'+error;return;}}
 let settings;try{settings=settingsDto();}catch(error){section='coordination';render();$('settings-error').textContent=error.message;return;}
 const reconnect=state.networkEnabled&&(drafts.port.listen!==saved.port.listen||drafts.network.protocol!==saved.network.protocol||drafts.network.mode!==saved.network.mode);
 if(reconnect&&!await confirmAction('保存全部设置并重新连接？','连接方式、协议或接收端口的修改会短暂中断连接，其他修改会一起保存。','保存并重连'))return;
 const before=clone(saved),patch={};if(drafts.identity.name.trim()!==saved.identity.name){patch.deviceName=drafts.identity.name.trim();patch.expectedDeviceName=saved.identity.name;}if(drafts.logging.level!==saved.logging.level){patch.logLevel=drafts.logging.level;patch.expectedLogLevel=saved.logging.level;}
 const action={action:'settings',settings,expectedRevision:baseRevision,confirmReplace:reconnect};if(Object.keys(patch).length)action.patch=patch;if(drafts.system.startup!==saved.system.startup){action.autoStart=drafts.system.startup;action.expectedAutoStart=saved.system.startup;}
 const uiOwner=drafts.network.owner,terminal=drafts.logging.terminal,existingRoute=drafts.network.existingRoute,refreshUnit=drafts.network.unit;
 await command('network',{network:action});
 try{localStorage.setItem('streamlink-entry-owner',uiOwner);localStorage.setItem('streamlink-terminal-theme',terminal);localStorage.setItem('streamlink-existing-route',existingRoute);localStorage.setItem('streamlink-entry-refresh-unit',String(refreshUnit));}catch{}
 history=before;saved=configFromStatus(state);drafts=clone(saved);baseRevision=state.settingsRevision||'';render();notice('');notify('全部设置已保存');
}
function restoreSettings(){if(dirtyCount()){saved=configFromStatus(state);drafts=clone(saved);baseRevision=state.settingsRevision||'';render();notify('所有未保存的修改已还原');}else if(history&&!same(history,saved)){drafts=clone(history);render();notify('已恢复前一组完整设置，保存后生效');}}
function resetDefaults(){ask('恢复全部默认设置？','将全部分区填为默认值，保存后生效。当前网络固定的身份设置保持锁定。','填入默认值',()=>{drafts=Object.fromEntries(Object.keys(defaults).map(k=>[k,effectiveDefaults(k)]));render();notify('已填入默认设置，保存后生效');});}
function confirmAction(title,text,label,tone='neutral'){return new Promise(resolve=>ask(title,text,label,()=>resolve(true),resolve,tone));}
function ask(title,text,label,callback,cancel,tone='neutral'){if(modalCallback)throw Error('请先处理当前确认窗口');$('dialog-title').textContent=title;$('dialog-description').textContent=text;$('dialog-confirm').textContent=label;$('dialog-confirm').classList.toggle('danger',tone==='danger');$('dialog-confirm').classList.toggle('positive',tone==='positive');modalCallback=callback;modalCancel=cancel||null;$('confirm-dialog').showModal();$('dialog-cancel').focus();}
let modalCancel=null;
function closeDialog(yes){const callback=modalCallback,cancel=modalCancel;modalCallback=modalCancel=null;$('confirm-dialog').close();if(yes)callback?.();else cancel?.(false);}
function requireApplied(){if(dirtyCount())throw Error('设置有未保存的更改，请先保存全部设置，或恢复刚才设置。');}
function coordination(){const p=state.settings;if(!p?.service){openSettings('coordination');throw Error('请先填写并保存 HTTPS 协调服务器地址。');}return {service:p.service,certificatePin:p.certificatePin};}
async function createNetwork(){requireApplied();if(networkActive)throw Error('需要退出当前网络后才能创建。');const direct=activeRoute()==='direct';await network(direct?'create-direct':'create',{...(direct?{}:coordination()),mode:saved.network.protocol,expectedNetwork:state.networkId});notify('网络已创建');}
async function generate(){requireApplied();if(state.pairing?.candidate&&!await confirmAction('重新生成邀请？','将取消当前尚未处理的加入申请。','重新生成'))return;await network('invite',{expectedNetwork:state.networkId});notify(activeRoute()==='direct'?'直连邀请已生成':'配对码已生成');}
async function leaveNetwork(deleting=false){if(!networkActive)return;const wasOwner=owner,title=owner?'删除当前网络？':'退出当前网络？',text=owner?'将停止本机网络、撤销成员授权并删除网络凭据。其他设备需要重新加入；本机设置和入口保留。':'将停止本机连接并移除网络凭据；再次连接需重新申请加入。';if(!await confirmAction(title,text,owner?'删除网络':'退出网络','danger'))return;await network('leave',{expectedNetwork:state.networkId,confirmReplace:true});notify(wasOwner?'当前网络已删除':'已退出当前网络');}
const network=(action,fields={},quiet=false)=>command('network',{network:{action,...fields}},quiet);
async function joinNetwork(){requireApplied();if(networkActive)throw Error('需要退出当前网络后才能申请加入。');const direct=activeRoute()==='direct',code=(direct?joinInviteValue:joinCodeValue).replace(/\s/g,'');if(direct&&!code.startsWith('SL6.'))throw Error('请使用新版主机生成的 SL6. 直连邀请；旧版预授权邀请需重新生成。');if(!direct&&!/^\d{6}$/.test(code))throw Error('请输入六位数字配对码。');const name=(joinName||localName()).trim();if(!name)throw Error('请输入本机设备名称。');if(name!==state.deviceName)await command('patch',{patch:{deviceName:name,expectedDeviceName:state.deviceName}},true);submittedJoin={code,direct};try{await network(direct?'join-invitation':'join',{...(direct?{}:coordination()),code,expectedNetwork:state.networkId,mode:saved.network.protocol});}catch(error){if(!state?.pairing?.active)submittedJoin=null;throw error;}notify('申请已发送，等待主机批准');}
function bindJoinInput(){const direct=activeRoute()==='direct',input=$(direct?'join-invite':'join-code');if(!input)return;input.oninput=()=>{if(direct)joinInviteValue=input.value;else{joinCodeValue=input.value.replace(/\D/g,'').slice(0,6);input.value=joinCodeValue;input.closest('.digits-input').querySelectorAll('.digit').forEach((el,i)=>{const digit=joinCodeValue[i]||'';el.textContent=digit;el.classList.toggle('filled',!!digit);});}joinError='';$('join-error').textContent='';};$('join-device-name').oninput=e=>joinName=e.target.value;$('join-form').onsubmit=e=>{e.preventDefault();run(joinNetwork).catch(()=>{});};}
async function testAddresses(){const settings=settingsDto(),slot=drafts.network.owner==='local'?0:drafts.network.owner==='target'?-1:Number(drafts.network.owner.slice(4)),entries=settings.existingEntries.filter(e=>e.peerSlot===slot);if(!entries.length)throw Error('请先填写地址来源。');const version=++testGeneration,selected=drafts.network.owner;await network('resolve-entries',{settings:{...settings,existingEntries:entries}});if(page!=='settings'||section!=='network'||version!==testGeneration||selected!==drafts.network.owner||!$('test-results'))return;const results=state.entryResolutions||[];$('test-status').textContent=results.filter(r=>!r.error).length+'/'+results.length+' 个来源解析成功';$('test-results').innerHTML=results.map(r=>`<div class="test-result ${r.error?'error':''}">${icon(r.error?'x':'check')}<div class="grow"><div>${esc(r.error||r.endpoints.join('、'))}</div><p>${r.error?'可以检查来源或稍后重试；现有健康连接继续保持。':'地址已解析。保存后连接时仍需验证设备身份与双向通信。'}</p></div></div>`).join('');}
async function pollPair(){if(!online||busy||!state?.pairing?.active||state.pairing.direct||Date.now()-lastPairPoll<2500)return;lastPairPoll=Date.now();try{await network('pair-poll',{},true);if(lastPairError&&noticeSource==='pair')notice('');lastPairError='';if(!state.pairing?.active&&state.pairing?.state)notify(state.pairing.state);}catch(e){lastPairPoll=Date.now()+10000;if(e.message!==lastPairError){lastPairError=e.message;notice(e.message,true,'pair');}}}
const logSnapshots=new Map(),seenLogEntries=new Map();
let logOrdinal=0;
function appendLogLine(line,source,timestamp){
 const match=line.match(/^(\d\d:\d\d:\d\d) (?:\[(INFO|WARN|ERROR|DEBUG)\] )?(.*)$/);
 const time=match?.[1]||'',message=match?.[3]||line;
 if(!Number.isFinite(timestamp)){
  const date=new Date();
  if(time){const parts=time.split(':').map(Number);date.setHours(...parts,0);if(date.getTime()>Date.now()+300000)date.setDate(date.getDate()-1);}
  timestamp=date.getTime();
 }
 logLines.push({time,level:match?.[2]||'INFO',message:source?'['+source+'] '+message:message,timestamp,ordinal:logOrdinal++});
}
function appendLogs(lines,key='device',source=''){
 if(!lines.length)return;
 const previous=logSnapshots.get(key)||[];
 // A reduced reply can contain only an older suffix of the current window.
 if(previous.length>=lines.length&&previous.some((_,offset)=>offset+lines.length<=previous.length&&lines.every((line,i)=>line===previous[offset+i])))return;
 let start=0,matched=false;
 for(let count=Math.min(previous.length,lines.length);count>0&&!matched;count--){
  for(let offset=0;offset+count<=lines.length;offset++){
   if(previous.slice(-count).every((line,i)=>line===lines[offset+i])){start=offset+count;matched=true;break;}
  }
 }
 for(const line of lines.slice(start))appendLogLine(line,source);
 logSnapshots.set(key,lines.slice());
}
function appendStatusLogs(status){
 const sources=[{key:'device',name:status.workspaceVersion?'本机':'',status}];
 if(status.workspaceVersion)for(const network of status.networks||[])sources.push({key:network.id,name:network.name,status:network.status});
 const active=new Set(sources.map(source=>source.key));
 for(const key of logSnapshots.keys())if(!active.has(key))logSnapshots.delete(key);
 for(const source of sources){
  if(!Array.isArray(source.status.logEntries)){appendLogs(source.status.logs||[],source.key,source.name);continue;}
  for(const entry of source.status.logEntries){
   const key=source.key+':'+entry.id,seen=seenLogEntries.has(key);
   seenLogEntries.delete(key);seenLogEntries.set(key,true);
   if(!seen)appendLogLine(entry.text,source.name,entry.timestamp);
  }
 }
 while(seenLogEntries.size>4096)seenLogEntries.delete(seenLogEntries.keys().next().value);
 logLines.sort((a,b)=>a.timestamp-b.timestamp||a.ordinal-b.ordinal);
 if(logLines.length>500)logLines.splice(0,logLines.length-500);
}
let logFilter='ALL',logSearch='',autoScroll=true;
function visibleLogs(){return logLines.filter(l=>(logFilter==='ALL'||l.level===logFilter)&&(!logSearch||l.message.toLowerCase().includes(logSearch.toLowerCase())));}
function logsPage(){return heading('日志','查看连接与操作记录，定位发生问题的阶段。')+`<article class="card" data-static-style="u14"><div class="terminal-actions row between wrap"><div class="row"><select class="preview-select" id="log-filter" aria-label="日志等级筛选">${['ALL','INFO','WARN','ERROR','DEBUG'].map(v=>`<option ${logFilter===v?'selected':''} value="${v}">${v==='ALL'?'全部等级':v}</option>`).join('')}</select><input id="log-search" class="preview-select" aria-label="搜索日志" value="${esc(logSearch)}" placeholder="搜索日志"></div><div class="row"><button class="text-btn" data-action="copy-logs">复制日志</button><button class="text-btn" data-action="download-logs">导出</button><button class="text-btn" data-settings="logging">日志设置</button></div></div><div class="terminal terminal-content" id="terminal-content"><div id="terminal-lines" role="log" aria-label="当前后台日志"></div></div><div class="table-foot row between"><span id="log-count"></span><label><input type="checkbox" id="auto-scroll" ${autoScroll?'checked':''}>自动滚动</label></div></article>`;}
function updateLogView(){const terminal=$('terminal-content');if(!terminal)return;const value=saved.logging.terminal,light=value==='light'||value==='auto'&&theme==='light';terminal.classList.toggle('light',light);const scroll=terminal.scrollTop,lines=visibleLogs();$('terminal-lines').innerHTML=lines.map(l=>`<div class="log-entry"><span class="dim">${esc(l.time)}</span><span class="${l.level==='ERROR'?'warn':l.level==='WARN'?'warn':'info'}">[${esc(l.level)}]</span><span class="message">${esc(l.message)}</span></div>`).join('');$('log-count').textContent=lines.length+' 条 · 最多保留 500 条面板日志';terminal.scrollTop=autoScroll?terminal.scrollHeight:scroll;}
async function copyText(value){if(!value)return;await navigator.clipboard.writeText(value);notify('已复制');}
async function run(action){try{return await action();}catch(error){notice(error.message,true,expired?'authorization':'action');if(page==='join'){joinError=error.message;if($('join-error'))$('join-error').textContent=joinError;}throw error;}}
document.addEventListener('input',e=>{if(e.target.matches('#settings-fields input:not([type=checkbox]):not([type=radio]),#settings-fields textarea'))inputChange(e.target);if(e.target.id==='log-search'){logSearch=e.target.value;updateLogView();}});
document.addEventListener('change',e=>{if(e.target.matches('#settings-fields select,#settings-fields input[type=radio],#settings-fields input[type=checkbox]'))inputChange(e.target);if(e.target.id==='log-filter'){logFilter=e.target.value;updateLogView();}if(e.target.id==='auto-scroll')autoScroll=e.target.checked;});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b||b.disabled)return;run(async()=>{
 if(b.dataset.page)return navigate(b.dataset.page);if(b.dataset.settings)return openSettings(b.dataset.settings);if(b.dataset.section){section=b.dataset.section;render();return;}if(b.dataset.joinTab){joinTab=b.dataset.joinTab;render();return;}
 if(b.dataset.peerDetails){const slot=Number(b.dataset.peerDetails);expanded.has(slot)?expanded.delete(slot):expanded.add(slot);return render();}if(b.dataset.peerCopy)return copyText(state.peers.find(p=>p.slot===Number(b.dataset.peerCopy))?.virtualIp);
 if(b.dataset.removeEntry!==undefined){const list=drafts.network.entries[drafts.network.owner];list.splice(Number(b.dataset.removeEntry),1);if(!list.length)list.push('');renderFields();return;}
 switch(b.dataset.action){
 case 'theme':theme=theme==='dark'?'light':'dark';document.documentElement.dataset.theme=theme;try{localStorage.setItem('streamlink-theme',theme);}catch{}$('theme-button').innerHTML=icon(theme==='dark'?'sun':'moon');if(page==='logs')updateLogView();break;
 case 'save':await saveSection();break;case 'revert':restoreSettings();break;case 'defaults':resetDefaults();break;case 'create':await createNetwork();break;case 'generate':await generate();break;case 'leave':case 'delete':await leaveNetwork();break;
 case 'copy-code':await copyText(pairCode);break;case 'copy-invite':await copyText(invitation);break;case 'copy-ip':await copyText(state?.virtualIp);break;
 case 'add-entry':{const values=drafts.network.entries[drafts.network.owner];if(Object.values(drafts.network.entries).flat().filter(v=>v.trim()).length>=12||values.length>=12)throw Error('最多保存 12 项地址来源。');values.push('');renderFields();document.querySelector('.entry-row:last-child input').focus();break;}
 case 'test':await testAddresses();break;
 case 'cancel-join':await network('pair-cancel');submittedJoin=null;notify('已取消加入申请');break;
 case 'approve':case 'reject':{const p=state.pairing;if(b.dataset.action==='approve'&&!await confirmAction('确认双方校验码','请确认 '+p.peerName+' 显示的校验码也是 '+p.verification+'。','同意加入','positive'))return;await network(b.dataset.action,{candidate:p.candidate,verification:p.verification,proposedIp:p.proposedIp});notify(b.dataset.action==='approve'?'已同意加入':'已拒绝申请');break;}
 case 'revoke':{const peer=state.peers.find(p=>p.slot===Number(b.dataset.slot));if(peer&&await confirmAction('移出设备？','将撤销 '+peer.name+' 的网络授权。','移出设备','danger'))await network('revoke',{expectedNetwork:state.networkId,peerSlot:peer.slot});break;}
 case 'network-toggle':if(state.networkEnabled&&!await confirmAction('断开网络？','当前串流会中断，网络和设置保留。','断开'))return;await command(state.networkEnabled?'stop':'start');break;
 case 'retry':await command('retry');break;case 'register-service':await command('register-service');break;
 case 'copy-logs':await copyText(visibleLogs().map(l=>l.time+' ['+l.level+'] '+l.message).join('\n'));break;
 case 'download-logs':{const blob=new Blob([visibleLogs().map(l=>l.time+' ['+l.level+'] '+l.message).join('\n')],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='ConWU-'+new Date().toISOString().slice(0,10)+'.log';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);break;}
 }
}).catch(()=>{});});
$('dialog-cancel').onclick=()=>closeDialog(false);$('dialog-confirm').onclick=()=>closeDialog(true);$('confirm-dialog').addEventListener('cancel',e=>{e.preventDefault();closeDialog(false);});
window.addEventListener('beforeunload',e=>{if(dirtyCount()){e.preventDefault();e.returnValue='';}});
async function boot(){document.documentElement.dataset.theme=theme;$('theme-button').innerHTML=icon(theme==='dark'?'sun':'moon');render();try{const ticket=location.hash.slice(1);window.history.replaceState(null,'',location.pathname);const session=await api('/api/session',/^[A-F0-9]{64}$/.test(ticket)?{ticket}:undefined);csrf=session.csrf;await refresh();}catch(e){unavailable(e.message);}setInterval(async()=>{if(expired)return;await refresh();await pollPair();},2000);setInterval(()=>{checkStatusFreshness();updateConnectedTimes();},1000);document.addEventListener('visibilitychange',resumeStatus);window.addEventListener('pageshow',resumeStatus);}
