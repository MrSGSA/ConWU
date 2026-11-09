// Deterministic slow-API checks using the production assets. This complements
// Test-ConvergedBrowser's actual WebPanel/service fixture; no public requests.
const path=require('node:path'),fs=require('node:fs');
const root=path.resolve(__dirname,'..'),assets=path.join(root,'src/StreamLink.Web/wwwroot');
const {chromium}=require(process.env.CONWU_BROWSER_TOOLS||path.resolve(root,'../StreamLink/out/browser-tools/node_modules/playwright'));
const output=process.env.CONWU_UI_STATES_OUTPUT||path.join(root,'artifacts/ui-refinement-20261108/ui-states');fs.mkdirSync(output,{recursive:true});
const settings={service:'https://coord.example.com/',certificatePin:'',manualEndpoint:'',pathSelection:'faketcp-only',listenPort:44680,sourcePort:44691,connectionSource:'existing',directMode:true,coordinatorBackup:true,existingEntries:[{peerSlot:0,source:'https://entry.example.com/current#streamlink1'}],entryRefreshSeconds:60,tcpStun:['stun.example.com:3478'],udpStun:['stun.example.com:3478'],requestedVirtualIp:'',pkarrPublish:false,coordinator:{enabled:false,listenUrl:'http://127.0.0.1:47822',publicUrl:'',certificateFile:'',certificateKeyFile:'',publicCertificatePin:'',trustCloudflare:false}};
const base={version:'1.1.0-ui-test',deviceName:'Thinkbook',virtualIp:'',state:'就绪',serviceReady:true,networkEnabled:false,directPeers:0,totalPeers:0,peers:[],logLevel:'info',platform:'windows',settingsRevision:'base',settings,logs:[],desktop:{autoStart:true,serviceRegistered:true},coordinator:{enabled:false,running:false,state:'未启用'}};
const host={id:'11111111111111111111111111111111',name:'笔记本—手机',configurationId:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',status:{...base,networkId:'12121212121212121212121212121212',isOwner:true,networkEnabled:true,virtualIp:'10.171.1.1',networkDirect:true,peers:[{slot:2,name:'Phone',virtualIp:'10.171.1.2',connected:false,sentBytes:0,receivedBytes:0}],pairing:{active:false}}};
const guest={id:'22222222222222222222222222222222',name:'游戏主机',configurationId:'',status:{...base,settings:{...settings,existingEntries:[{peerSlot:-1,source:'https://entry.example.com/current#streamlink1'}]},networkId:'23232323232323232323232323232323',isOwner:false,networkEnabled:true,directPeers:1,virtualIp:'10.172.1.2',peers:[{slot:1,name:'Akane',virtualIp:'10.172.1.1',connected:true,sentBytes:900000,receivedBytes:50000000,rttMs:12.3,outerTarget:'203.0.113.1:8436',connection:{phase:'Connected',elapsedMs:123400}}],receivedNetworkSettings:{hostListenPort:44680},pairing:null}};
let model={...base,workspaceVersion:2,selectedNetworkId:'',deviceSettings:{...settings,directMode:false},deviceSettingsRevision:'dev1',networks:[host,guest],configurations:[{id:host.configurationId,name:'默认设置',revision:1,settings,networks:[{networkId:host.id,name:host.name,state:'applied'}]}],aggregate:{sentBytes:900000,receivedBytes:50000000}};
const clone=x=>JSON.parse(JSON.stringify(x)),commands=[],checks=[],errors=[];
const check=(value,name)=>{if(!value)throw Error(name);checks.push(name);console.log('CHECK '+checks.length+' '+name)};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve}};
async function within(promise,name){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('Timed out: '+name)),15000))]);}finally{clearTimeout(timer)}}
let saveGate,saveStarted,editorGate,editorStarted,cancelGate,cancelStarted,pollStarted=deferred(),probeId='',staleModel;
(async()=>{
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1050}});page.on('pageerror',e=>errors.push(e.message));
 await page.route('https://conwu.test/**',async route=>{
  const u=new URL(route.request().url());
  if(u.pathname==='/api/session')return route.fulfill({json:{csrf:'fixture'}});
  if(u.pathname==='/api/status'){
   if(u.searchParams.has('operation'))return route.fulfill({json:{ok:true,status:staleModel||model,operation:{id:probeId,completed:false}}});
   return route.fulfill({json:{ok:true,status:model}});
  }
  if(u.pathname==='/api/command'){
   const body=route.request().postDataJSON();commands.push(body);
   if(body.method==='save-settings'){
    saveStarted?.resolve();await saveGate?.promise;
    model={...model,deviceName:body.settingsBatch.device.patch?.deviceName||model.deviceName,deviceSettings:body.settingsBatch.device.settings||model.deviceSettings,deviceSettingsRevision:'dev'+commands.length};
   }else if(body.configuration?.action==='save'){
    editorStarted?.resolve();await editorGate?.promise;
    model={...model,configurations:model.configurations.map(c=>c.id===body.configuration.id?{...c,name:body.configuration.name,settings:body.configuration.settings,revision:c.revision+1}:c)};
   }else if(body.method==='cancel'){
    cancelStarted?.resolve();await cancelGate?.promise;
   }else if(body.network?.autoConfigure){
    model={...model,selectedNetworkId:'33333333333333333333333333333333',networks:[...model.networks,{id:'33333333333333333333333333333333',name:'连接 3',configurationId:'',status:{...base,pairing:{active:true,owner:false,direct:false,peerName:'新主机',verification:'123456',expires:Math.floor(Date.now()/1000)+300,state:'等待主机批准'}}}]};
   }else if(body.network?.action==='pair-poll'){
    probeId=body.operationId;staleModel=clone(model);pollStarted.resolve();
    return route.fulfill({json:{ok:true,status:model,operation:{id:probeId,completed:false}}});
   }else if(body.network?.action==='pair-cancel')model={...model,selectedNetworkId:'',networks:model.networks.filter(n=>n.id!==body.networkId)};
   return route.fulfill({json:{ok:true,status:model}});
  }
  const file=path.join(assets,u.pathname==='/'?'index.html':u.pathname);
  return route.fulfill({path:file,contentType:u.pathname.endsWith('.css')?'text/css':u.pathname.endsWith('.js')?'application/javascript':u.pathname.endsWith('.svg')?'image/svg+xml':'text/html'});
 });
 try{
  await page.goto('https://conwu.test/');await page.getByRole('heading',{name:'概况',exact:true}).waitFor();
  check(await page.locator('thead th').count()===5,'overview has consistent columns and no management column');
  await page.screenshot({path:path.join(output,'overview.png'),fullPage:true});
  await page.locator('.nav[data-page="join"]').click();await page.locator('#joined-networks [data-ui-action="open-editor"]').click();
  check(await page.locator('#network-edit-actions').isHidden(),'received settings have no mutation controls');
  check(await page.locator('#network-settings-body input,#network-settings-body textarea,#network-settings-body select').count()===0,'guest settings are read-only in every visible field');
  await page.screenshot({path:path.join(output,'readonly.png'),fullPage:true});await page.locator('#network-readonly-close').click();
  const initialDevice=clone(model.deviceSettings);
  check(await page.locator('#join-code').isEnabled(),'upgrade retains a previously configured coordination address for joining');
  const selectCoordinator=async address=>{await page.locator('[data-ui-action="open-lookup"]').click();await page.locator('#lookup-address').fill(address);await page.locator('[data-ui-action="save-lookup"]').click();await page.locator('#lookup-dialog').waitFor({state:'hidden'});};
  const beforeLookup=commands.length;await selectCoordinator('');
  check(await page.locator('#join-code').isDisabled()&&await page.locator('#join-submit').isDisabled(),'clearing the address disables code input and join without changing the selected mode');
  check(commands.length===beforeLookup,'changing a join-specific address does not rewrite device or network settings');
  check(await page.locator('#join-submit').evaluate(e=>getComputedStyle(e).cursor)==='not-allowed','disabled code submission keeps a prohibition cursor');
  await page.locator('[data-ui-action="join-invite-mode"]').click();await page.locator('#join-invite').fill('SL6.saved-invitation-draft');
  check(await page.locator('[data-ui-action="open-lookup"],#join-coordinator-state').count()===0,'invitation mode has no coordinator settings or coordinator status');
  check((await page.locator('.join-connection-note').innerText()).includes('直连邀请下')&&!(await page.locator('.join-connection-note').innerText()).includes('首次连接配对需要经由协调服务器'),'invitation explanation does not include the short-code explanation');
  await page.locator('[data-ui-action="join-code-mode"]').click();
  check((await page.locator('.join-connection-note').innerText()).includes('首次连接配对需要经由协调服务器')&&!(await page.locator('.join-connection-note').innerText()).includes('直连邀请下'),'short-code explanation does not include the invitation explanation');
  model={...model,deviceSettings:{...initialDevice,service:'',directMode:true},deviceSettingsRevision:'no-coord'};
  await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='no-coord');check(await page.locator('#join-code').isDisabled(),'backend default changes do not select invitation mode');
  model={...model,deviceSettings:{...model.deviceSettings,coordinator:{...settings.coordinator,enabled:true}},deviceSettingsRevision:'provider-only'};
  await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='provider-only');check(await page.locator('#join-code').isDisabled(),'enabling a local provider does not enable short pairing');
  model={...model,deviceSettings:{...model.deviceSettings,coordinator:{...settings.coordinator,enabled:true,publicUrl:'https://own-coord.example.com/'}},deviceSettingsRevision:'self-provider'};
  await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='self-provider');check(await page.locator('#join-code').isDisabled(),'even a known provider HTTPS address does not become the join coordinator implicitly');
  await page.reload();await page.getByRole('heading',{name:'概况',exact:true}).waitFor();await page.locator('.nav[data-page="join"]').click();check(await page.locator('#join-code').isDisabled()&&await page.locator('#join-submit').isDisabled(),'an explicitly cleared address remains cleared after reload even when a local HTTPS provider is available');
  await page.locator('[data-ui-action="join-invite-mode"]').click();await page.locator('#join-invite').fill('SL6.saved-invitation-draft');await page.locator('[data-ui-action="join-code-mode"]').click();
  await page.locator('.nav[data-page="coordinator"]').click();
  check(await page.locator('[data-ui-key="server"],[data-ui-key="discover"]').count()===0,'provider page no longer contains the duplicate coordination client settings');
  check(await page.locator('[data-ui-key="publicUrl"]').count()===0,'provider page has no redundant external HTTPS input');
  check(!(await page.locator('#content').innerText()).includes('默认协调服务器为自身'),'provider page does not promise implicit self discovery');
  model={...model,deviceSettings:{...initialDevice,coordinator:{...initialDevice.coordinator,enabled:true,publicUrl:'https://own-coord.example.com/'}},deviceSettingsRevision:'external-again'};await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='external-again');
  await page.locator('.nav[data-page="join"]').click();check(await page.locator('#join-code').isDisabled(),'restoring an old device default does not override an explicitly cleared join address');
  await selectCoordinator('https://selected-coord.example.com/');await page.locator('#join-code').fill('657483');
  await selectCoordinator('');check(await page.locator('#join-code').isDisabled()&&await page.locator('#join-code').inputValue()==='657483'&&await page.locator('#join-submit').isDisabled(),'clearing the coordinator preserves the numeric draft but prevents its submission');
  await page.locator('[data-ui-action="open-lookup"]').click();await page.locator('#lookup-address').fill('https://coord.example.com/?token=unexpected');await page.locator('[data-ui-action="save-lookup"]').click();check(await page.locator('#lookup-dialog').isVisible()&&!!await page.locator('#lookup-error').innerText(),'a coordinator URL with credentials or subscription parameters is not accepted as a discovery service');await page.locator('[data-ui-action="close-lookup"]').click();await selectCoordinator('https://selected-coord.example.com/');
  await page.locator('[data-ui-action="join-invite-mode"]').click();check(await page.locator('#join-invite').inputValue()==='SL6.saved-invitation-draft','mode changes preserve the independent invitation draft');
  await page.locator('[data-ui-action="join-code-mode"]').click();check(await page.locator('#join-code').inputValue()==='657483','mode changes preserve the short-code draft');
  await page.locator('.nav[data-page="coordinator"]').click();
  const clientPin='a'.repeat(64),providerPin='b'.repeat(64);
  model={...model,deviceSettings:{...initialDevice,certificatePin:clientPin,coordinator:{...initialDevice.coordinator,publicUrl:initialDevice.service}},deviceSettingsRevision:'pin-preserve'};await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='pin-preserve');
  check(!await page.locator('[data-ui-scope="host"][data-ui-key="enabled"]').isChecked(),'a clean provider form refreshes changed backend fields even when the selected server address is unchanged');
  if(!await page.locator('#coordinator-certificates').evaluate(e=>e.open))await page.locator('#coordinator-certificates summary').click();
  await page.locator('[data-ui-key="trustCloudflare"]').check();await page.locator('#save-coord').click();await page.waitForFunction(()=>!busy&&workspaceState.deviceSettings.coordinator.trustCloudflare);
  check(model.deviceSettings.certificatePin===clientPin,'saving provider settings keeps the selected coordinator certificate pin even when it is the local provider');
  model={...model,deviceSettings:{...initialDevice,service:'',certificatePin:clientPin,coordinator:{...initialDevice.coordinator,enabled:true,publicUrl:'https://own-coord.example.com/',publicCertificatePin:providerPin}},deviceSettingsRevision:'pin-default'};await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='pin-default');
  if(!await page.locator('#coordinator-certificates').evaluate(e=>e.open))await page.locator('#coordinator-certificates summary').click();
  await page.locator('[data-ui-key="trustCloudflare"]').check();await page.locator('#save-coord').click();await page.waitForFunction(()=>!busy&&workspaceState.deviceSettings.coordinator.trustCloudflare);
  check(model.deviceSettings.certificatePin===clientPin&&model.deviceSettings.service==='','provider save preserves client preferences without silently selecting the provider or its certificate');
  model={...model,deviceSettings:initialDevice,deviceSettingsRevision:'external-restored'};await page.waitForFunction(()=>workspaceState.deviceSettingsRevision==='external-restored');
  await page.locator('.nav[data-page="join"]').click();await page.locator('[data-ui-action="open-lookup"]').click();check(await page.locator('#lookup-address').inputValue()==='https://selected-coord.example.com/','provider saves cannot replace the join-specific address');await page.locator('[data-ui-action="close-lookup"]').click();
  await page.reload();await page.getByRole('heading',{name:'概况',exact:true}).waitFor();await page.locator('.nav[data-page="join"]').click();await page.locator('[data-ui-action="open-lookup"]').click();check(await page.locator('#lookup-address').inputValue()==='https://selected-coord.example.com/','join-specific address persists across a full page reload');await page.locator('[data-ui-action="close-lookup"]').click();
  await page.locator('.nav[data-page="create"]').click();await page.locator('#owned-networks [data-ui-action="open-editor"]').click();
  check(await page.locator('[data-ui-section="coordination"],[data-ui-section="pkarr"],[data-ui-section="stun"]').count()===0,'existing-entry editor excludes all autonomous discovery controls');
  await page.locator('[data-ui-section="entry"]').click();const originalEntry=await page.locator('[data-entry-index="0"]').inputValue();await page.locator('[data-entry-index="0"]').fill('https://remember.example.com/#streamlink2');
  await page.locator('[data-ui-section="network"]').click();await page.locator('[data-key="mode"][value="custom"]').check();
  await page.locator('[data-key="route"]').selectOption('server');check(await page.locator('[data-ui-section="coordination"]').count()===1&&await page.locator('[data-ui-section="pkarr"],[data-ui-section="entry"]').count()===0,'coordinated autonomous mode exposes only its server discovery controls');
  await page.locator('[data-ui-section="coordination"]').click();await page.locator('[data-key="url"]').fill('https://remember-coord.example.com/');await page.locator('[data-ui-section="network"]').click();await page.locator('[data-key="route"]').selectOption('pkarr');
  check(await page.locator('[data-ui-section="coordination"],[data-ui-section="entry"]').count()===0,'PKARR mode hides server and existing-entry controls');await page.locator('[data-ui-section="pkarr"]').click();
  check(await page.locator('[data-key="pkarrPublish"]').count()===0&&(await page.locator('#network-settings-body').innerText()).includes('始终启用'),'PKARR mode has no independent disable switch and explains its limits');
  await page.locator('[data-ui-section="network"]').click();await page.locator('[data-key="route"]').selectOption('direct');check(await page.locator('[data-ui-section="invitation"]').count()===1&&await page.locator('[data-ui-section="pkarr"],[data-ui-section="entry"]').count()===0,'manual autonomous mode replaces entry settings with direct invitation instructions');
  await page.locator('[data-key="mode"][value="existing"]').check();await page.locator('[data-ui-section="entry"]').click();check(await page.locator('[data-entry-index="0"]').inputValue()==='https://remember.example.com/#streamlink2','switching policies preserves dormant entry drafts');
  await page.locator('[data-ui-section="network"]').click();await page.locator('[data-key="mode"][value="custom"]').check();await page.locator('[data-key="route"]').selectOption('server');await page.locator('[data-ui-section="coordination"]').click();check(await page.locator('[data-key="url"]').inputValue()==='https://remember-coord.example.com/','switching policies preserves dormant coordinator drafts');
  await page.locator('[data-ui-action="restore-editor"]').click();await page.locator('[data-ui-action="close-editor"]').first().click();
  await page.locator('.nav[data-page="settings"]').click();await page.locator('#device-name').fill('保存后的设备名');
  saveGate=deferred();saveStarted=deferred();await page.locator('#save-device').click();await within(saveStarted.promise,'device save request');
  check(await page.locator('#device-name').isDisabled(),'device fields are locked while their save is in flight');
  await page.locator('.nav[data-page="join"]').click();await page.locator('.nav[data-page="settings"]').click();
  check(await page.locator('#device-name').isDisabled()&&await page.locator('#device-name').inputValue()==='保存后的设备名','navigation during save neither unlocks nor discards device draft');
  saveGate.resolve();await page.waitForFunction(()=>!busy&&workspaceState.deviceName==='保存后的设备名');
  check(await page.locator('#device-name').isEnabled()&&await page.locator('#save-device').isDisabled(),'accepted save restores input and clears the dirty state');
  await page.locator('.nav[data-page="create"]').click();await page.locator('#owned-networks [data-ui-action="open-editor"]').click();
  await page.locator('[data-ui-section="entry"]').click();await page.locator('[data-entry-index="0"]').fill('https://new-entry.example.com/#streamlink1');
  editorGate=deferred();editorStarted=deferred();await page.locator('[data-ui-action="save-editor"]').click();
  await page.locator('#dialog-confirm').click();await within(editorStarted.promise,'editor save request');
  check(await page.locator('#settings-fields').evaluate(e=>e.inert),'network editor locks its fields during save');
  await page.keyboard.press('Escape');check(await page.locator('#network-dialog').isVisible(),'Escape does not close an in-flight settings transaction');
  editorGate.resolve();await page.locator('#network-dialog').waitFor({state:'hidden'});
  check(model.configurations[0].settings.existingEntries[0].source==='https://new-entry.example.com/#streamlink1','network draft reaches the backend save request');
  await page.locator('.nav[data-page="join"]').click();await page.locator('#join-code').fill('657483');await page.locator('#join-submit').click();
  check(commands.find(c=>c.network?.autoConfigure)?.network.service==='https://selected-coord.example.com/','short-code request uses the join-specific coordinator rather than the previous device default');
  await page.getByRole('heading',{name:'等待主机同意',exact:true}).waitFor();await within(pollStarted.promise,'background pairing observation');
  check(await page.evaluate(()=>!busy),'passive pairing observation does not take the foreground busy flag');
  check(await page.locator('[data-ui-action="cancel-join"]').isEnabled(),'cancel remains available during a delayed pairing read');
  check(await page.locator('[data-ui-action="choose-exit"]').isEnabled(),'exit remains available during a delayed pairing read');
  await page.locator('.nav[data-page="settings"]').click();await page.locator('#device-name').fill('新草稿');
  check(await page.locator('#save-device').isEnabled(),'background pairing does not lock unrelated settings');
  await page.locator('.nav[data-page="join"]').click();cancelGate=deferred();cancelStarted=deferred();await page.locator('[data-ui-action="cancel-join"]').click();await within(cancelStarted.promise,'cancelling the old observation');
  const reads=commands.filter(c=>c.network?.action==='pair-poll').length;await page.waitForTimeout(2500);
  check(commands.filter(c=>c.network?.action==='pair-poll').length===reads,'a delayed foreground cancellation prevents new background observations from racing it');cancelGate.resolve();
  await page.locator('#join-code').waitFor();await page.waitForTimeout(1600);
  check(await page.locator('#join-code').isEnabled(),'cancelling restores pair-code input without a page reload');
  check(commands.some(c=>c.method==='cancel'&&c.cancelOperationId===probeId),'foreground cancel first cancels the old pairing operation by ID');
  check(await page.locator('#joined-networks [data-network-row]').count()===1,'late pairing observation cannot resurrect the cancelled network');
  check(!/取消|cancel/i.test(await page.locator('#notice').innerText()),'intentional observation cancellation creates no persistent error');
  check(errors.length===0,'slow-API state checks have no browser script errors');
  fs.writeFileSync(path.join(output,'checks.json'),JSON.stringify({passed:true,checks,errors,scope:'Production assets with deterministic API delays; no real peers or public PKARR publication'},null,2));
  console.log('PASS '+checks.length+' production-UI slow-API checks');
 }catch(error){await page.screenshot({path:path.join(output,'failure.png'),fullPage:true});console.error(error.stack);console.error(errors);process.exitCode=1;}
 finally{saveGate?.resolve();editorGate?.resolve();cancelGate?.resolve();await browser.close();}
})();
