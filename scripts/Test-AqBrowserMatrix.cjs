// Runs against the same actual restricted-pipe fixture as Test-AqBrowser.cjs.
module.exports=async({page,context,browser,child,nextLine,nav,section,action,check,errors})=>{
 const idle=()=>page.waitForFunction(()=>!busy);
 const persisted=async()=>JSON.stringify((await(await page.request.get(new URL('/api/status',page.url()).href)).json()).status.settings);
 await nav('settings');await section('network');const unchanged=await persisted();
 await page.evaluate(()=>window.matrixOption=document.querySelector('#protocol option'));await page.evaluate(()=>refresh());
 check(await page.evaluate(()=>window.matrixOption===document.querySelector('#protocol option')),'unchanged backend refresh keeps select-option DOM stable instead of interrupting an open dropdown');
 await section('network');await page.locator('[data-entry-index="0"]').fill('203.0.113.99:44680');
 await section('publish');await page.locator('[data-entry-index="0"]').fill('203.0.113.88:44680');
 await page.locator('[data-source-refresh]').fill('123');
 await section('network');
 check(await page.locator('[data-key=refresh]').inputValue()==='123'&&await page.locator('[data-key=unit]').inputValue()==='1','publication sources edit the same global refresh setting without creating a second saved value');
 check(await page.locator('[data-entry-index="0"]').inputValue()==='203.0.113.99:44680','network and published entry sections preserve independent drafts');
 await page.locator('[data-key=useServer]').uncheck();await page.locator('[name=mode][value=custom]').check();await page.locator('[name=mode][value=existing]').check();
 check(!(await page.locator('[data-key=useServer]').isChecked()),'switching connection modes restores the previous existing-entry pairing choice');
 await action('revert');check(await persisted()===unchanged,'reverting option changes does not write backend settings');

 await page.locator('[data-key=refresh]').fill('60');await page.locator('[data-key=unit]').selectOption('1');await action('save');await idle();
 await page.reload();await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();await nav('settings');await section('network');
 check(await page.locator('[data-key=refresh]').inputValue()==='60'&&await page.locator('[data-key=unit]').inputValue()==='1','explicit refresh number and seconds unit survive save and full page reload');

 await section('identity');await page.locator('#device-name').fill('Typing during background observation');
 await page.evaluate(()=>{window.matrixBackground=network('resolve-entries',{settings:{...state.settings,existingEntries:[{peerSlot:0,source:'203.0.113.42:44680'}]}},true).catch(()=>{});});
 await page.waitForFunction(()=>busy&&busyKind==='background');
 check(!(await page.locator('#settings-fields').evaluate(e=>e.inert)),'background observation does not lock the settings input area');
 await page.locator('#device-name').fill('Typed while background command is pending');
 await section('port');await page.locator('#listen-port').fill('45003');await page.evaluate(()=>refresh());await idle();
 check(await page.locator('#listen-port').inputValue()==='45003','port input remains editable and retains its draft across asynchronous backend progress');
 await section('identity');check(await page.locator('#device-name').inputValue()==='Typed while background command is pending','device-name draft survives section changes and background completion');
 await section('coordination');await page.locator('[data-key=url]').fill('https://draft.example.com/');
 await section('certificate');await page.locator('[data-key=pin]').fill('A'.repeat(64));
 await section('stun');await page.locator('[data-key=tcp]').fill('stun.example.com:3478');
 await nav('logs');await page.locator('#log-search').fill('matrix-log-filter');await page.evaluate(()=>refresh());
 check(await page.locator('#log-search').inputValue()==='matrix-log-filter','log search remains editable across backend refresh');
 await nav('settings');await section('coordination');check(await page.locator('[data-key=url]').inputValue()==='https://draft.example.com/','coordination-address draft survives navigation and unrelated status updates');
 await section('certificate');check(await page.locator('[data-key=pin]').inputValue()==='A'.repeat(64),'certificate draft survives navigation');
 await section('stun');check(await page.locator('[data-key=tcp]').inputValue()==='stun.example.com:3478','STUN textarea draft survives navigation');
 await action('revert');

 await section('identity');await page.locator('#device-name').fill('Matrix saved name');await action('save');
 await page.waitForFunction(()=>busy&&busyKind==='settings-save');
 check(await page.locator('#settings-fields').evaluate(e=>e.inert),'an explicit settings save locks its submitted draft until the result is known');await idle();
 const previousName=await page.evaluate(()=>history.identity.name);
 child.stdin.write('seed-network\n');check(await nextLine()==='seeded','history fixture creates an actual isolated network');await page.evaluate(()=>refresh());
 await nav('create');await action('delete');await page.locator('#dialog-confirm').click();await idle();
 await nav('settings');await section('identity');await action('revert');
 check(await page.locator('#device-name').inputValue()===previousName&&await page.evaluate(()=>state.deviceName)==='Matrix saved name','network creation and deletion preserve settings undo history without silently applying it');
 await action('revert');

 child.stdin.write('open\n');const secondLink=await nextLine();const second=await context.newPage();
 second.on('pageerror',e=>errors.push('second tab: '+e.message));await second.goto(secondLink);await second.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await second.locator('.nav[data-page=settings]').click();await second.locator('[data-section=identity]').click();await second.locator('#device-name').fill('Second tab unsaved name');
 const commandIds=[];const requestListener=request=>{if(new URL(request.url()).pathname==='/api/command')commandIds.push(request.postDataJSON()?.operationId);};page.on('request',requestListener);
 await page.locator('#device-name').fill('First tab saved after session rotation');await section('port');await page.locator('#listen-port').fill('45004');await action('save');await idle();page.off('request',requestListener);
 check(commandIds.length===2&&commandIds[0]===commandIds[1]&&await page.evaluate(()=>state.deviceName)==='First tab saved after session rotation','old tab resynchronizes rotated CSRF and submits the same operation ID exactly once to the backend');
 await second.evaluate(()=>refresh());check(await second.locator('#device-name').inputValue()==='Second tab unsaved name','another tab saving cannot overwrite this tab\'s unsaved input');
 await second.locator('[data-action=save]').click();await second.waitForFunction(()=>!busy);
 const conflictNotice=await second.locator('#notice').innerText();
 check(/改变|修改/.test(conflictNotice)&&await second.locator('#device-name').inputValue()==='Second tab unsaved name','stale multi-window save reports a real conflict and retains the unsaved draft: '+conflictNotice);
 await second.locator('[data-action=revert]').click();await second.locator('#device-name').fill('Second tab explicitly saved');await second.locator('[data-action=save]').click();await second.waitForFunction(()=>!busy);
 await section('identity');await page.evaluate(()=>refresh());
 check(await page.locator('#device-name').inputValue()==='Second tab explicitly saved','clean input fields update after another tab saves without needing a page reload');await second.close();

 const savedBeforeDefaults=await persisted();await action('defaults');await page.locator('#dialog-confirm').click();
 check(await page.evaluate(()=>dirtyCount()>0)&&await persisted()===savedBeforeDefaults,'restore defaults only fills drafts and never commits settings without Save');await action('revert');

 child.stdin.write('open\n');const faultLink=await nextLine();const faultContext=await browser.newContext(),fault=await faultContext.newPage();
 fault.on('pageerror',e=>errors.push('fault tab: '+e.message));await fault.goto(faultLink);await fault.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await fault.locator('.nav[data-page=join]').click();await fault.locator('#join-code').fill('123456');
 const stopped=route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({ok:false,code:'Stopped',error:'个人后台已停止'})});
 await fault.route('**/api/status',stopped);await fault.evaluate(()=>refresh());
 check((await fault.locator('#notice').innerText()).includes('个人后台已停止')&&await fault.locator('#join-submit').isDisabled(),'a confirmed stopped service is reported immediately and blocks mutations');
 check(await fault.locator('#join-code').inputValue()==='123456','a real backend failure does not erase pairing input');await fault.unroute('**/api/status',stopped);await fault.evaluate(()=>refresh());
 check(await fault.locator('#notice').isHidden()&&await fault.locator('#join-submit').isEnabled()&&await fault.locator('#join-code').inputValue()==='123456','backend recovery clears its warning and reenables controls without discarding input');
 const expired=route=>route.fulfill({status:401,contentType:'application/json',body:JSON.stringify({ok:false,error:'expired'})});
 await fault.route('**/api/status',expired);await fault.evaluate(()=>{window.matrixLateStatus=clone(state);return refresh();});
 await fault.evaluate(()=>render(window.matrixLateStatus));
 check((await fault.locator('#backend-state').innerText())==='面板授权已过期'&&await fault.locator('#join-submit').isDisabled(),'authorization expiry cannot be overwritten by a late successful status or mislabeled as missing backend');
 await faultContext.close();

 // Disabled DDNS exercises credential/settings persistence without any DNS
 // publication, Cloudflare request or live network change in this fixture.
 await nav('settings');await section('ddns');
 const credential='fixture-token-0123456789-secret';
 await page.locator('[data-key=domain]').fill('conwu.example.test');
 await page.locator('[data-key=newToken]').fill(credential);
 await section('logging');check(await page.locator('#save-section').isEnabled(),'DDNS draft participates in global save outside its section');
 await section('ddns');check(await page.locator('[data-key=newToken]').inputValue()===credential,'unsaved credential survives section navigation');
 await action('save');await idle();await section('ddns');
 check(await page.locator('[data-key=newToken]').inputValue()===''&&await page.evaluate(()=>state.ddnsCredentialConfigured),'saved DDNS credential is write-only');
 check(!(await persisted()).includes(credential)&&await page.evaluate(()=>!JSON.stringify({saved,history,storage:{...localStorage}}).includes('fixture-token-0123456789-secret')),'credential is absent from exported settings, undo history and browser storage');
 await page.evaluate(()=>network('settings',{settings:{...state.settings,ddns:null},expectedRevision:state.settingsRevision}));await idle();
 check(await page.evaluate(()=>state.settings.ddns.domain==='conwu.example.test'&&state.ddnsCredentialConfigured),'older settings client omitting DDNS preserves domain and credential');
 await section('ddns');await page.locator('[data-key=domain]').fill('draft.example.test');await page.evaluate(()=>refresh());
 check(await page.locator('[data-key=domain]').inputValue()==='draft.example.test','DDNS status refresh does not erase an active settings draft');await action('revert');
 await page.locator('[data-key=clearToken]').check();await action('save');await idle();
 check(await page.evaluate(()=>!state.ddnsCredentialConfigured),'only explicit credential clearing removes the DDNS token');
};
