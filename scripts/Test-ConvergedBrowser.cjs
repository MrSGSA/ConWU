const path=require('node:path'),fs=require('node:fs'),{spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const root=path.resolve(__dirname,'..');
const {chromium}=require(process.env.CONWU_BROWSER_TOOLS||path.resolve(root,'../StreamLink/out/browser-tools/node_modules/playwright'));
const output=process.env.CONWU_BROWSER_OUTPUT||path.join(root,'artifacts/entry-backup-20261108/browser');fs.mkdirSync(output,{recursive:true});
const child=spawn(path.join(root,'tests/StreamLink.WebTests/bin/Release/net10.0-windows/StreamLink.WebTests.exe'),['--browser-fixture',path.join(root,'src/StreamLink.Web/wwwroot'),'--pair-workspace','--deferred'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
const lines=createInterface({input:child.stdout});let browser;const stderr=[];child.stderr.on('data',x=>stderr.push(x.toString()));
const link=new Promise((resolve,reject)=>{lines.once('line',resolve);child.once('exit',code=>reject(Error('Fixture exited: '+code+' '+stderr.join(''))));});child.stdin.write('open\n');
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="settings"]').click();await page.locator('#configuration-name').waitFor();
 await page.locator('[data-workspace="new-configuration"]').click();await page.locator('#configuration-name').fill('浏览器配置');
 await page.locator('[data-key="mode"]').selectOption('existing');await page.locator('[data-entry-index="0"]').fill('entry.example.com#streamlink1');
 await page.locator('#save-section').click();await page.waitForFunction(()=>workspaceState.configurations.some(c=>c.name==='浏览器配置'));
 await page.locator('[data-section="network"]').click();if(await page.locator('[data-entry-index="0"]').inputValue()!=='txt://entry.example.com#streamlink1')throw Error('Canonical source lost');
 await page.locator('[data-section="stun"]').click();await page.locator('[data-section="network"]').click();if(!await page.locator('[data-key="mode"]').evaluate(e=>e.value==='existing'))throw Error('Saved mode changed');
 await page.locator('[data-entry-index="0"]').fill('changed.example.com#streamlink2');await page.waitForTimeout(2500);if(await page.locator('[data-entry-index="0"]').inputValue()!=='changed.example.com#streamlink2')throw Error('Poll replaced draft');
 await page.locator('[data-workspace="device-scope"]').click();await page.locator('[data-workspace="configuration-scope"]').click();if(await page.locator('[data-entry-index="0"]').inputValue()!=='changed.example.com#streamlink2')throw Error('Scope switch lost draft');
 await page.locator('#revert-section').click();if(await page.locator('[data-entry-index="0"]').inputValue()!=='txt://entry.example.com#streamlink1')throw Error('Revert lost saved config');
 await page.locator('[data-key="coordinatorBackup"]').check();await page.locator('[data-section="coordination"]').click();await page.locator('[data-key="url"]').fill('https://coord.example.test/');
 await page.locator('#save-section').click();await page.waitForFunction(()=>workspaceState.configurations.some(c=>c.name==='浏览器配置'&&c.settings.coordinatorBackup&&c.settings.service==='https://coord.example.test/'));
 await page.locator('[data-section="network"]').click();if(!await page.locator('[data-key="coordinatorBackup"]').isChecked())throw Error('Saved backup switch lost');
 await page.locator('[data-workspace="device-scope"]').click();await page.locator('[data-workspace="configuration-scope"]').click();if(!await page.locator('[data-key="coordinatorBackup"]').isChecked())throw Error('Backup setting lost on scope change');
 await page.screenshot({path:path.join(output,'settings.png'),fullPage:true});
 await page.locator('.nav[data-page="create"]').click();if(!await page.locator('[data-action="create"]').isEnabled())throw Error('Create blocked without network');await page.screenshot({path:path.join(output,'create.png'),fullPage:true});
 await page.locator('.nav[data-page="join"]').click();await page.locator('#join-code').fill('123456');await page.waitForTimeout(2500);if(await page.locator('#join-code').inputValue()!=='123456')throw Error('Pairing input lost on poll');
 await page.locator('#join-help summary').click();await page.locator('.nav[data-page="settings"]').click();await page.locator('.nav[data-page="join"]').click();if(!await page.locator('#join-help').evaluate(e=>e.open))throw Error('Disclosure state lost');await page.screenshot({path:path.join(output,'join.png'),fullPage:true});
 await page.locator('.nav[data-page="logs"]').click();await page.locator('[data-settings="logging"]').click();if(!await page.evaluate(()=>settingsScope==='device'&&section==='logging'))throw Error('Log settings route selected wrong scope');
 await page.locator('[data-key="level"]').selectOption('warn');await page.locator('#save-section').click();await page.waitForFunction(()=>workspaceState.logLevel==='warn');
 await page.locator('.nav[data-page="overview"]').click();await page.screenshot({path:path.join(output,'overview.png'),fullPage:true});
 await page.waitForFunction(()=>!busy);
 await page.evaluate(()=>{const base=structuredClone(workspaceState),c=base.configurations[0];base.networks=[1,2].map(i=>({id:String(i).repeat(32),name:'审批网络'+i,configurationId:c.id,status:{...base,networkId:String(i+2).repeat(32),isOwner:true,networkEnabled:true,peers:[],settings:c.settings,pairing:{active:true,owner:true,code:'123456',verification:'654321',candidate:'a'.repeat(32),peerName:'申请设备'+i,expires:Date.now()/1000+300}}}));page='join';joinTab='incoming';selectedNetwork='';render(base);});
 for(const button of await page.locator('[data-request-network]').all())if(!await button.isEnabled())throw Error('Global approval list disabled an actionable button: '+JSON.stringify(await page.evaluate(()=>({busy,online,expired,serviceReady:state?.serviceReady,pairing:state?.pairing,requests:workspaceState?.networks.map(n=>({id:n.id,pairing:n.status.pairing}))}))));
 if(await page.locator('[data-action="approve"].positive').count()!==2||await page.locator('[data-action="reject"].danger').count()!==2)throw Error('Approval colors or request count wrong');
 if(errors.length)throw Error(errors.join('; '));fs.writeFileSync(path.join(output,'result.json'),JSON.stringify({passed:true,checks:['configuration save and selection','canonical selector preserved','poll preserves draft','device/config scope drafts','revert','create readiness','pair code editable and stable','disclosure state'],errors},null,2));console.log('PASS 配置保存、来源标签、草稿隔离、输入与折叠状态');
 }catch(error){console.error(error.stack||error);process.exitCode=1;if(browser){const pages=browser.contexts().flatMap(c=>c.pages());if(pages[0]){await pages[0].screenshot({path:path.join(output,'failure.png'),fullPage:true});console.error((await pages[0].locator('body').innerText()).slice(-3500));}}}
 finally{await browser?.close();child.stdin.write('quit\n');setTimeout(()=>child.kill(),3000).unref();}
})();
