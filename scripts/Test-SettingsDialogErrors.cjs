// Isolated WebPanel regression: errors belong to the dialog that issued the
// action. Rejected API replies never reach a production service or adapter.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.join(root,'artifacts/mobile-pair-fix/settings-errors');
fs.mkdirSync(out,{recursive:true});
const fixture=spawn(path.join(root,'tests/StreamLink.WebTests/bin/Release/net10.0-windows/StreamLink.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/StreamLink.Web/wwwroot'),'--pair-workspace','--deferred'],
 {cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
const lines=createInterface({input:fixture.stdout}),checks=[],errors=[];
let browser,stderr='',failure=null;
fixture.stderr.on('data',value=>stderr+=value);
const link=new Promise((resolve,reject)=>{
 const timer=setTimeout(()=>reject(Error('Fixture timeout '+stderr)),25000);
 lines.once('line',value=>{clearTimeout(timer);resolve(value);});
 fixture.once('exit',code=>{clearTimeout(timer);reject(Error('Fixture exited '+code+' '+stderr));});
});
fixture.stdin.write('open\n');
function check(value,label){if(!value)throw Error(label);checks.push(label);console.log('PASS '+label);}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/api/command',async route=>{
  const request=route.request().postDataJSON();
  if(failure&&failure.matches(request)){
   const current=failure;failure=null;
   if(current.wait)await current.wait;
   await route.fulfill({status:200,json:{ok:false,error:current.message}});return;
  }
  await route.continue();
 });
 const fail=(matches,message,wait)=>{failure={matches,message,wait};};
 const cleanGlobal=async()=>!await page.locator('#notice').evaluate(e=>!e.hidden&&e.classList.contains('error'));
 const settled=()=>page.waitForFunction(()=>!busy);
 const save=()=>page.locator('[data-ui-action="save-editor"]').click();
 const error=()=>page.locator('#settings-error');
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="create"]').click();await page.locator('#new-network-name').fill('设置错误归属回归');
 await page.locator('#open-network-settings').click();
 const size=await page.locator('#network-dialog').boundingBox();
 await page.locator('[data-ui-section="port"]').click();
 await page.locator('[data-key="listen"]').fill('80');await save();
 await error().filter({hasText:'1024'}).waitFor();
 check(await cleanGlobal()&&await page.locator('#network-dialog').isVisible(),'invalid local fields report inside the open settings dialog');
 await page.locator('[data-key="listen"]').fill('43010');
 check(await error().innerText()==='','editing an invalid field clears its obsolete error');
 const rejected='接收端口已被其他网络占用，请选择其他端口。';
 fail(r=>r.method==='configuration',rejected);await save();await settled();
 await error().filter({hasText:rejected}).waitFor({timeout:4000});
 check(await cleanGlobal(),'a backend save rejection is not hidden behind the dialog');
 check(await page.locator('[data-key="listen"]').inputValue()==='43010'&&await page.locator('[data-key="listen"]').isEditable()&&await page.locator('[data-ui-action="save-editor"]').isEnabled(),'failed saving preserves the draft and permits corrections and retry');
 check(await page.locator('[data-key="listen"]').evaluate(e=>document.activeElement===e),'failed saving returns focus to the edited input');
 await page.waitForTimeout(2200);
 check(await error().innerText()===rejected,'background status refresh cannot erase the current dialog error');
 await page.locator('[data-ui-section="stun"]').click();
 await page.locator('[data-key="tcp"]').evaluate(e=>e.style.height='600px');
 const longError='STUN 服务器列表中有无效地址。';
 fail(r=>r.method==='configuration',longError);await save();await settled();
 await error().filter({hasText:longError}).waitFor();
 check(await error().evaluate(e=>{const r=e.getBoundingClientRect(),p=e.parentElement.getBoundingClientRect();return r.top>=p.top-1&&r.bottom<=p.bottom+1;}),'errors in long settings sections scroll into the visible dialog body');
 const after=await page.locator('#network-dialog').boundingBox();
 check(after.width===size.width&&after.height===size.height,'error display preserves the approved fixed dialog dimensions');
 await save();await page.locator('#network-dialog').waitFor({state:'hidden'});
 check(await page.evaluate(()=>workspaceState.configurations.some(c=>c.settings.listenPort===43010)),'retry saves through the real isolated backend');
 await page.locator('#open-network-settings').click();
 check(await error().innerText()==='','reopening saved settings starts without the previous error');
 await page.locator('[data-key="mode"][value="existing"]').check();
 await page.locator('[data-ui-section="entry"]').click();
 await page.locator('[data-ui-action="test-entry"]').click();
 await error().filter({hasText:'请先填写本机入口'}).waitFor();
 check(await cleanGlobal(),'testing an empty entry reports in its settings dialog');
 await page.locator('[data-entry-index="0"]').fill('https://entry.example.invalid/current');
 fail(r=>r.network?.action==='resolve-entries','入口解析失败 <img src=x onerror=alert(1)>');
 await page.locator('[data-ui-action="test-entry"]').click();await settled();
 await error().filter({hasText:'入口解析失败'}).waitFor();
 check(await cleanGlobal()&&await error().locator('img').count()===0,'entry-test failures remain local and are rendered as text');
 // Changing a subscription while its old test is pending must not attach the
 // delayed result to the new source or to a newly opened settings dialog.
 let release;const wait=new Promise(resolve=>release=resolve);
 fail(r=>r.network?.action==='resolve-entries','旧入口的迟到错误',wait);
 await page.locator('[data-ui-action="test-entry"]').click();await page.waitForFunction(()=>busy);
 await page.locator('[data-entry-index="0"]').fill('https://new-entry.example.invalid/current');release();await settled();
 check(await error().innerText()===''&&await cleanGlobal(),'editing a source discards the pending test failure for the old source');
 await page.locator('[data-ui-action="restore-editor"]').click();
 check(await error().innerText()==='','restoring saved settings clears errors');
 await page.locator('[data-ui-action="close-editor"]').first().click();
 await page.locator('.nav[data-page="coordination"]').click();await page.locator('[data-ui-action="open-coordination-settings"]').click();
 const port=page.locator('[data-ui-scope="coordination"][data-ui-key="port"]');
 await port.fill('100');await page.locator('#save-coordination').click();
 await page.locator('#coordination-error').filter({hasText:'1024'}).waitFor();
 check(await cleanGlobal(),'coordinator validation is shown only in its current settings dialog');
 await port.fill('43011');
 fail(r=>r.method==='save-settings','协调端口已占用。');await page.locator('#save-coordination').click();await settled();
 await page.locator('#coordination-error').filter({hasText:'协调端口已占用'}).waitFor();
 check(await cleanGlobal()&&await port.isEditable()&&await page.locator('#save-coordination').isEnabled(),'coordinator backend rejection keeps the editable draft without a duplicate main-page error');
 check(await port.evaluate(e=>document.activeElement===e),'coordinator save failure restores input focus');
 await page.locator('#save-coordination').click();await settled();
 const coordinatorResult={error:await page.locator('#coordination-error').innerText(),port:await page.evaluate(()=>new URL(workspaceState.deviceSettings.coordinator.listenUrl).port)};
 check(coordinatorResult.error===''&&coordinatorResult.port==='43011','a corrected coordinator retry saves and clears the error '+JSON.stringify(coordinatorResult));
 await page.locator('[data-ui-action="close-coordination-settings"]').click();
 await page.locator('[data-ui-action="open-coordination-settings"]').click();
 check(await page.locator('#coordination-error').innerText()==='','reopening coordinator settings has no stale error');
 await page.locator('[data-ui-action="close-coordination-settings"]').click();
 fail(r=>r.method==='save-settings','本机协调服务启动失败。');
 await page.locator('[data-ui-scope="coordinationSwitch"]').check();await settled();
 check(!await cleanGlobal()&&(await page.locator('#notice').innerText()).includes('本机协调服务启动失败'),'actions from the main page retain their main-page error reporting');
 check(errors.length===0,'no browser script errors');
 await page.screenshot({path:path.join(out,'settings-errors.png'),fullPage:true});
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,productionServicesModified:false},null,2));
 console.log('PASS '+checks.length+' settings-dialog checks');
}finally{
 await browser?.close();lines.close();fixture.stdin.end('quit\n');
 await new Promise(resolve=>{if(fixture.exitCode!==null)return resolve();const timer=setTimeout(()=>{fixture.kill();resolve();},5000);fixture.once('exit',()=>{clearTimeout(timer);resolve();});});
}})().catch(error=>{console.error(error);process.exitCode=1;});
