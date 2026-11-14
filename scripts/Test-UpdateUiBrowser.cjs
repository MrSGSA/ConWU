// Browser presentation checks use a real isolated WebPanel and scripted update
// metadata. Service authorization/HTTP concurrency are covered by --update-ui.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.resolve(process.argv[2]||path.join(root,'artifacts/mobile-android/update-browser'));
fs.mkdirSync(out,{recursive:true});
const child=spawn(path.join(root,'tests/ConWU.WebTests/bin/Release/net10.0-windows/ConWU.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/ConWU.Web/wwwroot'),'--pair-workspace'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
let browser,stderr='',metadata={state:'NotChecked',message:'尚未检查更新'},local=null,lastStatus,requests=0,writes=0,checks=0,downloads=0,installs=0;
child.stderr.on('data',value=>stderr+=value);
const lines=createInterface({input:child.stdout});
const link=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Fixture did not open: '+stderr)),25000);lines.once('line',value=>{clearTimeout(timer);resolve(value);});});
child.stdin.write('open\n');
function check(ok,label){if(!ok)throw Error(label);checks++;console.log('PASS '+label);}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:1000}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/api/status*',async route=>{const response=await route.fetch(),body=await response.json();if(body.status){lastStatus=body.status;body.status.update=metadata;if(local)body.status.localUpdate=local;}await route.fulfill({response,json:body});});
 await page.route('**/api/command',async route=>{
  const body=route.request().postDataJSON();
  if(body.method==='update-download'||body.method==='update-install'){
   if(body.method==='update-download'){downloads++;local={supported:true,state:'Downloading',message:'正在下载完整安装包',busy:true,totalBytes:1000,downloadedBytes:100};}
   else{installs++;check(body.localUpdate.ticket===local.ticket&&body.localUpdate.version===local.version,'installation submits only the verified ticket and version');local={...local,state:'Launching',message:'已交给本机独立安装程序',busy:true,canInstall:false};}
   return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,status:{...lastStatus,update:metadata,localUpdate:local}})});
  }
  if(body.method!=='update-check'){writes++;return route.continue();}
  requests++;metadata={state:'Checking',message:'正在检查更新'};
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,status:{...lastStatus,update:metadata}})});
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="settings"]').click();
 await page.locator('#update-state').filter({hasText:'尚未检查更新'}).waitFor();
 await page.locator('#device-name').fill('保留未保存草稿');
 await page.evaluate(()=>window.updateDraftNode=document.querySelector('#device-name'));
 await page.locator('[data-ui-action="check-update"]').click();
 await page.locator('#update-state').filter({hasText:'正在检查更新'}).waitFor();
 check(await page.locator('[data-ui-action="check-update"]').isDisabled(),'checking status updates in place and disables duplicate checks');
 check(await page.evaluate(()=>!busy),'update checks do not lock network operations');
 metadata={state:'Available',message:'发现新版本 9.0.0',latestVersion:'9.0.0',updateAvailable:true,checkedAt:1,
  releaseUrl:'https://github.com/MrSGSA/ConWU/releases/tag/v9.0.0',package:{url:'https://github.com/MrSGSA/ConWU/releases/download/v9.0.0/ConWU-9.0.0-x64.msi'}};
 await page.evaluate(()=>refresh());await page.locator('#update-state').filter({hasText:'发现新版本'}).waitFor();
 check(await page.locator('#software-update-details a').count()===2,'verified release and matching package links appear after polling');
 check(await page.locator('#device-name').inputValue()==='保留未保存草稿'&&await page.evaluate(()=>window.updateDraftNode===document.querySelector('#device-name')),'update completion preserves the draft and its input element');
 local={supported:true,state:'Idle'};await page.evaluate(()=>refresh());
 await page.locator('[data-ui-action="download-update"]').click();await page.locator('progress[aria-label="安装包下载进度"]').waitFor();
 check(downloads===1&&installs===0&&await page.locator('#device-name').isEnabled(),'package download leaves other settings usable and never installs implicitly');
 local={...local,state:'Ready',message:'安装包已下载并校验，等待确认更新',busy:false,canInstall:true,version:'9.0.0',ticket:'123456781234123412341234567890ab'};
 await page.evaluate(()=>refresh());await page.locator('[data-ui-action="install-update"]').click();await page.locator('#dialog-cancel').click();
 check(installs===0,'cancelling the explicit confirmation preserves the downloaded package');
 await page.locator('[data-ui-action="install-update"]').click();await page.locator('#dialog-confirm').click();
 await page.locator('#local-update-state').filter({hasText:'独立安装程序'}).waitFor();
 check(installs===1&&await page.evaluate(()=>!!localStorage.getItem('conwu-local-update')),'confirmed local installation records an expected service restart');
 local={...local,state:'Completed',message:'更新完成，后台和网络已恢复',busy:false};await page.evaluate(()=>refresh());
 check(await page.evaluate(()=>!localStorage.getItem('conwu-local-update')),'verified recovery clears the temporary restart notice');
 local={supported:false,state:'Idle'};
 metadata={state:'Error',message:'<img src=x onerror=alert(1)>',updateAvailable:true,releaseUrl:'https://evil.example/release',package:{url:'javascript:alert(1)'}};
 await page.evaluate(()=>refresh());await page.locator('#update-state').filter({hasText:'<img src=x'}).waitFor();
 check(await page.locator('#software-update-details a,#software-update-details img').count()===0,'failed metadata cannot inject markup or external download links');
 check(await page.locator('[data-ui-action="check-update"]').isEnabled(),'a failed check restores the retry control');
 await page.locator('.nav[data-page="join"]').click();check(await page.locator('#join-invite').isEnabled(),'joining remains available after update failure');
 check(requests===1&&writes===0&&downloads===1&&installs===1&&errors.length===0,'checking, downloading and confirming never write network settings or cause browser errors');
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,productionServicesModified:false},null,2));
}finally{await browser?.close();lines.close();child.stdin.end('quit\n');await new Promise(resolve=>{const timeout=setTimeout(()=>{child.kill();resolve();},5000);child.once('exit',()=>{clearTimeout(timeout);resolve();});});}})().catch(error=>{console.error(error);process.exitCode=1;});
