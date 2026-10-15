// Development-only browser checks. Product runtime contains no Node/Playwright.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('child_process');
const {createInterface}=require('readline');
const fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'..'),out=path.resolve(process.argv[2]||path.join(root,'artifacts/aq-browser'));
fs.mkdirSync(out,{recursive:true});
const exe=path.join(root,'tests/StreamLink.WebTests/bin/Release/net10.0-windows/StreamLink.WebTests.exe');
const child=spawn(exe,['--browser-fixture',path.join(root,'src/StreamLink.Web/wwwroot')],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
let errors='',browser;child.stderr.on('data',d=>errors+=d.toString());
const lines=createInterface({input:child.stdout}),queue=[],waiting=[];
lines.on('line',l=>waiting.length?waiting.shift()(l):queue.push(l));
const line=()=>queue.length?Promise.resolve(queue.shift()):Promise.race([new Promise(r=>waiting.push(r)),new Promise((_,r)=>setTimeout(()=>r(Error('fixture startup timeout')),20000))]);
let checks=0;const findings=[];function check(ok,label){checks++;if(!ok)throw Error(label);findings.push(label);}
(async()=>{
 try{
  child.stdin.write('open\n');const link=await line();if(!link.startsWith('http://127.0.0.1:'))throw Error('fixture returned no launch link');
  browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1050}});const page=await context.newPage();const jsErrors=[];page.on('pageerror',e=>jsErrors.push(e.message));
  await page.goto(link);await page.getByText('个人后台已就绪',{exact:true}).waitFor();
  check(!page.url().includes('#'),'one-use fragment removed from browser location');
  await page.screenshot({path:path.join(out,'overview-desktop.png'),fullPage:true});
  await page.locator('[data-page="diagnostics"]').click();await page.locator('#device-name').fill('AQ browser draft');
  await page.waitForTimeout(3000);check(await page.locator('#device-name').inputValue()==='AQ browser draft','polling preserves edited metadata draft');
  await page.getByRole('button',{name:'保存设备设置',exact:true}).click();await page.getByText('设备设置已保存，当前连接保持运行。',{exact:true}).waitFor();
  await page.reload();await page.getByText('个人后台已就绪',{exact:true}).waitFor();await page.locator('[data-page="diagnostics"]').click();
  check(await page.locator('#device-name').inputValue()==='AQ browser draft','real backend persisted metadata across page reload');
  await page.locator('[data-page="settings"]').click();await page.locator('#allow-quality').check();
  await page.getByRole('button',{name:'保存连接设置',exact:true}).click();await page.getByText('设置已保存。',{exact:true}).waitFor();
  check(await page.locator('#allow-quality').isChecked(),'permitted connection setting saved through restricted service handler');
  await page.locator('[data-page="network"]').click();await page.locator('#server').fill('http://127.0.0.1/');await page.getByRole('button',{name:'创建网络',exact:true}).click();
  await page.getByText('请填写 HTTPS 协调地址',{exact:true}).waitFor();check(true,'invalid coordination scheme produces actionable error without I/O');
  await page.locator('[data-page="overview"]').click();await page.locator('#theme').click();
  check(await page.locator('html').getAttribute('data-theme')==='light','light theme works');
  await page.screenshot({path:path.join(out,'overview-light.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'390px layout has no horizontal overflow');
  await page.screenshot({path:path.join(out,'overview-mobile.png'),fullPage:true});
  await page.keyboard.press('Tab');check(await page.evaluate(()=>document.activeElement.tagName)!=='BODY','keyboard focus is reachable');
  check(jsErrors.length===0,'no browser JavaScript errors');
  await page.close();const reopened=await context.newPage();await reopened.goto(new URL(link).origin);await reopened.getByText('个人后台已就绪',{exact:true}).waitFor();check(true,'closing/reopening browser page preserves backend');
  fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,findings,scope:'real headless Edge + isolated actual ControlWorker; no SCM/driver/physical WAN/user streaming claim'},null,2));
 }catch(e){fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Fail',checks,findings,error:e.message,stderr:errors},null,2));process.exitCode=1;}
 finally{if(browser)await browser.close();child.stdin.end('quit\n');await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>setTimeout(()=>{child.kill();r();},5000))]);lines.close();}
})().then(()=>process.exit(process.exitCode||0));
