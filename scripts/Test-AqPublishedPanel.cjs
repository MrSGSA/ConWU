const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('child_process');
const {createInterface}=require('readline');
const fs=require('fs'),path=require('path');
const [bundle,id,out,...flags]=process.argv.slice(2),readOnly=flags.includes('--read-only');
if(!/^[0-9a-f]{32}$/.test(id)&&!(id==='daily'&&readOnly))throw Error('Validation ID required; daily verification must be read-only');
fs.mkdirSync(out,{recursive:true});
const child=spawn(path.join(bundle,'web','StreamLink.Web.exe'),[...(id==='daily'?[]:['--validation-instance',id]),'--controlled'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
let stderr='',browser,page,checks=[];child.stderr.on('data',d=>stderr+=d.toString());
const lines=createInterface({input:child.stdout}),queue=[],waiting=[];
lines.on('line',l=>waiting.length?waiting.shift()(l):queue.push(l));
const next=()=>queue.length?Promise.resolve(queue.shift()):Promise.race([new Promise(r=>waiting.push(r)),new Promise((_,r)=>setTimeout(()=>r(Error('panel startup timeout')),15000))]);
function check(ok,label){if(!ok)throw Error(label);checks.push(label);}
(async()=>{try{
 child.stdin.write('open\n');const link=await next();check(link.startsWith('http://127.0.0.1:')&&new URL(link).hash.length===65,'published host started with anonymous-pipe launch ticket');
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:1050}});page=await context.newPage();page.setDefaultTimeout(12000);
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(link);await page.getByText('后台运行中',{exact:true}).waitFor();
 check(!page.url().includes('#'),'ticket removed');
 await page.screenshot({path:path.join(out,'published-overview.png'),fullPage:true});
 if(!readOnly){const deviceName='AQ installed '+Date.now().toString(36);
 await page.locator('[data-page="settings"]').click();await page.locator('[data-setting-section=identity]').click();await page.locator('#settings-name').fill(deviceName);
 await page.getByRole('button',{name:'保存本机设置',exact:true}).click();await page.locator('#toast').filter({hasText:'本机设置已保存'}).waitFor();
 await page.reload();await page.getByText('后台运行中',{exact:true}).waitFor();await page.locator('[data-page="settings"]').click();
 check(await page.locator('#settings-name').inputValue()===deviceName,'published Web -> SID pipe -> SCM service persisted restricted metadata');}
 await page.close();const reopened=await context.newPage();await reopened.goto(new URL(link).origin);await reopened.getByText('后台运行中',{exact:true}).waitFor();check(true,'browser close/reopen preserves actual service');
 check(errors.length===0,'no JavaScript errors');
 fs.writeFileSync(path.join(out,'browser.json'),JSON.stringify({status:'Pass',checks,readOnly,instance:id,scope:'published self-contained Web and assets + actual SCM service; launch token is documented separately by the caller; no physical streaming or cross-account/UAC interactive acceptance'},null,2));
 }catch(e){if(page)await page.screenshot({path:path.join(out,'published-failure.png'),fullPage:true}).catch(()=>{});fs.writeFileSync(path.join(out,'browser.json'),JSON.stringify({status:'Fail',checks,error:e.message,stderr},null,2));process.exitCode=1;}
 finally{if(browser)await browser.close();child.stdin.end('quit\n');await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>setTimeout(()=>{child.kill();r();},5000))]);lines.close();}
})().then(()=>process.exit(process.exitCode||0));
