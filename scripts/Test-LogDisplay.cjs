// Real isolated WebPanel, controlled status snapshots: no installed service changes.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.join(root,'artifacts/maintenance-1.4.1/log-browser');
fs.mkdirSync(out,{recursive:true});
const fixture=spawn(path.join(root,'tests/ConWU.WebTests/bin/Release/net10.0-windows/ConWU.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/ConWU.Web/wwwroot'),'--pair-workspace'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
const lines=createInterface({input:fixture.stdout});let browser,stderr='',checks=0;
fixture.stderr.on('data',x=>stderr+=x);
const link=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error(stderr||'fixture timeout')),25000);lines.once('line',line=>{clearTimeout(timer);resolve(line);});});
fixture.stdin.write('open\n');
function check(value,label){if(!value)throw Error(label);checks++;console.log('PASS '+label);}
const now=Date.now(),events=[{id:'long-1',timestamp:now,text:'12:29:54 [INFO] '+('long-content '.repeat(180))+'\ncontinuation <img src=x onerror=alert(1)>'}];
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1100,height:850}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.route('**/api/status*',async route=>{
  const response=await route.fetch(),body=await response.json(),s=body.status;
  body.status={...s,workspaceVersion:2,selectedNetworkId:'',logEntries:events.slice(),logs:[],networks:[]};
  await route.fulfill({response,json:body});
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();await page.locator('.nav[data-page="logs"]').click();
 const terminal=page.locator('#terminal-content'),rows=page.locator('.log-entry');
 check(await rows.count()===1,'one backend event is exactly one visible row, including multiline content');
 check(await rows.first().locator('span').nth(0).innerText()==='12:29:54'&&await rows.first().locator('span').nth(1).innerText()==='[INFO]','time and severity stay intact beside a long message');
 check(await rows.first().evaluate(e=>getComputedStyle(e).whiteSpace==='pre'&&e.getBoundingClientRect().height<40),'long records do not wrap or grow into several lines');
 check(await terminal.evaluate(e=>e.scrollWidth>e.clientWidth+500&&getComputedStyle(e).overflowX==='auto'),'the terminal provides its own horizontal scroll range');
 check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'long logs do not widen the page');
 check(await rows.first().locator('.message').innerText().then(t=>t.includes('↵ continuation <img'))&&await rows.locator('img').count()===0,'embedded newlines are shown inline and log content remains plain text');
 await page.locator('#auto-scroll').uncheck();await terminal.evaluate(e=>e.scrollLeft=350);
 await page.evaluate(()=>refresh());await page.evaluate(()=>refresh());
 check(await rows.count()===1&&await terminal.evaluate(e=>e.scrollLeft===350),'quiet polling adds no fake events and preserves horizontal position');
 events.push({id:'next-2',timestamp:now+1000,text:'12:40:55 [WARN] fixture-new-record'});
 await page.evaluate(()=>refresh());await rows.filter({hasText:'fixture-new-record'}).waitFor();
 check(await rows.count()===2,'a new backend event appears without reopening or reloading the log page');
 await page.evaluate(()=>refresh());check(await rows.count()===2,'repeated snapshots cannot duplicate a log event');
 await page.locator('#log-filter').selectOption('WARN');check(await rows.count()===1&&await rows.first().innerText().then(t=>t.includes('fixture-new-record')),'severity filtering still selects the expected new record');
 await page.locator('#log-filter').selectOption('ALL');await page.locator('#log-search').fill('continuation');check(await rows.count()===1,'search still matches a long event containing an embedded newline');
 await page.setViewportSize({width:390,height:844});
 check(await terminal.evaluate(e=>e.scrollWidth>e.clientWidth)&&await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'narrow screens retain horizontal scrolling inside the terminal');
 check(errors.length===0,'log refresh and filtering produce no browser exceptions');
 await page.screenshot({path:path.join(out,'log-one-line.png'),fullPage:true});
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,productionServicesModified:false},null,2));
}finally{await browser?.close();lines.close();fixture.stdin.end('quit\n');await new Promise(resolve=>{const timer=setTimeout(()=>{fixture.kill();resolve();},5000);fixture.once('exit',()=>{clearTimeout(timer);resolve();});});}})().catch(e=>{console.error(e);process.exitCode=1;});
