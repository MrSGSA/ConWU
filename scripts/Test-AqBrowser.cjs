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
  await page.goto(link);await page.getByText('后台已就绪',{exact:true}).waitFor();
  check(!page.url().includes('#'),'one-use fragment removed from browser location');
  check(await page.locator('.nav').count()===3,'three navigation entries with device list on the connection page');
  await page.screenshot({path:path.join(out,'overview-desktop.png'),fullPage:true});
  await page.locator('[data-page="settings"]').click();await page.locator('#device-name').fill('AQ browser draft');
  await page.waitForTimeout(3000);check(await page.locator('#device-name').inputValue()==='AQ browser draft','polling preserves edited metadata draft');
  await page.getByRole('button',{name:'保存设备设置',exact:true}).click();await page.getByText('设备设置已保存，当前连接保持运行。',{exact:true}).waitFor();
  await page.reload();await page.getByText('后台已就绪',{exact:true}).waitFor();await page.locator('[data-page="settings"]').click();
  check(await page.locator('#device-name').inputValue()==='AQ browser draft','real backend persisted metadata across page reload');
  await page.locator('#connection-settings > summary').click();await page.locator('#allow-quality').check();
  await page.waitForTimeout(3000);check(await page.locator('#allow-quality').isChecked(),'polling preserves connection settings draft');
  await page.getByRole('button',{name:'保存连接设置',exact:true}).click();await page.getByText('设置已保存。',{exact:true}).waitFor();
  check(await page.locator('#allow-quality').isChecked(),'permitted connection setting saved through restricted service handler');
  await page.locator('[data-page="network"]').click();await page.locator('#server').fill('http://127.0.0.1/');await page.getByRole('button',{name:'创建网络',exact:true}).click();
  await page.getByText('请填写 HTTPS 协调地址',{exact:true}).waitFor();check(true,'invalid coordination scheme produces actionable error without I/O');
  // Feed statuses through HTTP, exercising the shipped rendering/timers rather
  // than calling JS internals. This section is UI evidence, not WAN evidence.
  const base=(await (await page.request.get(new URL('/api/status',link).href)).json()).status;
  const peer={slot:2,name:'Akane',virtualIp:'10.81.7.2',connected:true,degraded:false,rttMs:23.4,phase:'P2P 直连',actualTransport:'FakeTCP+HTTP',traversalMethod:'ExplicitEntry',sentBytes:1024,receivedBytes:2048,droppedPackets:0,quality:'Unknown',liveness:{reason:'Healthy',receiveAgeMs:10,roundTripAgeMs:50},connection:{phase:'Connected',detail:'已验证直连',elapsedMs:35000,attempt:1,canRetry:false}};
  let mock={...base,state:'已直连',virtualIp:'10.81.7.1',networkId:'browser-fixture',networkEnabled:true,totalPeers:1,directPeers:1,peers:[peer],connection:{phase:'Connected',detail:'直连已通过双向验证，可复制设备 IP 开始串流。',elapsedMs:35000,attempt:1,canRetry:false}},failure=0,retryDeadline=0;
  await page.route('**/api/status',r=>{
    if(retryDeadline)mock.connection.retryInSeconds=Math.max(0,Math.ceil((retryDeadline-Date.now())/1000));
    return r.fulfill({status:failure||200,contentType:'application/json',body:JSON.stringify(failure?{ok:false,code:'Stopped',error:'本机后台暂未响应'}:{ok:true,status:mock})});
  });
  await page.locator('[data-page="overview"]').click();await page.locator('#refresh').click();await page.getByRole('heading',{name:'Akane',exact:true}).waitFor();
  check(await page.locator('#retry').isHidden(),'healthy connection does not invite unnecessary retry');
  await page.locator('.peer details > summary').click();await page.waitForTimeout(3000);
  check(await page.locator('.peer details').evaluate(e=>e.open),'polling preserves expanded peer details');
  await page.screenshot({path:path.join(out,'connection-desktop.png'),fullPage:true});
  const healthy={...mock};
  const offline={...peer,slot:3,name:'未开机的电脑',virtualIp:'10.81.7.3',connected:false,rttMs:null,connection:{phase:'Offline',detail:'尚未收到此设备的有效上线信息；上线后会自动连接。',elapsedMs:0,canRetry:false}};
  mock={...healthy,totalPeers:2,peers:[peer,offline],connection:{...healthy.connection,detail:'已直连 1 台设备；另有 1 台设备未在线，上线后会自动连接。'}};
  await page.locator('#refresh').click();await page.getByRole('heading',{name:'未开机的电脑',exact:true}).waitFor();
  check(await page.locator('#network-state').innerText()==='已直连'&&await page.locator('#connection-steps').isHidden()&&await page.locator('#retry').isHidden(),'an offline paired device does not turn a healthy connection into waiting');
  check(await page.locator('.peer').nth(1).locator('.badge').innerText()==='未在线'&&!(await page.locator('.peer').nth(1).innerText()).includes('已等待'),'offline device has no indefinitely growing wait timer');
  await page.screenshot({path:path.join(out,'connected-with-offline-member.png'),fullPage:true});
  mock={...mock,state:'网络已就绪',directPeers:0,totalPeers:1,peers:[offline],connection:{phase:'Idle',detail:'已配对设备暂未在线，上线后会自动连接。',elapsedMs:0,canRetry:false}};
  await page.locator('#refresh').click();await page.getByRole('heading',{name:'网络已就绪',exact:true}).waitFor();
  check(await page.locator('#connection-progress').innerText()===''&&await page.locator('#connection-steps').isHidden()&&await page.locator('#connection-card').getAttribute('data-state')==='idle','network with only offline members is ready without a pending progress indicator');
  mock={...mock,totalPeers:0,peers:[],pairing:null,connection:{...mock.connection,detail:'当前没有其他设备；需要时可在“添加设备”中邀请电脑。'}};
  await page.locator('#refresh').click();await page.locator('.empty').waitFor();
  check(!(await page.locator('.empty').innerText()).includes('等待')&&await page.locator('#retry').isHidden(),'empty membership does not request more devices or repeated retries');
  await page.screenshot({path:path.join(out,'idle-network.png'),fullPage:true});
  await page.locator('[data-page="network"]').click();
  check(await page.locator('#verification').innerText()==='—','no pairing request is shown as waiting unless an invitation is active');
  mock={...healthy,directPeers:0,peers:[{...offline,connection:{phase:'WaitingPeer',detail:'等待本轮直连响应',elapsedMs:3000,remainingSeconds:10,canRetry:true}}],connection:{phase:'WaitingPeer',detail:'等待本轮直连响应',elapsedMs:3000,remainingSeconds:10,canRetry:true},state:'等待设备响应'};
  await page.locator('[data-page="overview"]').click();await page.locator('#refresh').click();await page.getByRole('heading',{name:'等待设备响应',exact:true}).waitFor();
  check(await page.locator('#connection-steps').isVisible()&&(await page.locator('#connection-progress').innerText()).includes('本轮剩余'),'a real bounded connection attempt still shows progress and deadline');
  mock={...healthy};
  peer.connected=false;peer.rttMs=null;peer.liveness={reason:'ReturnPathTimedOut',receiveAgeMs:25,roundTripAgeMs:12500};
  peer.connection={phase:'Retrying',detail:'同路径往返验证超时，正在恢复。',elapsedMs:65000,attempt:2,retryInSeconds:9,canRetry:true};
  retryDeadline=Date.now()+9000;
  mock={...mock,state:'正在恢复',directPeers:0,connection:peer.connection};
  await page.locator('#refresh').click();await page.getByRole('heading',{name:'正在恢复',exact:true}).waitFor();
  check((await page.locator('#connection-progress').innerText()).includes('9 秒后重试')&&await page.locator('#retry').isVisible(),'real retry countdown and user action are visible during recovery');
  await page.waitForFunction(()=>!document.getElementById('connection-progress').textContent.includes('9 秒后重试'),null,{timeout:4000});check(true,'retry timer advances between server polls');
  let retryCommand='';await page.route('**/api/command',r=>{retryCommand=r.request().postDataJSON().method;return r.fulfill({contentType:'application/json',body:JSON.stringify({ok:true,status:mock})});});
  await page.locator('#retry').click();await page.getByText('已请求重新探测，健康连接保持运行。',{exact:true}).waitFor();
  check(retryCommand==='retry','retry action calls the dedicated backend method');await page.unroute('**/api/command');
  failure=503;await page.locator('#refresh').click();await page.getByRole('heading',{name:'面板暂未连接后台',exact:true}).waitFor();
  check(await page.locator('#retry').isDisabled()&&await page.locator('.badge').innerText()==='状态未更新','backend failure removes stale connected claims and disables network mutations');
  failure=0;peer.name='<img src=x onerror=alert(1)>';await page.locator('#refresh').click();await page.getByText('后台已就绪',{exact:true}).waitFor();
  check(await page.locator('.peer-name').innerText()===peer.name&&await page.locator('.peer img').count()===0,'peer names render as text, never HTML');
  await page.locator('[data-page="overview"]').click();await page.locator('#theme').click();
  check(await page.locator('html').getAttribute('data-theme')==='light','light theme works');
  await page.screenshot({path:path.join(out,'overview-light.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'390px layout has no horizontal overflow');
  await page.screenshot({path:path.join(out,'overview-mobile.png'),fullPage:true});
  await page.keyboard.press('Tab');check(await page.evaluate(()=>document.activeElement.tagName)!=='BODY','keyboard focus is reachable');
  check(jsErrors.length===0,'no browser JavaScript errors');
  failure=401;await page.locator('#refresh').click();await page.getByRole('heading',{name:'请重新打开面板',exact:true}).waitFor();
  check((await page.locator('#state-detail').innerText()).includes('后台网络继续运行'),'panel session expiration is distinguished from data connection failure');
  await page.close();const reopened=await context.newPage();await reopened.goto(new URL(link).origin);await reopened.getByText('后台已就绪',{exact:true}).waitFor();check(true,'closing/reopening browser page preserves backend');
  fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,findings,scope:'real headless Edge + isolated actual ControlWorker for settings; synthetic HTTP status transitions for recovery/backend failure/expiration; no SCM/driver/physical WAN/user streaming claim'},null,2));
 }catch(e){fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Fail',checks,findings,error:e.message,stderr:errors},null,2));process.exitCode=1;}
 finally{if(browser)await browser.close();child.stdin.end('quit\n');await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>setTimeout(()=>{child.kill();r();},5000))]);lines.close();}
})().then(()=>process.exit(process.exitCode||0));
