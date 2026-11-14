// Real isolated WebPanel/backend; runtime traffic metadata is simulated here.
// Real WinDivert/UU paths are validated separately, never by this browser test.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.resolve(process.argv[2]||path.join(root,'artifacts/uu-remote-lab/ui-tests'));
fs.mkdirSync(out,{recursive:true});
const child=spawn(path.join(root,'tests/ConWU.WebTests/bin/Release/net10.0-windows/ConWU.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/ConWU.Web/wwwroot'),'--pair-workspace'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
let browser,stderr='',lastStatus,metadata=null,writes=[],checks=0,delay=0,rejectNext=false,removeSelected=false;
const first='10101010101010101010101010101010',second='20202020202020202020202020202020';
child.stderr.on('data',v=>stderr+=v);const lines=createInterface({input:child.stdout});
const link=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Fixture did not open: '+stderr)),25000);lines.once('line',value=>{clearTimeout(timer);resolve(value);});});
child.stdin.write('open\n');
function check(ok,label){if(!ok)throw Error(label);checks++;console.log('PASS '+label);}
function decorate(body){
 if(!body.status)return body;
 const s=body.status,u=s.uuTakeover;
 const make=(id,name)=>({id,name,status:{...s,networks:[],aggregate:null,networkId:id,isOwner:true,virtualIp:'10.203.1.1',directPeers:1,peers:[],settingsRevision:'fixture'}});
 s.networks=[...(!removeSelected?[make(first,'主机—笔记本')]:[]),make(second,'主机—安卓')];
 if(metadata&&u?.settings?.enabled)s.uuTakeover={...u,...metadata};
 lastStatus=s;return body;
}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:1000}}),errors=[];page.on('pageerror',e=>{errors.push(e.message);console.error('BROWSER '+e.message);});
 page.on('response',r=>{if(r.status()>=400)console.error('HTTP '+r.status()+' '+new URL(r.url()).pathname);});
 await page.route('**/api/status*',async route=>{const response=await route.fetch();await route.fulfill({response,json:decorate(await response.json())});});
 await page.route('**/api/command',async route=>{
  const data=route.request().postDataJSON();writes.push(data);
  if(data.method==='uu-takeover'){
   if(delay)await new Promise(resolve=>setTimeout(resolve,delay));
   if(rejectNext){rejectNext=false;return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:false,error:'模拟设置冲突，请核对后重试',status:lastStatus})});}
  }
  const response=await route.fetch();await route.fulfill({response,json:decorate(await response.json())});
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor({timeout:15000});
 await page.locator('.nav[data-page="settings"]').click();
 await page.locator('#device-name').fill('保持本机名草稿');
 await page.locator('.nav[data-page="uu"]').click();
 await page.locator('#uu-takeover-section').waitFor();
 check(await page.locator('.nav[data-page="uu"]').innerText()==='UU远程'&&await page.locator('#uu-takeover-detail,#uu-takeover-traffic').count()===0,'UU navigation is concise and duplicate status details are removed');
 check(!await page.locator('#uu-takeover-enabled').isChecked(),'takeover is a separate default-off setting');
 check(await page.locator('#uu-takeover-networks [role="listitem"]').count()===2&&await page.locator('#uu-takeover-section select').count()===0,'all networks appear automatically with no manual network selector');
 check(writes.length===0,'opening the page does not write settings');
 delay=900;await page.locator('#uu-takeover-enabled').check();
 check(await page.locator('#uu-takeover-enabled').isDisabled()&&await page.evaluate(()=>!busy),'saving the option disables its own switch without locking network actions');
 await page.waitForFunction(()=>workspaceState?.uuTakeover?.settings?.enabled===true);delay=0;
 await page.locator('#uu-takeover-state').filter({hasText:'等待 ConWU 直连'}).waitFor();
 check(!await page.locator('#uu-takeover-dot').evaluate(el=>el.classList.contains('good')),'enabled alone never displays a successful connection');
 metadata={state:'Ready',rulesActive:true,trafficObserved:false,message:'接管已就绪；请新建或重新连接 UU 会话',networkId:first,networkName:'主机—笔记本',virtualIp:'10.203.1.2',processIds:[123]};
 await page.evaluate(()=>refresh());await page.locator('#uu-takeover-state').filter({hasText:'等待 UU 连接'}).waitFor();
 check(!await page.locator('#uu-takeover-dot').evaluate(el=>el.classList.contains('good')),'installed rules are distinct from observed UU traffic');
 metadata={...metadata,state:'Transmitting',message:'已检测到 UU 持续流量经过 ConWU',trafficObserved:true,receivedBytes:3145728,sentBytes:65536,recentBytesPerSecond:1000000,networks:[{id:first,trafficObserved:true,receivedBytes:3145728,sentBytes:65536}]};
 await page.evaluate(()=>refresh());await page.locator('#uu-takeover-state').filter({hasText:'经由 ConWU 传输'}).waitFor();
 check(await page.locator('#uu-takeover-dot').evaluate(el=>el.classList.contains('good'))&&await page.locator(`#uu-takeover-networks [data-uu-network="${first}"]`).innerText().then(t=>t.includes('3.00 MiB')&&t.includes('0.06 MiB')&&t.includes('检测到 UU 流量')),'live traffic state and per-network counters update in place');
 check(writes.length===1&&writes[0].uuTakeover.settings.enabled===true&&!writes[0].uuTakeover.settings.networkId,'only the enabled option is saved; no network selection is persisted');
 check(await page.evaluate(()=>!busy),'live traffic polling never locks other pages');
 metadata={...metadata,state:'Idle',message:'已检测到 UU 数据，当前流量较少或会话空闲',trafficObserved:false,recentBytesPerSecond:500};
 await page.evaluate(()=>refresh());await page.locator('#uu-takeover-state').filter({hasText:'当前低流量'}).waitFor();
 check(!await page.locator('#uu-takeover-state').innerText().then(t=>t.includes('等待 UU 连接')),'an idle session is not shown as disconnected');
 metadata={...metadata,state:'Transmitting',message:'已检测到 UU 持续流量经过 ConWU',trafficObserved:true,recentBytesPerSecond:1000000};await page.evaluate(()=>refresh());
 await page.screenshot({path:path.join(out,'uu-takeover-page.png'),fullPage:true});
 metadata={...metadata,state:'Ready',rulesActive:true,trafficObserved:false,message:'其余已直连网络仍可自动接管',networkId:second,networkName:'主机—安卓',networks:[{id:second,virtualIp:'10.203.2.2'}]};
 removeSelected=true;await page.evaluate(()=>refresh());await page.locator('#uu-takeover-state').filter({hasText:'等待 UU 连接'}).waitFor();
 check(await page.locator('#uu-takeover-networks [role="listitem"]').count()===1&&await page.locator('#uu-takeover-networks').innerText().then(t=>t.includes('主机—安卓')),'removing one network keeps the remaining network available without another setting');
 check(!await page.locator('#uu-takeover-dot').evaluate(el=>el.classList.contains('good')),'a topology change waits for new traffic evidence');
 rejectNext=true;await page.locator('#uu-takeover-enabled').uncheck();
 await page.locator('#uu-takeover-error').filter({hasText:'模拟设置冲突'}).waitFor();
 check(await page.locator('#uu-takeover-enabled').isChecked()&&await page.evaluate(()=>!busy),'rejected save restores persisted intent and leaves unrelated actions usable');
 metadata={...metadata,state:'Error',message:'<img src=x onerror=alert(1)>'};
 await page.locator('#uu-takeover-enabled').uncheck();
 await page.waitForFunction(()=>workspaceState?.uuTakeover?.settings?.enabled===false);
 await page.locator('#uu-takeover-enabled').check();
 await page.locator('#uu-takeover-error').filter({hasText:'<img'}).waitFor();
 check(await page.locator('#uu-takeover-error img').count()===0,'runtime error text cannot inject markup');
 await page.locator('#uu-takeover-enabled').uncheck();
 await page.waitForFunction(()=>workspaceState?.uuTakeover?.settings?.enabled===false);
 await page.locator('.nav[data-page="settings"]').click();
 check(await page.locator('#device-name').inputValue()==='保持本机名草稿'&&await page.locator('#uu-takeover-section').count()===0&&errors.length===0,'UU has its own page and other settings retain the unsaved device-name draft');
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,backendSettingsWrites:writes.length,nativeDriverOpened:false,productionServicesModified:false},null,2));
}finally{
 await browser?.close();lines.close();child.stdin.end('quit\n');
 await new Promise(resolve=>{const timer=setTimeout(()=>{child.kill();resolve();},5000);child.once('exit',()=>{clearTimeout(timer);resolve();});});
}})().catch(error=>{console.error(error);process.exitCode=1;});
