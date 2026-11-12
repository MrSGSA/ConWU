// Exercise delayed, superseded status replies against the production WebUI.
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),assets=path.join(root,'src/StreamLink.Web/wwwroot');
const remote=process.argv.includes('--remote');
const {chromium}=require(process.env.CONWU_BROWSER_TOOLS||path.resolve(root,'../StreamLink/out/browser-tools/node_modules/playwright'));
const settings={service:'',certificatePin:'',manualEndpoint:'',pathSelection:'faketcp-only',listenPort:44680,sourcePort:44691,connectionSource:'custom',directMode:true,discoveryMode:'pkarr',pkarrPublish:true,pkarrGateways:['https://pkarr.pubky.app'],existingEntries:[],entryRefreshSeconds:60,requestedVirtualIp:'',tcpStun:[],udpStun:[],coordinator:{enabled:false}};
const model={version:'1.2.0-test',deviceName:'Fresh device',state:'就绪',serviceReady:true,networkEnabled:false,directPeers:0,totalPeers:0,peers:[],logLevel:'info',settings,settingsRevision:'1',deviceSettings:settings,deviceSettingsRevision:'1',networkDefaults:settings,workspaceVersion:2,selectedNetworkId:'',networks:[],configurations:[],logs:[],desktop:{autoStart:true,serviceRegistered:true},aggregate:{sentBytes:0,receivedBytes:0}};
const checks=[],errors=[];let mode='normal',statusReplies=0;
const check=(value,name)=>{if(!value)throw Error(name);checks.push(name);console.log('PASS '+name);};
(async()=>{
 const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage();page.on('pageerror',e=>errors.push(e.message));
 await page.route('https://conwu.test/**',async route=>{
  const u=new URL(route.request().url());if(remote)u.pathname=u.pathname.replace(/^\/admin(?=\/)/,'');
  if(u.pathname==='/api/session')return route.fulfill({json:{csrf:'fixture'}});
  if(u.pathname==='/api/status'){
   if(mode==='offline')return route.abort('failed');
   const superseded=mode==='superseded';
   if(superseded){
    await new Promise(resolve=>setTimeout(resolve,1000));
    // The request began before a foreground generation change. Its success
    // proves liveness, but its old device/network state must be discarded.
    if(!page.isClosed())await page.evaluate(()=>generation++);
   }
   statusReplies++;
   return route.fulfill({json:{ok:true,status:superseded?{...model,deviceName:'STALE SNAPSHOT'}:model}}).catch(error=>{if(!page.isClosed())throw error;});
  }
  if(u.pathname==='/api/command')return route.fulfill({json:{ok:true,status:model}});
  return route.fulfill({path:path.join(assets,u.pathname==='/'?'index.html':u.pathname),contentType:u.pathname.endsWith('.js')?'application/javascript':u.pathname.endsWith('.css')?'text/css':u.pathname.endsWith('.svg')?'image/svg+xml':'text/html'});
 });
 try{
  await page.goto(remote?'https://conwu.test/admin/':'https://conwu.test/#'+'A'.repeat(64));
  await page.waitForFunction(()=>state?.serviceReady&&online);
  mode='superseded';const before=statusReplies;
  await page.waitForTimeout(12500);
  check(statusReplies-before>=5,'superseded replies trigger prompt follow-up status requests');
  check(await page.evaluate(()=>online&&!document.querySelector('#notice').textContent.includes('超过 10 秒')),'healthy backend replies do not become an offline warning when UI generations change');
  check(await page.evaluate(()=>state.deviceName==='Fresh device'),'superseded snapshots never overwrite current device or network state');
  mode='normal';await page.waitForFunction(()=>online&&performance.now()-lastStatusAt<1000);
  mode='offline';await page.waitForFunction(()=>!online,{},{timeout:16000});
  check(await page.locator('#backend-state').innerText()==='后台状态未更新','a genuine backend outage still becomes visible within the existing deadline');
  mode='normal';await page.waitForFunction(()=>online,{},{timeout:5000});
  check(await page.locator('#notice').isHidden(),'successful recovery clears the transient backend warning');
  check(!errors.length,'no browser script errors');
  const output=process.env.CONWU_FRESHNESS_OUTPUT||path.join(root,'artifacts/transport-next/backend-freshness.json');
  fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,JSON.stringify({status:'Pass',checks,statusReplies},null,2));
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
