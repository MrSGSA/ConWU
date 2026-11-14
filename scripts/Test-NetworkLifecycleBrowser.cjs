// Real isolated WebPanel; scripted lifecycle replies never touch installed networks.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');
const out=path.resolve(process.argv[2]||path.join(root,'artifacts/release-1.4.3/browser-lifecycle'));
fs.mkdirSync(out,{recursive:true});
const child=spawn(path.join(root,'tests/ConWU.WebTests/bin/Release/net10.0-windows/ConWU.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/ConWU.Web/wwwroot'),'--pair-workspace','--deferred'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
const stderr=[];child.stderr.on('data',b=>stderr.push(b.toString()));
const link=new Promise((resolve,reject)=>{
 createInterface({input:child.stdout}).once('line',resolve);
 child.once('exit',code=>reject(Error('Fixture exited '+code+' '+stderr.join(''))));
});
child.stdin.write('open\n');
const host='11111111111111111111111111111111',guest='22222222222222222222222222222222';
let template,paused=false,removed=false,browser,checks=0;const commands=[];
function check(ok,label){if(!ok)throw Error(label);checks++;console.log('PASS '+label);}
function fixture(){
 const peer=(name,remotePaused=false)=>({slot:remotePaused?2:1,name,virtualIp:'10.90.1.2',connected:!paused,
  rttMs:12,phase:paused?'Paused':'Connected',connection:{phase:paused?'Paused':'Connected'},sentBytes:100,receivedBytes:200});
 const network=(owner,id)=>({...template,networkId:id,isOwner:owner,networkEnabled:owner||!paused,
  networkPaused:!owner&&paused,virtualIp:owner?'10.90.1.1':'10.90.2.2',directPeers:paused?0:1,
  peers:[peer(owner?'我的从机':'我的主机',owner)],pairing:null,settingsRevision:'fixture-settings'});
 return {...template,workspaceVersion:1,selectedNetworkId:guest,networks:[
  {id:host,name:'我创建的网络',status:network(true,'host-network')},
  ...removed?[]:[{id:guest,name:'我加入的网络',status:network(false,'guest-network')}]],
  aggregate:{networkCount:removed?1:2,connectedNetworks:paused?0:2,connectingNetworks:0,offlineNetworks:paused?2:0,totalDevices:2,sentBytes:0,receivedBytes:0,peers:[]}};
}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:1000}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/api/status*',async route=>{
  const response=await route.fetch(),body=await response.json();template??=structuredClone(body.status);
  body.status=fixture();await route.fulfill({response,json:body});
 });
 await page.route('**/api/command',async route=>{
  const body=route.request().postDataJSON();commands.push(body);
  if(body.method==='network'&&['disconnect','reconnect','leave'].includes(body.network?.action)){
   if(body.network.action==='leave')removed=true;else paused=body.network.action==='disconnect';
   await route.fulfill({json:{ok:true,error:'',status:fixture()}});return;
  }
  await route.continue();
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="join"]').click();
 const joined=page.locator(`[data-network-row="${guest}"]`);
 check(await joined.getByRole('button',{name:'断开连接',exact:true}).isEnabled(),'joined networks expose temporary disconnect instead of permanent exit');
 await joined.getByRole('button',{name:'断开连接',exact:true}).click();
 await joined.getByRole('button',{name:'重新连接',exact:true}).waitFor();
 check(commands.at(-1).network.action==='disconnect'&&commands.at(-1).networkId===guest&&commands.at(-1).network.expectedNetwork==='guest-network','disconnect targets the exact selected membership');
 check((await joined.innerText()).includes('已断开连接')&&!commands.some(c=>c.network?.action==='leave'),'disconnect keeps the network and never sends a leave action');
 await page.screenshot({path:path.join(out,'disconnected.png'),fullPage:true});
 await page.locator('.nav[data-page="create"]').click();
 check((await page.locator(`[data-network-row="${host}"]`).innerText()).includes('对机已断开连接'),'the host distinguishes a disconnected guest from an offline device');
 check(await page.locator(`[data-network-row="${host}"]`).getByRole('button',{name:'删除网络',exact:true}).isVisible(),'host deletion keeps its original name');
 await page.locator('.nav[data-page="join"]').click();
 await joined.getByRole('button',{name:'重新连接',exact:true}).click();
 await joined.getByRole('button',{name:'断开连接',exact:true}).waitFor();
 check(commands.at(-1).network.action==='reconnect'&&await joined.count()===1,'reconnect resumes the saved network without joining again');
 await page.locator('[data-ui-action="choose-exit"]').click();
 await page.locator('#exit-network-select').selectOption(guest);
 check(await page.locator('#exit-title').innerText()==='退出网络'&&await page.locator('#exit-confirm').innerText()==='确认退出网络','permanent exit retains the approved name in both title and confirmation');
 check((await page.locator('#exit-description').innerText()).includes('主机离线时自动重试通知')&&(await page.locator('#exit-description').innerText()).includes('断开连接'),'permanent-exit explanation distinguishes deletion, notification retry and temporary disconnect');
 await page.screenshot({path:path.join(out,'exit-confirmation.png'),fullPage:true});
 await page.locator('#exit-confirm').click();await joined.waitFor({state:'detached'});
 const leave=commands.find(c=>c.network?.action==='leave');
 check(leave?.networkId===guest&&leave.network.confirmReplace===true&&leave.network.expectedNetwork==='guest-network','only explicit exit requests permanent deletion of the selected guest network');
 check(await page.evaluate(()=>workspaceState.networks.length===1&&workspaceState.networks[0].id==='11111111111111111111111111111111'),'exiting a guest network preserves the independent host network');
 check(errors.length===0,'lifecycle rendering and polling have no browser exceptions');
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,scope:'real WebPanel and scripted network status; no installed service, NIC, NAT or streaming changes'},null,2));
 console.log(`PASS ${checks} browser lifecycle checks`);
}catch(error){console.error(error);process.exitCode=1;}
finally{await browser?.close();child.stdin.write('quit\n');const done=new Promise(resolve=>child.once('exit',resolve));await Promise.race([done,new Promise(resolve=>setTimeout(resolve,5000))]);if(child.exitCode===null)child.kill();}
})();
