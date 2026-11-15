// Real isolated WebPanel, scripted entry states; no production service changes.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.resolve(process.argv[2]||path.join(root,'artifacts/host-entry-next/browser'));
fs.mkdirSync(out,{recursive:true});
const child=spawn(path.join(root,'tests/ConWU.WebTests/bin/Release/net10.0-windows/ConWU.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/ConWU.Web/wwwroot'),'--pair-workspace'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
let browser,stderr='',template,attempt=0,checks=0;
child.stderr.on('data',chunk=>stderr+=chunk);
const lines=createInterface({input:child.stdout});
const link=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Fixture startup: '+stderr)),25000);lines.once('line',value=>{clearTimeout(timer);resolve(value);});});
child.stdin.write('open\n');
const id='d'.repeat(32),code='5JR0-E45A-840Y-4G12';
function check(value,name){if(!value)throw Error(name);checks++;console.log('PASS '+name);}
function fixture(){
 const entry=attempt>=2?{state:'Candidate',stage:'Candidate',detail:'已取得入口候选；尚未确认对端可以连接',attempt:3,elapsedMilliseconds:670,receiverReady:true,receiverError:''}
  :{state:'Unavailable',stage:'GatewayMapping',detail:'TCP STUN 已返回候选，但本层网关不支持自动映射',failureCode:'Unavailable',attempt:attempt+1,elapsedMilliseconds:7850,retryAt:Math.ceil(Date.now()/1000)+20,receiverReady:true,receiverError:''};
 const status={...template,isOwner:true,networkId:'fixture-network',networkEnabled:true,virtualIp:'10.90.1.1',directPeers:0,peers:[],entryPreparation:entry,
  settingsRevision:'fixture-settings',settings:{...template.settings,connectionSource:'custom',directMode:true,pathSelection:'faketcp-only'},
  pairing:attempt>=2?{active:true,format:'compact',code,expires:Math.ceil(Date.now()/1000)+300}:null};
 return {...template,workspaceVersion:1,selectedNetworkId:id,networks:[{id,name:'主机入口测试',status}],aggregate:{networkCount:1,connectedNetworks:0,connectingNetworks:1,offlineNetworks:0,totalDevices:1,sentBytes:0,receivedBytes:0,peers:[]}};
}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/api/status*',async route=>{
  const response=await route.fetch(),body=await response.json();template??=structuredClone(body.status);
  body.status=fixture();await route.fulfill({response,json:body});
 });
 await page.route('**/api/command',async route=>{
  const request=route.request().postDataJSON();
  if(request.method!=='network'||request.network?.action!=='invite-compact')return route.continue();
  check(request.networkId===id,'retry targets the selected host network');
  attempt++;
  return route.fulfill({json:{ok:attempt>=2,error:attempt<2?'主机入口准备失败：本层网关不支持自动映射；后台会自动重试':'',status:fixture()}});
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="create"]').click();
 await page.locator('[data-network-row="'+id+'"] [data-ui-action="select-host"]').last().click();
 const dialog=page.locator('#invitation-dialog');await dialog.waitFor({state:'visible'});
 await page.locator('#invitation-status').filter({hasText:'网关不支持自动映射'}).waitFor();
 check((await page.locator('#invitation-status').innerText()).includes('第 1 次')&&(await page.locator('#invitation-status').innerText()).includes('自动重试'),
  'invitation shows the actual failed stage, round and scheduled retry');
 check(await page.locator('#invitation-code').getAttribute('aria-label')==='尚未生成直连码'&&await page.locator('[data-ui-action="copy-pair"]').isDisabled(),
  'failed entry remains a placeholder and cannot be copied as an invitation');
 await page.locator('#invitation-generate').click();
 await page.locator('#invitation-error').filter({hasText:'网关不支持自动映射'}).waitFor();
 check(await dialog.isVisible(),'retry failure remains in the invitation dialog');
 await page.screenshot({path:path.join(out,'entry-unavailable.png')});
 await page.locator('#invitation-generate').click();
 await page.locator('#invitation-code').filter({hasText:'5JR0'}).waitFor();
 check((await page.locator('#invitation-code').innerText()).replace(/[-\s]/g,'')===code.replaceAll('-',''),
  'recovery displays the sixteen symbols once without duplicated grouping');
 check((await page.locator('#invitation-error').innerText())==='','successful retry clears the old dialog error');
 check((await page.locator('#invitation-status').innerText()).includes('尚未确认对端可以连接'),'a candidate is not displayed as confirmed Internet connectivity');
 await page.setViewportSize({width:800,height:700});
 check(await dialog.evaluate(element=>element.getBoundingClientRect().right<=innerWidth&&element.scrollWidth<=element.clientWidth+1),
  'entry diagnostics fit the compact dialog');
 check(errors.length===0,'no browser runtime errors');
 await page.screenshot({path:path.join(out,'entry-ready.png')});
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,productionServicesModified:false},null,2));
}catch(error){console.error(error);process.exitCode=1;}
finally{await browser?.close();child.stdin.write('close\n');child.kill();}})();
