// A real isolated WebPanel with deterministic two-network replies. Never opens
// a production adapter or invokes the installed service.
const {chromium}=require('../out/browser-tools/node_modules/playwright');
const {spawn}=require('node:child_process'),{createInterface}=require('node:readline');
const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..'),out=path.join(root,'artifacts/mobile-pair-fix/invitation-browser');
fs.mkdirSync(out,{recursive:true});
const fixture=spawn(path.join(root,'tests/StreamLink.WebTests/bin/Release/net10.0-windows/StreamLink.WebTests.exe'),
 ['--browser-fixture',path.join(root,'src/StreamLink.Web/wwwroot'),'--pair-workspace'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','pipe']});
const lines=createInterface({input:fixture.stdout});let stderr='',browser,checks=0;
fixture.stderr.on('data',value=>stderr+=value);
const link=new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('Fixture timeout '+stderr)),25000);lines.once('line',line=>{clearTimeout(timer);resolve(line);});});fixture.stdin.write('open\n');
const A='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',B='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',C='cccccccccccccccccccccccccccccccc';
const codes=new Map([[A,'AAAA-BBBB-CCCC-DDDD'],[B,'EEEE-FFFF-GGGG-HHHH']]),pending=new Map(),requests=[];
let template,complete=false,observe=false,failGeneration=false,created=false,createdName='';const configurations=[];
const passiveOperations=new Set();
function check(ok,label){if(!ok)throw Error(label);checks++;console.log('PASS '+label);}
function snapshot(selected=''){
 const networks=[A,B,...(created?[C]:[])].map((id,index)=>({id,name:index===2?createdName:index?'网络乙':'网络甲',configurationId:id===C?C:'',status:{...template,
  networkId:id,networkEnabled:true,isOwner:true,virtualIp:`10.200.${index}.1`,peers:[],directPeers:0,
  settings:{...template.settings,pathSelection:'https-only',connectionSource:'custom'},
  pairing:{active:true,owner:!(observe&&id===A),direct:true,format:'compact',method:'direct',code:codes.get(id)||'',expires:Math.floor(Date.now()/1000)+300,candidate:'',verification:'',state:'等待设备申请'}}}));
 return {...template,...networks.find(n=>n.id===selected)?.status,workspaceVersion:2,selectedNetworkId:selected,networks,configurations,deviceSettings:template.settings};
}
(async()=>{try{
 browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];
 page.on('pageerror',error=>errors.push(error.message));
 await page.route('**/api/status*',async route=>{
  const response=await route.fetch(),body=await response.json();template??=body.status;
  const query=new URL(route.request().url()).searchParams,operation=query.get('operation'),selected=query.get('networkId')||'';
  body.status=snapshot(selected);
  if(operation&&pending.has(operation)){
   const expected=pending.get(operation);requests.push({kind:'poll',expected,actual:selected,passive:passiveOperations.has(operation)});
   if(expected!==selected)return route.fulfill({status:200,json:{ok:false,error:'操作 ID 已绑定另一条网络'}});
   if(complete){if(expected)codes.set(expected,expected===A?'2222-3333-4444-5555':'6666-7777-8888-9999');body.status=snapshot(selected);}
   body.operation={id:operation,command:'invite-compact',phase:'生成直连码',completed:complete,cancelable:!complete,error:''};
  }
  await route.fulfill({response,json:body});
 });
 await page.route('**/api/command',async route=>{
  const command=route.request().postDataJSON();requests.push({kind:'command',command});
  if(command.method==='configuration'){
   configurations.push({id:C,name:command.configuration.name,revision:1,settings:command.configuration.settings,networks:[]});
   return route.fulfill({status:200,json:{ok:true,status:snapshot(''),configurationId:C}});
  }
  if(command.network?.action==='create-direct'){
   created=true;createdName=command.network.name;configurations[0].networks.push({networkId:C,name:createdName,enabled:true,state:'applied'});
   return route.fulfill({status:200,json:{ok:true,status:snapshot(C)}});
  }
  if(!['invite-compact','pair-poll'].includes(command.network?.action)&&!(command.method==='save-settings'&&command.networkId===''))throw Error('Unexpected mutation in invitation test');
  if(command.network?.action==='invite-compact'&&failGeneration){failGeneration=false;return route.fulfill({status:200,json:{ok:false,error:'直连码生成错误测试'}});}
  if(command.network?.action==='pair-poll')passiveOperations.add(command.operationId);
  pending.set(command.operationId,command.networkId);
  await route.fulfill({status:200,json:{ok:true,status:snapshot(command.networkId),operation:{id:command.operationId,command:'invite-compact',phase:'准备入口',completed:false,cancelable:true,error:''}}});
 });
 await page.goto(await link);await page.locator('#backend-state').filter({hasText:'后台运行中'}).waitFor();
 await page.locator('.nav[data-page="create"]').click();
 const choose=async id=>{if(await page.locator('#invitation-dialog').isVisible())await page.locator('[data-ui-action="close-invitation"]').click();await page.locator(`[data-network-row="${id}"] .btn[data-ui-action="select-host"]`).click();await page.locator('#invitation-dialog').waitFor({state:'visible'});};
 const code=()=>page.locator('#invitation-code').getAttribute('aria-label');
 await page.locator('#new-network-name').fill('保留的新网络草稿');
 const originalInput=await page.locator('#new-network-name').elementHandle();
 await choose(A);check((await code()).includes(codes.get(A)),'the older network opens its own direct-code dialog');
 check(await page.locator('#invitation-title').innerText()==='网络甲'&&await page.locator('#new-network-name').inputValue()==='保留的新网络草稿','the dialog names its network and preserves the creation form');
 check(await originalInput.evaluate(e=>e===document.getElementById('new-network-name')),'opening a code does not replace the creation input');
 check(await page.locator('#open-network-settings').getAttribute('data-network')==='','viewing an existing code never redirects new-network settings');
 await choose(B);check((await code()).includes(codes.get(B)),'selecting a different network displays its own code');
 await choose(A);
 // Reproduce the previously split selection: the last-created workspace ID
 // differs from the network shown in the create panel.
 await page.evaluate(id=>selectedNetwork=id,B);
 await page.locator('[data-ui-action="generate"]').click();
 await page.waitForFunction(()=>busy);await choose(B);
 check((await code()).includes(codes.get(B)),'another network can be viewed while code generation is pending');
 complete=true;await page.waitForFunction(()=>!busy);
 check(requests.some(r=>r.kind==='poll'&&r.expected===A&&r.actual===A)&&requests.every(r=>r.kind!=='poll'||r.expected===r.actual),'all asynchronous progress requests retain the submitted network ID');
 check((await code()).includes(codes.get(B)),'a late generation reply cannot replace the newly selected network code');
 await choose(A);check((await code()).includes('2222-3333-4444-5555'),'the generated code is retained on its original network');
 await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async value=>window.lastInvitationCopy=value}}));
 await page.locator('[data-ui-action="copy-pair"]').click();
 check(await page.evaluate(()=>window.lastInvitationCopy==='2222-3333-4444-5555'),'copy uses the selected network with exactly one set of separators');
 failGeneration=true;await page.locator('#invitation-generate').click();await page.locator('#invitation-error').filter({hasText:'直连码生成错误测试'}).waitFor();
 check(!await page.locator('#notice').evaluate(e=>!e.hidden&&e.classList.contains('error')),'generation failures are visible inside the code dialog');
 check(await page.locator('#new-network-name').inputValue()==='保留的新网络草稿','generating and switching codes retain the new-network draft');
 await page.locator('[data-ui-action="close-invitation"]').click();
 await page.evaluate(()=>command('save-settings',{networkId:'',settingsBatch:{device:{action:'settings',settings:workspaceState.deviceSettings,confirmReplace:true},networks:[]}},true));
 check(requests.some(r=>r.kind==='poll'&&r.expected===''&&r.actual===''),'device-wide progress omits the empty network selector and does not inherit the selected network');
 observe=true;
 const observed=page.waitForResponse(response=>passiveOperations.has(new URL(response.url()).searchParams.get('operation')));
 await page.evaluate(async id=>{selectedNetwork=id;lastPairPoll=0;await refresh();await pollPair();},B);await observed;
 check(requests.some(r=>r.passive&&r.expected===A&&r.actual===A),'passive pairing progress stays on its pending network while a different network is selected');
 check(errors.length===0&&!await page.locator('#notice').innerText().then(text=>text.includes('绑定另一条网络')),'no cross-network operation error or browser exception');
 observe=false;
 await page.locator('#new-network-name').fill('第三条新网络');await page.locator('#create-network').click();await page.locator('#invitation-dialog').waitFor({state:'visible'});
 check(await page.locator('#invitation-title').innerText()==='第三条新网络','successful creation opens the new network in its code dialog');
 check(await page.locator('#new-network-name').inputValue()===''&&await page.locator('#create-form').count()===1,'creation keeps a fresh form ready for the next independent network');
 await page.locator('[data-ui-action="close-invitation"]').click();await page.locator('#open-network-settings').click();
 check(await page.locator('#network-dialog-title').innerText()==='新网络设置'&&await page.evaluate(()=>selectedConfiguration)==='','new settings remain independent of the network that just opened its code');
 await page.locator('[data-ui-action="close-editor"]').first().click();await choose(C);
 await page.screenshot({path:path.join(out,'network-selection.png'),fullPage:true});
 fs.writeFileSync(path.join(out,'result.json'),JSON.stringify({status:'Pass',checks,productionServicesModified:false},null,2));
}finally{await browser?.close();lines.close();fixture.stdin.end('quit\n');await new Promise(resolve=>{const timer=setTimeout(()=>{fixture.kill();resolve();},5000);fixture.once('exit',()=>{clearTimeout(timer);resolve();});});}})().catch(error=>{console.error(error);process.exitCode=1;});
