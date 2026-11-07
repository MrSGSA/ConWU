// Production UI against actual WebPanel/IPC. Delayed HTTP observations are
// controlled here; service-side read preemption has its own real-worker test.
module.exports=async({page,nav,check})=>{
 const original=await page.evaluate(()=>clone(state)),originalPage=await page.evaluate(()=>page);let pollId='',release;
 const held=new Promise(resolve=>release=resolve);
 const isPoll=route=>{const body=route.request().postDataJSON();return body?.method==='network'&&body.network?.action==='pair-poll'&&body.network?.background;};
 const late=async route=>{if(!isPoll(route))return route.fallback();pollId=route.request().postDataJSON().operationId;await held;await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,operation:{id:pollId,completed:true,error:''},status:{...original,deviceName:'stale automatic reply',networkId:''}})});};
 await page.route('**/api/command',late);
 const start=()=>page.evaluate(()=>{state.pairing={active:true,direct:false,expires:Math.floor(Date.now()/1000)+120};lastPairPoll=0;window.controlPoll=pollPair();});
 try{
  await nav('create');await start();await page.waitForFunction(()=>!!pairPolling);
  check(await page.evaluate(()=>!busy)&&await page.locator('.nav[data-action=leave]').isEnabled()&&await page.locator('[data-action=delete]').isEnabled(),'slow automatic pairing discovery leaves exit and delete controls enabled');
  await page.locator('.nav[data-action=leave]').click();await page.locator('#confirm-dialog').waitFor({state:'visible'});await page.locator('#dialog-cancel').click();
  check(await page.locator('.nav[data-action=leave]').isEnabled(),'exit confirmation can be opened and canceled while pairing discovery is pending');
  await page.evaluate(()=>command('patch',{patch:{deviceName:state.deviceName,expectedDeviceName:state.deviceName}}));
  release();await page.evaluate(()=>window.controlPoll);
  check(await page.evaluate(()=>!busy&&!pairPolling&&state.networkId.length>0&&state.deviceName!=='stale automatic reply'),'late background reply cannot undo a foreground operation or disable network controls');
 }finally{release();await page.unroute('**/api/command',late);}

 let retryId='',seenProgress=false;
 const accept=async route=>{if(!isPoll(route))return route.fallback();retryId=route.request().postDataJSON().operationId;return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,operation:{id:retryId,completed:false,phase:'fixture slow read'}})});};
 const failProgress=async route=>{if(new URL(route.request().url()).searchParams.get('operation')!==retryId)return route.fallback();seenProgress=true;return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'fixture background progress timeout'})});};
 await page.route('**/api/command',accept);await page.route('**/api/status?operation=*',failProgress);
 try{
  await start();await page.waitForFunction(()=>!!pairPolling);
  const until=Date.now()+5000;while(!seenProgress&&Date.now()<until)await page.waitForTimeout(20);
  check(seenProgress&&await page.locator('.nav[data-action=leave]').isEnabled()&&await page.evaluate(()=>!busy),'retrying a failed automatic progress query does not lock foreground controls');
  await page.evaluate(()=>command('patch',{patch:{deviceName:state.deviceName,expectedDeviceName:state.deviceName}}));
  await page.evaluate(()=>window.controlPoll);
  check(await page.evaluate(()=>!busy&&!pairPolling)&&await page.locator('.nav[data-action=leave]').isEnabled(),'foreground completion releases an obsolete background retry without a page reload');
 }finally{await page.unroute('**/api/command',accept);await page.unroute('**/api/status?operation=*',failProgress);}
 await nav(originalPage);
};
