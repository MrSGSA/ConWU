module.exports=async({page,check})=>{
 for(const pending of [false,true]){
 await page.waitForFunction(()=>!busy&&!pairPolling&&!reading);
 const fresh=await page.evaluate(()=>clone(state));let release,captured,progressSeen,held=false,id='';
 const gate=new Promise(resolve=>release=resolve),ready=new Promise(resolve=>captured=resolve),progressReady=new Promise(resolve=>progressSeen=resolve);
 const delayed=async route=>{
  const response=await route.fetch(),body=await response.json();
  if(!held){held=true;captured();await gate;body.status={...body.status,deviceName:'obsolete backend snapshot',networkId:''};}
  return route.fulfill({response,json:body});
 };
 const complete=async route=>{
  const body=route.request().postDataJSON();
  if(body?.method!=='network'||body.network?.action!=='pair-poll'||!body.network?.background)return route.fallback();
  id=body.operationId;
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,...(pending?{}:{status:fresh}),operation:{id,completed:!pending,error:''}})});
 };
 const progress=async route=>{if(new URL(route.request().url()).searchParams.get('operation')!==id)return route.fallback();progressSeen();return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,status:fresh,operation:{id,completed:false,phase:'fixture pairing progress',error:''}})});};
 await page.route('**/api/status',delayed);await page.route('**/api/command',complete);
 await page.route('**/api/status?operation=*',progress);
 let timer;
 try{
  await page.evaluate(()=>{void refresh();});
  await Promise.race([ready,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('old status query was not captured')),8000))]);clearTimeout(timer);
  await page.evaluate(()=>{window.orderGeneration=generation;window.olderStatus=reading;state.pairing={active:true,direct:false,expires:Math.floor(Date.now()/1000)+120};lastPairPoll=0;window.newPairStatus=pollPair();});
  if(pending){await progressReady;await page.waitForFunction(()=>generation>window.orderGeneration);}else await page.evaluate(()=>window.newPairStatus);
  release();await page.evaluate(()=>window.olderStatus);
  check(await page.evaluate(expected=>state.networkId===expected.networkId&&state.deviceName===expected.deviceName&&!busy,fresh)&&await page.locator('.nav[data-action=leave]').isEnabled(),'an older ordinary status response cannot overwrite newer pairing '+(pending?'progress':'completion')+' or disable exit');
  if(pending){await page.evaluate(()=>command('patch',{patch:{deviceName:state.deviceName,expectedDeviceName:state.deviceName}}));await page.evaluate(()=>window.newPairStatus);}
 }finally{clearTimeout(timer);release();await page.unroute('**/api/status',delayed);await page.unroute('**/api/command',complete);await page.unroute('**/api/status?operation=*',progress);}
 }
};
