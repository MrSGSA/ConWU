module.exports=async({page,check})=>{
 await page.waitForFunction(()=>!busy&&!pairPolling&&!reading);
 const fresh=await page.evaluate(()=>clone(state));let release,captured,held=false;
 const gate=new Promise(resolve=>release=resolve),ready=new Promise(resolve=>captured=resolve);
 const delayed=async route=>{
  const response=await route.fetch(),body=await response.json();
  if(!held){held=true;captured();await gate;body.status={...body.status,deviceName:'obsolete backend snapshot',networkId:''};}
  return route.fulfill({response,json:body});
 };
 const complete=async route=>{
  const body=route.request().postDataJSON();
  if(body?.method!=='network'||body.network?.action!=='pair-poll'||!body.network?.background)return route.fallback();
  return route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,status:fresh,operation:{id:body.operationId,completed:true,error:''}})});
 };
 await page.route('**/api/status',delayed);await page.route('**/api/command',complete);
 let timer;
 try{
  await page.evaluate(()=>{void refresh();});
  await Promise.race([ready,new Promise((_,reject)=>timer=setTimeout(()=>reject(Error('old status query was not captured')),8000))]);clearTimeout(timer);
  await page.evaluate(()=>{window.olderStatus=reading;state.pairing={active:true,direct:false,expires:Math.floor(Date.now()/1000)+120};lastPairPoll=0;window.newPairStatus=pollPair();});
  await page.evaluate(()=>window.newPairStatus);release();await page.evaluate(()=>window.olderStatus);
  check(await page.evaluate(expected=>state.networkId===expected.networkId&&state.deviceName===expected.deviceName&&!busy&&!pairPolling,fresh)&&await page.locator('.nav[data-action=leave]').isEnabled(),'an older ordinary status response cannot overwrite a newer pairing result or disable exit');
 }finally{clearTimeout(timer);release();await page.unroute('**/api/status',delayed);await page.unroute('**/api/command',complete);}
};
