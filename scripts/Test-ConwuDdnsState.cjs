// Exercises production UI state functions without building/running a backend.
// DOM/transport are fixtures; real browser + IPC regression is separate.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const nodes=new Map(),storage=new Map();
const element=()=>({addEventListener(){},dataset:{},classList:{add(){},remove(){},toggle(){}},textContent:''});
const context=vm.createContext({URL,console,setTimeout(){},clearTimeout(){},setInterval(){},
 document:{getElementById(id){if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);},addEventListener(){},documentElement:{dataset:{}}},
 window:{addEventListener(){}},localStorage:{getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v)},
 check:(condition,message)=>assert.ok(condition,message)});
const source=fs.readFileSync(path.join(__dirname,'../src/StreamLink.Web/wwwroot/app.js'),'utf8');
assert.match(source,/\bboot\(\);\s*$/);
vm.runInContext(source.replace(/\bboot\(\);\s*$/,''),context);
vm.runInContext(`
(async()=>{
 render=()=>{};notice=()=>{};notify=()=>{};
 state={deviceName:'Fixture',networkEnabled:false,settingsRevision:'initial',desktop:{autoStart:true},settings:{service:'https://coord.example.test/',ddns:clone(defaults.ddns)}};
 saved=configFromStatus(state);drafts=clone(saved);baseRevision=state.settingsRevision;
 let writes=[];
 command=async(method,payload)=>{const a=payload.network;writes.push(clone(a));state.settings=a.settings;state.ddnsCredentialConfigured=a.clearDdnsToken?false:!!a.ddnsToken||state.ddnsCredentialConfigured;state.settingsRevision='saved';};
 const token='fixture-token-0123456789-secret';
 drafts.ddns.domain='conwu.example.test';drafts.ddns.newToken=token;section='logging';
 check(dirtyCount()===1,'DDNS contributes to global dirty state');
 check(!JSON.stringify(settingsDto()).includes(token),'ordinary settings payload excludes credentials');
 await saveSection();
 check(writes.length===1&&writes[0].ddnsToken===token,'global save uses a separate credential patch');
 check(!JSON.stringify(writes[0].settings).includes(token),'settings object contains no credential');
 check(drafts.ddns.newToken===''&&saved.ddns.newToken===''&&!JSON.stringify(history).includes(token),'success clears draft and undo history credentials');
 check(dirtyCount()===0,'successful global save has no stale dirty state');
 drafts.ddns.enabled=true;drafts.ddns.publish=true;drafts.ddns.zoneId='a'.repeat(32);
 check(!validateSection('ddns'),'saved credentials can be reused with an empty token input');
 drafts.ddns.clearToken=true;check(!validateSection('ddns'),'explicit clear automatically changes publishing into discovery-only mode');
 drafts.ddns.publish=false;await saveSection();check(writes[1].clearDdnsToken&&!writes[1].ddnsToken,'explicit clear is separate from settings');
 const baseline=JSON.stringify(saved.ddns);drafts.ddns.newToken=token;restoreSettings();
 check(JSON.stringify(drafts.ddns)===baseline,'revert discards an unsaved credential without a write');
 drafts.ddns.domain='draft.example.test';drafts.ddns.newToken=token;
 command=async()=>{throw Error('controlled save failure');};
 try{await saveSection();throw Error('failure was not propagated');}catch(e){check(e.message==='controlled save failure','save failure preserved');}
 check(drafts.ddns.newToken===token&&drafts.ddns.domain==='draft.example.test','failed save retains editable draft for retry');
 check(saved.ddns.newToken===''&&!JSON.stringify(history).includes(token),'failed save does not copy credentials into persisted history');
 drafts.ddns.clearToken=true;check(!!validateSection('ddns'),'clear and replace cannot be requested together');
 state.ddns={thirdPartyRecordName:'e-device.n-network.conwu.example.test'};saved.ddns.domain=drafts.ddns.domain='conwu.example.test';drafts.network.mode='existing';
 check(thirdPartyDnsFields().includes('e-device.n-network.conwu.example.test')&&thirdPartyDnsFields().includes('streamlink='),'existing mode displays its generated third-party TXT record and shared format');
 check(!thirdPartyDnsFields().includes(token),'third-party instructions never contain the API token');
 drafts.ddns.domain='unsaved.example.test';check(!thirdPartyDnsFields().includes('e-device.n-network.conwu.example.test'),'an unsaved domain does not offer an obsolete record name');
 drafts.network.mode='custom';check(!thirdPartyDnsFields().includes('copy-thirdparty-record')&&thirdPartyDnsFields().includes('自行获取'),'autonomous mode has no third-party update task');
 return true;
})()
`,context).then(()=>{
 assert.ok(!JSON.stringify([...storage]).includes('fixture-token-0123456789-secret'),'browser storage excludes credentials');
 console.log('PASS ConWU DDNS UI state regression (fixture only; no backend or network)');
}).catch(e=>{console.error(e);process.exitCode=1;});
