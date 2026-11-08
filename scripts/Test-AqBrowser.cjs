// Exercise the current multi-network UI. Historical single-network/DDNS
// selectors in Test-AqSimplifiedBrowser no longer describe the product.
const {spawnSync}=require('node:child_process'),path=require('node:path');
const output=path.resolve(process.argv[2]||path.join(__dirname,'../artifacts/current-browser'));
for(const [script,envName,folder] of [['Test-ConvergedBrowser.cjs','CONWU_BROWSER_OUTPUT','live'],['Test-ConvergedUiStates.cjs','CONWU_UI_STATES_OUTPUT','slow-api']]){
 const result=spawnSync(process.execPath,[path.join(__dirname,script)],{stdio:'inherit',windowsHide:true,env:{...process.env,[envName]:path.join(output,folder)}});
 if(result.error)throw result.error;
 if(result.status!==0)process.exit(result.status||1);
}
