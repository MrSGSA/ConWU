from pathlib import Path
import json
from urllib.parse import quote

root = Path(__file__).resolve().parent.parent
assets = root / 'src/StreamLink.Web/wwwroot'
output = root / 'artifacts/convergence-20261108/ConWU-预览.html'
config_id = '1' * 32
settings = dict(service='', certificatePin='', manualEndpoint='', pathSelection='faketcp-only', listenPort=44680,
                sourcePort=44691, connectionSource='existing', directMode=True,
                existingEntries=[dict(peerSlot=0, source='https://entry.example.com/current#streamlink1')],
                entryRefreshSeconds=60, requestedVirtualIp='', tcpStun=[], udpStun=[], coordinator=dict(enabled=False))
state = dict(version='1.1.0-preview.2', deviceName='家中主机', virtualIp='', state='后台运行中', serviceReady=True,
             networkEnabled=False, directPeers=0, totalPeers=0, peers=[], logLevel='info', workspaceVersion=2,
             settingsPatchVersion=2, settings=settings, deviceSettings=settings, settingsRevision='preview',
             deviceSettingsRevision='preview', selectedNetworkId='', networkId='', desktop=dict(autoStart=True, serviceRegistered=True),
             coordinator=dict(enabled=False, running=False, state='未提供协调服务'), logs=[], networks=[], configurations=[])
for index, (name, ip) in enumerate([('笔记本', '10.172.40.2'), ('另一台电脑', '10.172.41.2')], 2):
    network_id = str(index) * 32
    peer = dict(slot=2, name=name, deviceId=str(index + 2) * 32, virtualIp=ip, connected=index == 2,
                degraded=False, rttMs=18.4 if index == 2 else None, phase='已直连' if index == 2 else '设备未在线',
                connectedSince=1794103200, sentBytes=120000000, receivedBytes=3200000000,
                actualTransport='FakeTCPHttp', outerTarget='203.0.113.42:44680', entryDirection='Outbound')
    status = dict(state, networkId=str(index + 4) * 32, isOwner=True, networkEnabled=True, networkDirect=True,
                  virtualIp=ip[:-1] + '1', directPeers=int(peer['connected']), totalPeers=1, peers=[peer],
                  networkEstablishedAt=1794100000, networkCreatedHere=True)
    status.pop('networks'); status.pop('configurations')
    state['networks'].append(dict(id=network_id, name='主机—' + name, configurationId=config_id,
                                  appliedConfigurationRevision=1, status=status))
state['aggregate'] = dict(networkCount=2, connectedNetworks=1, connectingNetworks=1, offlineNetworks=0,
                          totalDevices=2, sentBytes=240000000, receivedBytes=6400000000, peers=[])
state['configurations'] = [dict(id=config_id, name='家中入口', revision=1, settings=settings,
                               networks=[dict(networkId=n['id'], name=n['name'], enabled=True, state='applied', error='') for n in state['networks']])]
mock = r'''
const previewState=PREVIEW_STATE;
document.querySelector('.footer span').textContent='ConWU 界面预览 · 示例数据';
window.fetch=async function(input,options={}){
 const uri=new URL(String(input),'https://preview.invalid'),body=options.body?JSON.parse(options.body):null;
 let reply={ok:true,status:structuredClone(previewState)};
 if(uri.pathname.endsWith('/api/session'))return new Response(JSON.stringify({csrf:'preview'}),{status:200});
 if(body){
  const action=body.configuration;
  if(body.method==='configuration'&&action){
   let c=previewState.configurations.find(c=>c.id===action.id);
   if(action.action==='save'||action.action==='copy'){
    if(!c||action.action==='copy'){c={id:crypto.randomUUID().replaceAll('-',''),name:action.name,revision:0,settings:action.settings||c.settings,networks:[]};previewState.configurations.push(c);}
    c.name=action.name;c.settings=action.settings||c.settings;c.revision++;reply.configurationId=c.id;
    for(const n of previewState.networks.filter(n=>n.configurationId===c.id)){n.status.settings=c.settings;n.appliedConfigurationRevision=c.revision;}
   }else if(action.action==='delete'&&!c.networks.length)previewState.configurations=previewState.configurations.filter(x=>x!==c);
  }else if(body.network?.action==='resolve-entries')previewState.entryResolutions=body.network.settings.existingEntries.map((s,index)=>({index,peerSlot:s.peerSlot,kind:'HTTPS',endpoints:['203.0.113.42:44680'],error:''}));
  else{reply.ok=false;reply.error='此文件用于界面预览，不执行真实网络操作。';}
  reply.status=structuredClone(previewState);reply.operation={id:body.operationId,completed:true,phase:reply.ok?'已完成':'界面预览',error:reply.error||''};
 }
 return new Response(JSON.stringify(reply),{status:200,headers:{'Content-Type':'application/json'}});
};
'''.replace('PREVIEW_STATE', json.dumps(state, ensure_ascii=False))
html = (assets / 'index.html').read_text(encoding='utf-8')
html = html.replace('<link rel="stylesheet" href="/style.css">', '<style>' + (assets / 'style.css').read_text(encoding='utf-8') + '</style>')
html = html.replace('<link rel="stylesheet" href="/experience.css">', '<style>' + (assets / 'experience.css').read_text(encoding='utf-8') + '</style>')
html = html.replace('href="/icon.svg"', 'href="data:image/svg+xml,' + quote((assets / 'icon.svg').read_text(encoding='utf-8')) + '"')
html = html.replace('<script src="/app.js" defer></script>', '<script>' + mock + '</script><script>' + (assets / 'app.js').read_text(encoding='utf-8') + '</script>')
html = html.replace('<script src="/workspace.js" defer></script>', '<script>' + (assets / 'workspace.js').read_text(encoding='utf-8') + '</script>')
html = html.replace('<script src="/experience.js" defer></script>', '<script>' + (assets / 'experience.js').read_text(encoding='utf-8') + '</script>')
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(html, encoding='utf-8')
print(output)
