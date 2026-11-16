"""Local CPU comparison, not a throughput or latency claim for actual networks."""
import json, statistics, subprocess
from pathlib import Path
root=Path(__file__).resolve().parent.parent
oracle=root/'rust/compat/ConWU.DotnetOracle/bin/Release/net10.0/ConWU.DotnetOracle.dll'
rust=root/'out/rust-target/release/examples/bench_link.exe'
process=subprocess.Popen(['dotnet',str(oracle)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,encoding='utf-8')
def managed(count):
    process.stdin.write(json.dumps({'op':'benchmark','count':count})+'\n');process.stdin.flush()
    answer=json.loads(process.stdout.readline());assert answer['ok'],answer
    return answer['result']
try:
    managed(100000)
    trials={'rust':[],'dotnet':[]}
    for _ in range(5):
        trials['rust'].append(json.loads(subprocess.check_output([str(rust),'500000'],text=True,encoding='utf-8')))
        trials['dotnet'].append(managed(500000))
    result={'scope':'Windows x64, release builds, 1280 byte payload; AES-GCM link encode + decode only, excluding network, drivers, queues and GUI','trials':trials,
        'medianMbps':{name:round(statistics.median(t['mbps'] for t in values),2) for name,values in trials.items()}}
    result['ratio']=round(result['medianMbps']['rust']/result['medianMbps']['dotnet'],2)
    (root/'out/benchmark-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='trials'}))
finally:
    process.stdin.close()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.terminate();process.wait()
