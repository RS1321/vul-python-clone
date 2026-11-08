"""Launch the pinned CPU model invisibly on loopback, never on the LAN."""
import json,os,subprocess,sys,time
from pathlib import Path
import requests
PROJECT=Path(__file__).resolve().parents[1]
ROOT=Path(os.getenv('AVR_TOOL_ROOT',str(PROJECT)))
small='--small' in sys.argv
folder=ROOT/('.review-work/local-qwen05' if small else '.review-work/local-qwen')
binary='llama-server.exe' if os.name=='nt' else 'llama-server'
executables=list((ROOT/'.review-work/local-qwen/runtime').rglob(binary))
if len(executables)!=1: raise RuntimeError('Verified local runtime missing')
model='qwen2.5-coder-0.5b-instruct-q4km' if small else 'qwen2.5-coder-1.5b-instruct-q4km'
port=18081 if small else 18080
args=[str(executables[0]),'--model',str(folder/'model.gguf'),'--host','127.0.0.1',
      '--port',str(port),'--alias',model,'--threads','4','--ctx-size','16384',
      '--parallel','1','--n-gpu-layers','0','--batch-size','512']
with (folder/'server.log').open('w',encoding='utf-8') as log:
 process=subprocess.Popen(args,cwd=folder,stdout=log,stderr=subprocess.STDOUT,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
(folder/'server-pid.json').write_text(json.dumps({'pid':process.pid,'model':model,'args':args}),encoding='utf-8')
session=requests.Session();session.trust_env=False
for _ in range(60):
 if process.poll() is not None: raise RuntimeError('Local model startup failed; inspect server.log')
 try:
  response=session.get(f'http://127.0.0.1:{port}/health',timeout=1)
  if response.status_code==200: break
 except requests.RequestException:pass
 time.sleep(1)
else:raise RuntimeError('Local model did not become ready')
sys.path.insert(0,str(PROJECT/'llm'))
from llm_client import LLMClient
r=LLMClient('local',model,max_tokens=128).chat_completion([{'role':'user','content':'Reply with OK only.'}])
(PROJECT/('continuation/results/local-qwen05-probe.json' if small else 'continuation/results/local-model-probe.json')).write_text(json.dumps(r,indent=2),encoding='utf-8')
print('Verified local model ready:',model)
if '--serve' in sys.argv:
 print('Keeping the local inference process attached to this session.',flush=True)
 try:
  process.wait()
 finally:
  if process.poll() is None:process.terminate()
