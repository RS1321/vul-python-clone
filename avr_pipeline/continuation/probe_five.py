"""Probe a declared five-model free-tier cohort; never substitute models silently."""
import json, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'llm')]
from llm_client import LLMClient
from review.runner import dump
MODELS=['gemma-4-26b-a4b-it','gemma-4-31b-it','gemini-3.1-flash-lite','gemini-3.5-flash-lite','gemini-3.8-flash']
records=[]
for model in MODELS:
    start=time.monotonic()
    try:
        r=LLMClient('gemini',model,max_tokens=2048).chat_completion([{'role':'user','content':'Reply with OK only.'}])
        record={'requested_model':model,'status':'available','response':r}
    except Exception as exc:
        record={'requested_model':model,'status':'error','error':str(exc)}
    record['seconds']=round(time.monotonic()-start,2)
    records.append(record)
    dump(ROOT/'continuation/results/model-probes.json',records)
    print(model,record['status'],flush=True)
