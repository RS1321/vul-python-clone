"""Verify free-only Gemma access and preserve failures without credentials."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from review.runner import LLMClient, dump

results = []
for model in ('gemma-4-31b-it', 'gemma-4-26b-a4b-it'):
    try:
        client = LLMClient('gemini', model, max_tokens=2048)
        response = client.chat_completion([{'role':'user','content':'Reply with OK only. Do not reason.'}])
        record = {'model':model, 'status':'available', 'response':response}
    except Exception as exc:
        record = {'model':model, 'status':'unavailable', 'error':str(exc)}
    results.append(record)
    dump('review_results/model-access.json', results)
    print(model, record['status'], flush=True)
