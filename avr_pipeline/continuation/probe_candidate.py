import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'llm'))
from llm_client import LLMClient

parser = argparse.ArgumentParser()
parser.add_argument('--model', choices=['gemini-2.5-flash-lite', 'gemini-3.6-flash'], required=True)
args = parser.parse_args()
started = time.monotonic()
try:
    result = LLMClient('gemini', args.model, max_tokens=2048).chat_completion([
        {'role': 'user', 'content': 'Return only a Python function called add that adds its two integer arguments.'}])
except Exception as exc:
    result = {'error': str(exc)}
result['seconds'] = round(time.monotonic() - started, 2)
(ROOT / 'continuation/results' / (args.model + '-probe.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
print(result.get('model', result.get('error')))
