"""Prevent local credentials from entering code-generation payloads."""
import json
import os
import re


PATTERN=r'AIza[0-9A-Za-z_-]{30,}|sk-(?:proj-|or-v1-)?[0-9A-Za-z_-]{30,}|AKIA[0-9A-Z]{16}'


def check_local_credentials(messages):
    text=json.dumps(messages,ensure_ascii=False)
    for name,value in os.environ.items():
        if len(value)>=12 and re.search(r'(api.?key|access.?key|secret|token|password|credential)',name,re.I):
            if value in text:
                raise RuntimeError(f'Gemini egress blocked: credential from {name} appears in the prompt')


def sanitise(text):
    check_local_credentials([{'content':text}])
    return re.sub(PATTERN,'REDACTED_BENCHMARK_CREDENTIAL',text)


def check_messages(messages):
    check_local_credentials(messages)
    if re.search(PATTERN,json.dumps(messages,ensure_ascii=False)):
        raise RuntimeError('Gemini egress blocked: API-key-shaped value in source evidence')
