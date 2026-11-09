"""Preserve acknowledged replies and refinement state across transport outages."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from review.validation_health import ValidatorInfrastructureError


class ContinuationIntegrityError(ValidatorInfrastructureError):
    pass


def record_digest(record):
    return hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')).hexdigest()


def carried_attempts(interrupted, history_file):
    result = []
    for index, attempt in enumerate(interrupted.get('attempts', [])):
        if attempt.get('response') is None:
            continue
        saved = deepcopy(attempt)
        if 'continued_generation' not in saved:
            saved['continued_generation'] = dict(history_file=history_file,index=index,record_sha256=record_digest(attempt))
        result.append(saved)
    return result


def verify_generation_reference(run, attempt):
    reference = attempt.get('continued_generation')
    if not isinstance(reference,dict) or not re.fullmatch(r'interrupted-finding-[0-9]+-[0-9]+\.json',reference.get('history_file','')):
        raise ContinuationIntegrityError('Invalid continued-generation reference')
    path = Path(run)/reference['history_file']
    if not path.is_file():
        raise ContinuationIntegrityError('Missing original generation evidence')
    records = json.loads(path.read_text(encoding='utf-8')).get('attempts', [])
    index = reference.get('index')
    if not isinstance(index,int) or not 0 <= index < len(records):
        raise ContinuationIntegrityError('Invalid original generation index')
    original = records[index]
    candidate = {key:value for key,value in attempt.items() if key!='continued_generation'}
    if (original.get('continued_generation') or original.get('response') is None or
            record_digest(original)!=reference.get('record_sha256') or candidate!=original):
        raise ContinuationIntegrityError('Continued reply differs from its original immutable evidence')
    return original


def refinement_after(attempt, previous, parse_response):
    if attempt.get('accepted') or attempt.get('infrastructure_error'):
        raise ContinuationIntegrityError('Only rejected, acknowledged replies may be carried forward')
    failure = attempt.get('generation_failure')
    if failure == 'output_token_limit':
        return '', 'The reply exhausted its output limit. Return a shorter complete patch within the same limit.'
    if failure == 'malformed_or_blocked_output':
        return '', 'The generation did not contain the required complete patch. Use the specified patch format.'
    if failure:
        raise ContinuationIntegrityError('Unknown recorded generation outcome')
    try:
        previous = parse_response(attempt['response']['content'])['fixed_code']
    except Exception:
        if not attempt.get('error'):
            raise ContinuationIntegrityError('Recorded reply cannot reconstruct its refinement state') from None
    if 'validation' in attempt:
        return previous, json.dumps(attempt['validation'],ensure_ascii=False)
    if attempt.get('error'):
        return previous, attempt['error']
    raise ContinuationIntegrityError('Missing recorded rejection feedback')


def restore_refinement(attempts, builder, prompt, finding, cap, parse_response):
    if len(attempts) >= cap:
        raise ContinuationIntegrityError('No generation allowance remains for the interrupted finding')
    previous, feedback = '', ''
    for number, attempt in enumerate(attempts,1):
        expected = prompt if number==1 else builder.build_refinement_prompt(prompt,previous,feedback,finding,number,cap)
        if attempt.get('attempt')!=number or attempt.get('prompt')!=expected or attempt.get('response') is None:
            raise ContinuationIntegrityError('Recorded attempts or prompts differ from the unchanged continuation state')
        previous, feedback = refinement_after(attempt,previous,parse_response)
    return previous, feedback


def compatible_resume(prior, current, provider, protocol_path):
    if prior==current:
        return True
    if not protocol_path:
        return False
    protocol = json.loads(Path(protocol_path).read_text(encoding='utf-8'))
    if protocol.get('primary_implementation_sha256')!=current:
        return False
    variants = protocol.get('transport_only_compatible_implementations', [])+protocol.get('continuation_only_compatible_implementations', [])
    return any(v['implementation_sha256']==prior and (not v.get('providers') or provider in v['providers']) for v in variants)
