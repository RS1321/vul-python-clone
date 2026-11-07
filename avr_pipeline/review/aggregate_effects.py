"""Paired effects require completed matched conditions; absent cells stay null."""
import json
from pathlib import Path
from collections import defaultdict

out=Path(__file__).resolve().parents[1]/'review_results'
groups=defaultdict(dict)
for path in out.glob('*/manifest.json'):
    m=json.loads(path.read_text())
    if m.get('status')!='complete' or not m.get('sast') or m.get('selected_findings')!=m.get('eligible_findings'):
        continue
    identity=(m['source_commit'],m['model'],m.get('thinking_level','provider default'),m.get('repetition',1),
              m['sarif_sha256'],m['library_sha256'],m.get('max_tokens'),m.get('temperature'),m.get('zap_sha256'),
              m.get('context_profile','full'))
    # Duplicate runs are retained as ambiguous rather than silently choosing a preferred result.
    groups[identity].setdefault(m['condition'],[]).append((path.parent.name,m))
rows=[]
for identity,cells in groups.items():
    valid={k:v[0] for k,v in cells.items() if len(v)==1}
    required=('A','B','no_guidance','no_examples')
    row={'source_commit':identity[0],'model':identity[1],'thinking_level':identity[2],
         'repetition':identity[3], 'completed_conditions':list(valid),
         'missing_factorial_conditions':[k for k in required if k not in valid],
         'ambiguous_duplicate_conditions':[k for k,v in cells.items() if len(v)>1],
         'guidance_plus_examples_pp':None,'isolated_guidance_effect_pp':None,
         'guidance_given_examples_pp':None,'examples_given_guidance_pp':None,
         'isolated_example_effect_pp':None,'interaction_pp':None,'A_minus_C_security_pp':None}
    rate=lambda k:valid[k][1]['sast']['resolution_rate']
    if 'A' in valid and 'B' in valid:
        row['guidance_plus_examples_pp']=100*(rate('A')-rate('B'))
    if 'A' in valid and 'no_guidance' in valid:
        row['guidance_given_examples_pp']=100*(rate('A')-rate('no_guidance'))
    if 'A' in valid and 'no_examples' in valid:
        row['examples_given_guidance_pp']=100*(rate('A')-rate('no_examples'))
    if all(k in valid for k in required):
        row['isolated_guidance_effect_pp']=50*((rate('A')-rate('no_guidance'))+(rate('no_examples')-rate('B')))
        row['isolated_example_effect_pp']=50*((rate('A')-rate('no_examples'))+(rate('no_guidance')-rate('B')))
        row['interaction_pp']=100*(rate('A')-rate('no_guidance')-rate('no_examples')+rate('B'))
    if 'A' in valid and 'C' in valid:
        row['A_minus_C_security_pp']=100*(rate('A')-rate('C'))
    rows.append(row)
(out/'paired-effects.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
print('Wrote paired effects; missing comparisons remain null')
