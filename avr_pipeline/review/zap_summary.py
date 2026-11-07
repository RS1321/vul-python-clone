"""ZAP summaries keep unique endpoint/parameter alerts distinct from instances."""
import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl


def groups(path):
    sites=json.loads(Path(path).read_text(encoding='utf-8')).get('site',[])
    if isinstance(sites,dict): sites=[sites]
    keys=set()
    for site in sites:
        for alert in site.get('alerts',[]):
            for instance in alert.get('instances') or [{}]:
                url=urlsplit(instance.get('uri',''))
                keys.add((str(alert.get('pluginid',alert.get('alertRef',''))),str(alert.get('cweid','')),
                          instance.get('method',''),url.path,tuple(sorted(k for k,v in parse_qsl(url.query))),instance.get('param','')))
    return keys


def compare(before,after):
    a,b=groups(before),groups(after)
    return {'baseline_unique_alert_groups':len(a),'remaining_baseline_groups':len(a & b),
            'resolved_groups':len(a-b),'new_groups':len(b-a),
            'matching':'plugin id, CWE, method, path, query parameter names, alert parameter; payload values excluded'}


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('before');parser.add_argument('after',nargs='?')
    args=parser.parse_args()
    print(json.dumps(compare(args.before,args.after) if args.after else {'unique_alert_groups':len(groups(args.before))},indent=2))
