"""Publication-style fixed-cohort figure; requires requirements-figures.lock."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from review.study_statistics import repeated_cluster_ci


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model',default='gemini-3.5-flash-lite')
    parser.add_argument('--out',type=Path,default=ROOT/'review_docs/figures')
    args = parser.parse_args()
    os.environ.setdefault('MPLCONFIGDIR',str(ROOT/'.review-work/matplotlib'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    primary = json.loads((ROOT/'review/study-protocol.json').read_text())['primary_implementation_sha256']
    data = []
    conditions = ['A','B','no_guidance','no_examples','C','simple','A_strict']
    labels = ['A','B','No guidance','No examples','C','Simple','A strict']
    fig,axes = plt.subplots(1,2,figsize=(11.4,4.6),sharey=True)
    for ax,dataset,title,baseline in zip(axes,['vampi','flask-webgoat'],['VAmPI','flask-webgoat'],[3,7]):
        candidates = {}
        for path in (ROOT/'review_results').glob('*/manifest.json'):
            m = json.loads(path.read_text())
            if (m.get('model') == args.model and m.get('status') == 'complete' and
                    m.get('implementation_sha256') == primary and m.get('condition') in conditions and
                    m.get('source_commit') == json.loads((ROOT/f'review_results/baseline-{dataset}/dataset-manifest.json').read_text())['source_commit']):
                key = (m['condition'],m['repetition'])
                candidates.setdefault(key,[]).append((path.parent.name,m))
        for i,condition in enumerate(conditions):
            selected = [(r,values[0]) for (c,r),values in candidates.items() if c == condition and len(values)==1]
            selected.sort()
            rates = [m['sast']['resolution_rate']*100 for r,(name,m) in selected]
            offsets = [-.12,0,.12] if len(rates)==3 else [0]*len(rates)
            ax.scatter([i+x for x in offsets],rates,color='#286c9b',s=25,zorder=3,alpha=.75)
            if rates:
                mean = sum(rates)/len(rates)
                interval = repeated_cluster_ci(rates)
                ax.errorbar(i,mean,yerr=[[max(0,mean-interval[0])],[max(0,interval[1]-mean)]] if interval else None,
                            fmt='_',color='#19262f',capsize=4,markersize=13,linewidth=1.5,zorder=4)
            for r,(name,m) in selected:
                data.append({'subject':dataset,'condition':condition,'repetition':r,'run':name,
                             'resolved':m['sast']['resolved_findings'],'baseline':baseline,'new_alerts':m['sast']['new_findings']})
        ax.set_title(title+f' ({baseline} baseline alerts)',fontsize=12)
        ax.set_xticks(range(7),labels,rotation=30,ha='right',fontsize=9)
        ax.set_ylim(-5,105);ax.set_yticks(range(0,101,20))
        ax.grid(axis='y',color='#d8dfe3',linewidth=.7)
        ax.spines[['top','right']].set_visible(False)
    axes[0].set_ylabel('Baseline SAST alerts resolved (%)')
    fig.suptitle(args.model+' — three repetitions per condition; code 12f7847',fontsize=13)
    fig.legend(handles=[Line2D([],[],marker='o',linestyle='',color='#286c9b',label='Individual repetitions'),
                        Line2D([],[],marker='_',linestyle='',color='#19262f',label='Mean and 95% repetition bootstrap interval')],
               loc='lower center',bbox_to_anchor=(.5,.045),ncol=2,frameon=False,fontsize=9)
    fig.text(.5,.015,'Fixed subjects; intervals do not generalize to other applications. VAmPI has no CWE-1333 guidance entry. SAST resolution is not joint security success.',ha='center',fontsize=7.5)
    fig.tight_layout(rect=(0,.14,1,.95))
    args.out.mkdir(parents=True,exist_ok=True)
    fig.savefig(args.out/'factorial-review2.png',dpi=300)
    fig.savefig(args.out/'factorial-review2.svg')
    (args.out/'factorial-review2-data.json').write_text(json.dumps(data,indent=2))
    print('Plotted',len(data),'completed, uniquely matched runs')


if __name__ == '__main__':
    main()
