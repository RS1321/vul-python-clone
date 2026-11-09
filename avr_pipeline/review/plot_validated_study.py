"""Export static scientific figures from the corrected, derived study tables."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    os.environ.setdefault('MPLCONFIGDIR',str(ROOT/'.review-work/matplotlib'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap, BoundaryNorm
    from matplotlib.lines import Line2D

    plt.rcParams.update({'font.size':9, 'pdf.fonttype':42, 'svg.fonttype':'none',
                         'axes.spines.top':False, 'axes.spines.right':False})
    source = ROOT/'review_results/validated-analysis/summary-by-condition.json'
    rows = json.loads(source.read_text(encoding='utf-8'))
    status_path = ROOT/'review_results/validated-analysis/study-status-snapshot.json'
    status = json.loads(status_path.read_text(encoding='utf-8'))
    out = ROOT/'review_docs/figures/validated'
    out.mkdir(parents=True,exist_ok=True)
    models = list(dict.fromkeys(row['model'] for row in rows))
    subjects = [('synthetic','Synthetic',29),('pygoat','PyGoat',62),
                ('vampi','VAmPI',3),('flask-webgoat','flask-webgoat',7)]
    conditions = ['A','B','no_guidance','no_examples','C','simple','A_strict']
    labels = ['A','B','No guidance','No examples','C','Simple','A strict']
    index = {(row['model'],row['dataset'],row['condition']):row for row in rows}
    complete = status['completed_cells'] == status['planned_cells']
    heading = 'Completed study' if complete else f"Interim: {status['completed_cells']}/{status['planned_cells']} cells"
    short = lambda model:model.replace('qwen2.5-coder-','Qwen2.5 Coder ').replace('-instruct-q4km',' Q4_K_M').replace('gemma-4-26b-a4b-it','Gemma 4 26B A4B')
    save = lambda figure,stem:[figure.savefig(out/(stem+'.'+extension),dpi=220) for extension in ('png','svg')]
    for model in models:
        fig, axes = plt.subplots(2,2,figsize=(10.4,7.7),sharey=True)
        for ax,(dataset,title,baseline) in zip(axes.flat,subjects):
            n = sum(index[(model,dataset,c)]['repetitions'] for c in conditions)
            for x,condition in enumerate(conditions):
                row = index[(model,dataset,condition)]
                if row['mean_resolution_rate'] is not None:
                    mean = row['mean_resolution_rate']*100
                    interval = row['resolution_repetition_ci95']
                    err = [[max(0,mean-interval[0]*100)],[max(0,interval[1]*100-mean)]] if interval else None
                    ax.errorbar(x-.10,mean,yerr=err,fmt='o',color='#21618c',markersize=4,capsize=3,linewidth=1.1)
                    if row['joint_unknown_findings']==0:
                        ax.plot(x+.10,row['mean_joint_rate']*100,'D',color='#a64b00',markersize=3.5)
                    ax.text(x,105,str(row['repetitions']),ha='center',va='bottom',fontsize=8,color='#4a4a4a')
            ax.set_title(f'{title}: {baseline} baseline alerts; {n}/21 cells')
            ax.set_xticks(range(7),labels,rotation=25,ha='right')
            ax.set_ylim(-5,115);ax.set_yticks([0,25,50,75,100])
            ax.set_xlim(-.5,6.5)
            ax.grid(axis='y',color='#dddddd',linewidth=.6)
            ax.set_axisbelow(True)
        for ax in axes[:,0]:
            ax.set_ylabel('Baseline findings (%)')
        fig.suptitle(short(model)+' — '+heading,fontsize=13)
        fig.legend(handles=[Line2D([],[],marker='o',color='#21618c',linestyle='',label='Mean SAST resolution; 95% repetition interval'),
                            Line2D([],[],marker='D',color='#a64b00',linestyle='',label='Joint success; only fully observed rows')],
                   loc='lower center',bbox_to_anchor=(.5,.061),ncol=2,frameon=False,fontsize=8)
        fig.text(.5,.024,'Numbers above groups show completed repetitions (maximum 3). Intervals withheld below 3; fixed subjects only.\n'
                 'VAmPI has no CWE-1333 library entry. Missing rows are blank. SAST alert removal does not establish safe behavior.',ha='center',fontsize=8)
        fig.tight_layout(rect=(0,.13,1,.96))
        save(fig,model);plt.close(fig)
    matrix = [[index[(model,dataset,c)]['repetitions'] for c in conditions] for model in models for dataset,title,n in subjects]
    fig,ax = plt.subplots(figsize=(9.8,8.3))
    cmap = ListedColormap(['#eeeeee','#cde2ed','#76b3c4','#1b6f72'])
    ax.imshow(matrix,cmap=cmap,norm=BoundaryNorm([-.5,.5,1.5,2.5,3.5],4),aspect='auto')
    ax.set_xticks(range(7),labels,rotation=20,ha='right')
    ax.set_yticks(range(len(matrix)),[short(model)+' / '+title for model in models for d,title,n in subjects],fontsize=8)
    for y,row in enumerate(matrix):
        for x,value in enumerate(row):
            ax.text(x,y,str(value),ha='center',va='center',color='white' if value==3 else '#1b2933')
    for y in [3.5,7.5,11.5,15.5]:ax.axhline(y,color='white',linewidth=3)
    ax.set_title(heading+' — completed repetitions per condition',pad=12)
    fig.tight_layout();save(fig,'coverage');plt.close(fig)
    provenance = {'generated_from':str(source.relative_to(ROOT)), 'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                  'status_sha256':hashlib.sha256(status_path.read_bytes()).hexdigest(), 'snapshot_utc':status['generated_utc'],
                  'plotter_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'rows':rows,
                  'interpretation':'Fixed-subject descriptive repetition intervals; incomplete rows explicit. No independent-finding or architecture-generalization claim.'}
    (out/'plotted-data.json').write_text(json.dumps(provenance,indent=2),encoding='utf-8')
    print('Exported five model figures and coverage in PNG and SVG')


if __name__ == '__main__':
    main()
