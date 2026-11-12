#!/usr/bin/env python3
"""Render the observed A09 HTTP request/session mapping as a vector figure."""
import argparse
import hashlib
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results', type=Path, required=True)
    p.add_argument('--audit', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    raw = args.results.read_bytes()
    record, audit = json.loads(raw), json.loads(args.audit.read_bytes())
    assert audit['record_sha256'] == hashlib.sha256(raw).hexdigest()
    assert record['status'] == 'collected' and audit['status'] == 'audited'
    case = next(c for c in audit['cases'] if c['id'] == 'A09')
    rows = case['requests']
    assert len(rows) == 6 and all(r['classification'] == 'admitted_conforming' for r in rows)
    assert [r['path'] for r in rows] == ['/compat', '/restricted'] * 3
    ports = list(dict.fromkeys(r['local_port'] for r in rows))
    assert len(ports) == 2 and all(r['front_group'] == 'X25519MLKEM768' for r in rows)
    sessions = [s for s in audit['sessions'] if s['case_id'] == 'A09']
    assert len(sessions) == 2 and all(len(s['request_ids']) == 3 and set(s['local_ports']) == set(ports) for s in sessions)
    assert {s['origin']: s['group'] for s in sessions} == {'legacy': 'X25519', 'restricted': 'X25519MLKEM768'}
    assert all(r['connection_id'] == next(s['connection_id'] for s in sessions if s['origin'] == r['origin']) for r in rows)
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 9, 'pdf.fonttype': 42})
    fig, ax = plt.subplots(figsize=(7.2, 2.9))
    ax.set(xlim=(0, 10), ylim=(0, 4)); ax.axis('off')
    blue, orange, teal = '#235b87', '#9c570e', '#226f70'
    def box(x, y, width, height, text, color):
        patch = FancyBboxPatch((x,y), width,height,boxstyle='square,pad=0.04',linewidth=1.1,edgecolor=color,facecolor='#f4f6f7')
        ax.add_patch(patch);ax.text(x+width/2,y+height/2,text,ha='center',va='center',color=color,fontsize=9)
    def arrow(a,b,color):
        ax.annotate('',xy=b,xytext=a,arrowprops={'arrowstyle':'-|>','lw':1,'color':color})
    box(.1,2.85,2.2,.7,'Frontend F1\n4 HTTP requests; H',blue)
    box(.1,1.85,2.2,.7,'Frontend F2\n2 HTTP requests; H',blue)
    box(3.25,2.02,2.7,1.3,'Unmodified HAProxy\nRoute-specific policy\nSeparate backend pools',orange)
    box(7.25,2.85,2.55,.7,'Legacy origin\nConnection L1; C',teal)
    box(7.25,1.85,2.55,.7,'Restricted origin\nConnection S1; H',blue)
    arrow((2.35,3.15),(3.2,2.95),blue);arrow((2.35,2.2),(3.2,2.45),blue)
    arrow((6,2.95),(7.2,3.15),teal);arrow((6,2.45),(7.2,2.2),blue)
    ax.text(6.55,3.48,'D = none',ha='center',fontsize=8,color=teal)
    ax.text(6.57,1.72,'D = F,B',ha='center',fontsize=8,color=blue)
    ax.text(.1,3.9,'Observed request-to-connection mapping in A09',weight='bold',fontsize=10)
    cells=[]
    for i,r in enumerate(rows):
        front='F'+str(ports.index(r['local_port'])+1)
        backend='L1' if r['origin']=='legacy' else 'S1'
        cells.append([str(i+1),r['path'],front+' / '+backend])
    table=ax.table(cellText=list(map(list,zip(*cells))),rowLabels=['Request','Route','Front / back'],cellLoc='center',rowLoc='right',bbox=[.11,.17,.88,.25])
    table.auto_set_font_size(False);table.set_fontsize(8)
    for cell in table.get_celld().values():cell.set_linewidth(.4);cell.set_edgecolor('#b7bec5')
    ax.text(5,.02,'Each backend TLS connection carries three requests across F1 and F2. No TLS resumption.',ha='center',va='bottom',fontsize=8)
    fig.subplots_adjust(left=.02,right=.99,top=.98,bottom=.03)
    args.out.mkdir(parents=True,exist_ok=False)
    target=args.out/'http_admission.pdf'
    fig.savefig(target,metadata={'CreationDate':None,'ModDate':None,'Creator':'build_http_figure.py; retained native HTTP evidence'})
    plt.close(fig)
    manifest={'results_sha256':hashlib.sha256(raw).hexdigest(),'audit_sha256':hashlib.sha256(args.audit.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'matplotlib':matplotlib.__version__,'output_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'case':'A09','front_local_ports':ports,'backend_sessions':sessions,'scope':'Observed sequential request mapping; connections are not users; no timing or performance axis.'}
    (args.out/'http_figure_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    table = [r"\begin{table}[t]\centering\small",
             r"\caption{HTTP admission outcomes per 72-request execution. Each policy receives 24 requests. Violations are a subset of admissions. Excessive refusals reject admissible requests; ineligible refusals concern requests unable to meet the declared minimum in that condition.}",
             r"\label{tab:http}", r"\begin{tabular}{@{}lrrrr@{}}\toprule",
             r"Policy & Admit & Viol. & Excess & Inelig. \\ \midrule"]
    for key, label in [('support_only', 'Support only'), ('blanket_hybrid', 'Blanket H'), ('route_aware', 'Per route')]:
        counts = audit['by_policy'][key]
        assert counts['requests'] == 24 and counts['expectation_mismatches'] == 0
        table.append(label+' & '+' & '.join(str(counts[k]) for k in ['admitted','violations','overblocked','rejected_unavailable'])+r" \\")
    table += [r"\bottomrule\end{tabular}", r"\end{table}"]
    (args.out/'application_results.tex').write_text('\n'.join(table)+'\n')
    print(json.dumps({'figure':str(target),'case':'A09','requests':6,'backend_connections':2},indent=2))


if __name__ == '__main__':
    main()
