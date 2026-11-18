from pathlib import Path
import argparse, platform, subprocess
import csv, math, statistics
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description="Regenerate the article's four tables and three figures from the eight recorded CSV files.")
parser.add_argument('--output',type=Path,default=ROOT/'results',help='Output directory (default: results/).')
args=parser.parse_args()
RESULTS=args.output.resolve()
RAW=ROOT/'data'
OUT=RESULTS/'tables'
FIG=RESULTS/'figures'
OUT.mkdir(parents=True,exist_ok=True)
FIG.mkdir(parents=True,exist_ok=True)
print(f"Python {platform.python_version()}; NumPy {np.__version__}; Matplotlib {matplotlib.__version__}; {platform.platform()}")
try:
    print('Artifact commit:',subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True,stderr=subprocess.DEVNULL).strip())
except (subprocess.CalledProcessError, FileNotFoundError):
    print('Artifact commit: uncommitted source or downloaded archive')
S=['auxiliary_vector','inverse_constraint','gk15_oom_kfold']
NAMES={S[0]:'Auxiliary-vector',S[1]:'Inverse',S[2]:r'GK15 ($k$-fold)'}
FILES={
 'main':{S[0]:['main/auxiliary_default.csv','main/auxiliary_main_k4.csv'],S[1]:['main/inverse_default.csv','main/inverse_main_k4.csv'],S[2]:['main/gk15.csv']},
 'common':{S[0]:['common/auxiliary.csv'],S[1]:['common/inverse.csv'],S[2]:['common/gk15.csv']}}
def quantile(v,p):
 v=sorted(v); h=(len(v)-1)*p; i=int(h)
 return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(h-i)
def size(s,N,k):
 n=N.bit_length()-1
 return (2*n+6)*33+10*32 if s==S[0] else ((2*n+5)*33+7*32 if s==S[1] else k*(4*n*33+(3*n+1)*32))
stats={}; total=0; sourcefiles=set()
for campaign,arms in FILES.items():
 for scheme,files in arms.items():
  groups=defaultdict(list)
  for rel in files:
   p=RAW/rel; sourcefiles.add(rel)
   rows=list(csv.DictReader(p.open(encoding='utf-8-sig',newline='')))
   for r in rows:
    assert r['scheme']==scheme
    for c in ['ring_size','k','iteration','paper_size_bytes','implementation_size_bytes']: r[c]=int(r[c])
    for c in ['prove_ms','verify_ms']: r[c]=float(r[c]); assert r[c]>0 and math.isfinite(r[c])
    assert size(scheme,r['ring_size'],r['k'])==r['paper_size_bytes']
    r['source_csv']='data/'+rel
    groups[(r['ring_size'],r['k'])].append(r)
   total+=len(rows)
  expected={(x,4) for x in [16,32,64,128]} if campaign=='common' else {(x,y) for x in [128,256,512,1024] for y in [4,16]} | {(1024,y) for y in [1,2,8]}
  assert set(groups)==expected
  for (N,k),rs in groups.items():
   assert len(rs)==30 and sorted(r['iteration'] for r in rs)==list(range(30))
   assert len({r['paper_size_bytes'] for r in rs})==1
   assert len({r['implementation_size_bytes'] for r in rs})==1
   d=dict(campaign=campaign,scheme=scheme,ring_size=N,k=k,samples=30,paper_size_bytes=rs[0]['paper_size_bytes'],implementation_size_bytes=rs[0]['implementation_size_bytes'],source_csv=sorted({r['source_csv'] for r in rs}))
   for m in ['prove_ms','verify_ms']:
    vals=[r[m] for r in rs]
    d[m+'_median']=statistics.median(vals); d[m+'_q1']=quantile(vals,.25);d[m+'_q3']=quantile(vals,.75); d[m+'_iqr']=d[m+'_q3']-d[m+'_q1']
   stats[(campaign,scheme,N,k)]=d
assert total==1350 and len(stats)==45
def row(c,s,N,k):return stats[(c,s,N,k)]
sets={
 'valid_parameters':[row('common',s,N,4) for N in [16,32,64,128] for s in S],
 'large_ring':[row('main',s,N,4) for N in [128,256,512,1024] for s in S[1:]],
 'signer_count':[row('main',s,1024,k) for k in [1,2,4,8,16] for s in S[1:]]}
def csvwrite(p,rows):
 with p.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
for name,rs in sets.items(): csvwrite(RESULTS/(name+'.csv'),rs)
ablation=[]
for N in [128,256,512,1024]:
 a=row('main',S[0],N,16);b=row('main',S[1],N,16)
 ablation.append(dict(ring_size=N,k=16,prove_speedup=a['prove_ms_median']/b['prove_ms_median'],verify_speedup=a['verify_ms_median']/b['verify_ms_median'],auxiliary_format_bytes=a['paper_size_bytes'],inverse_format_bytes=b['paper_size_bytes'],auxiliary_protocol_domain_valid=N<=128))
csvwrite(RESULTS/'implementation_comparison.csv',ablation)
csvwrite(RESULTS/'all_statistics.csv',list(stats.values()))
# Export compact table fragments from raw medians, including the IQRs.
labels={'valid_parameters':'tab:revised-common-domain','large_ring':'tab:evaluation-large-ring','signer_count':'tab:evaluation-signer-count'}
captions={
 'valid_parameters':r'Proof performance comparison at $k=4$ and $N\in\{16,32,64,128\}$. Times are medians (IQR) in milliseconds over 30 measurements per entry. Format sizes follow the stated element counts.',
 'large_ring':r'Effect of ring size on proof performance at $k=4$. Times are medians (IQR) in milliseconds over 30 measurements per entry. Format sizes exclude the message, ring and public parameters.',
 'signer_count':r'Effect of signer count on proof performance at $N=1024$. Times are medians (IQR) in milliseconds over 30 measurements per entry. The inverse format has constant size across these signer counts.'}
printed_checks=[]
for name,rs in sets.items():
 xname='$k$' if name=='signer_count' else '$N$'
 text=[r'\begin{table}[htbp]',r'\centering',r'\caption{'+captions[name]+'}',r'\label{'+labels[name]+'}',r'\small',r'\setlength{\tabcolsep}{4pt}',r'\begin{tabular}{r l r r r}',r'\toprule',xname+r' & Implementation & \shortstack{Generation\\ms (IQR)} & \shortstack{Verification\\ms (IQR)} & \shortstack{Format\\bytes} \\',r'\midrule']
 for i,d in enumerate(rs):
  if i and rs[i-1]['ring_size' if name!='signer_count' else 'k']!=d['ring_size' if name!='signer_count' else 'k']:text.append(r'\addlinespace')
  p=f"{d['prove_ms_median']:.3f}";v=f"{d['verify_ms_median']:.3f}"
  pi=f"{d['prove_ms_iqr']:.3f}";vi=f"{d['verify_ms_iqr']:.3f}"
  printed_checks.append(dict(table=name,scheme=d['scheme'],N=d['ring_size'],k=d['k'],generation=p,verification=v,generation_iqr=pi,verification_iqr=vi,format_bytes=d['paper_size_bytes']))
  x=d['k'] if name=='signer_count' else d['ring_size']
  text.append(f"{x} & {NAMES[d['scheme']]} & {p} ({pi}) & {v} ({vi}) & {d['paper_size_bytes']} "+r'\\')
 text +=[r'\bottomrule',r'\end{tabular}',r'\end{table}']
 (OUT/(name+'.tex')).write_text('\n'.join(text)+'\n',encoding='utf-8')
text = [
    r'\begin{table}[htbp]',
    r'\centering',
    r'\caption{Comparison of nonemptiness constraints at $k=16$. Time ratios divide the auxiliary-vector median by the inverse median for each local proof operation. Format sizes are calculated from element counts.}',
    r'\label{tab:evaluation-encoding}',
    r'\small',
    r'\begin{tabular}{r r r r r}',
    r'\toprule',
    r'$N$ & \shortstack{Generation\\time ratio} & \shortstack{Verification\\time ratio} & \shortstack{Auxiliary\\format bytes} & \shortstack{Inverse\\format bytes} \\',
    r'\midrule',
]
for d in ablation:
 p=f"{d['prove_speedup']:.2f}";v=f"{d['verify_speedup']:.2f}"
 ring_size = d['ring_size']
 domain_mark = r'$^\dagger$' if ring_size >= 256 else ''
 text.append(
     rf"{ring_size}{domain_mark} & {p}$\times$ & {v}$\times$ & "
     rf"{d['auxiliary_format_bytes']} & {d['inverse_format_bytes']} \\"
 )
 printed_checks.append(dict(table='implementation_comparison',**d,printed_prove_speedup=p,printed_verify_speedup=v))
text +=[r'\bottomrule',r'\end{tabular}',r'\par\smallskip',r'\begin{minipage}{0.92\linewidth}\footnotesize $^\dagger$~The auxiliary relation requires $2^N-1<q$. Marked rows fall outside this domain and report computational costs for the length-$2N$ encoding.\end{minipage}',r'\end{table}']
(OUT/'implementation_comparison.tex').write_text('\n'.join(text)+'\n',encoding='utf-8')
# Vector publication figures: timing panels show Q1--Q3, all axes start at zero.
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':11,'axes.labelsize':11,'axes.titlesize':10.5,'xtick.labelsize':10,'ytick.labelsize':10,'legend.fontsize':10.5,'pdf.fonttype':42,'ps.fonttype':42})
colors={S[0]:'#0072B2',S[1]:'#D55E00',S[2]:'#009E73'}
markers={S[0]:'s',S[1]:'o',S[2]:'^'}
for name,rs in sets.items():
 schemes=S if name=='valid_parameters' else S[1:]
 xs=[1,2,4,8,16] if name=='signer_count' else ([16,32,64,128] if name=='valid_parameters' else [128,256,512,1024])
 fig,axes=plt.subplots(1,3,figsize=(7.15,3.2))
 fig.subplots_adjust(top=.78,bottom=.20,left=.085,right=.99,wspace=.65)
 for ax,metric,title,ylabel in zip(axes,['prove_ms','verify_ms','paper_size_bytes'],['(a) Proof generation','(b) Proof verification','(c) Public evidence'],['Time (ms)','Time (ms)','Format size (bytes)']):
  for s in schemes:
   ds=[d for d in rs if d['scheme']==s]
   y=[d[metric+'_median'] if metric!='paper_size_bytes' else d[metric] for d in ds]
   label=NAMES[s]
   if metric!='paper_size_bytes':
    err=np.array([[m-d[metric+'_q1'] for m,d in zip(y,ds)],[d[metric+'_q3']-m for m,d in zip(y,ds)]])
    ax.errorbar(range(len(xs)),y,yerr=err,label=label,color=colors[s],marker=markers[s],markersize=4,linewidth=1.3,elinewidth=.8,capsize=2)
   else:ax.plot(range(len(xs)),y,label=label,color=colors[s],marker=markers[s],markersize=4,linewidth=1.3)
  ax.set_title(title,pad=7);ax.set_xlabel('Signer count $k$' if name=='signer_count' else 'Ring size $N$');ax.set_ylabel(ylabel)
  ax.set_xticks(range(len(xs)),xs);ax.set_ylim(bottom=0);ax.grid(axis='y',alpha=.25,linewidth=.6);ax.set_axisbelow(True)
  ax.spines[['top','right']].set_visible(False);ax.ticklabel_format(style='plain',axis='y',useOffset=False)
 handles,ls=axes[0].get_legend_handles_labels();fig.legend(handles,ls,loc='upper center',bbox_to_anchor=(.53,1),ncol=len(schemes),frameon=False)
 basename={'valid_parameters':'secure_protocol_comparison','large_ring':'large_ring_scalability','signer_count':'k_sensitivity_large_ring'}[name]
 for ext in ['pdf','png']:fig.savefig(FIG/(basename+'.'+ext),dpi=300,bbox_inches='tight')
 plt.close(fig)
# Check every published table row against the manuscript's frozen outputs.
checked_rows=0
checked_fields=0
for name in [*sets, 'implementation_comparison']:
    expected=list(csv.DictReader((ROOT/'expected'/(name+'.csv')).open(newline='',encoding='utf-8-sig')))
    actual=list(csv.DictReader((RESULTS/(name+'.csv')).open(newline='',encoding='utf-8-sig')))
    assert len(expected)==len(actual),(name,'row count')
    for index,(left,right) in enumerate(zip(expected,actual)):
        assert left.keys()==right.keys(),(name,'columns')
        for key,value in left.items():
            # Path metadata reflects the public package layout; numeric fields
            # and scheme identities must agree with the manuscript outputs.
            if key=='source_csv':
                continue
            try:
                a,b=float(value),float(right[key])
            except ValueError:
                assert value==right[key],(name,index,key,value,right[key])
            else:
                assert math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-10),(name,index,key,a,b)
            checked_fields+=1
        checked_rows+=1
    assert (OUT/(name+'.tex')).read_text()==(ROOT/'expected/tables'/(name+'.tex')).read_text(),(name,'LaTeX differs')
assert checked_rows==34
common_aux=row('common',S[0],128,4)
common_inv=row('common',S[1],128,4)
print(f"PASS: {len(sourcefiles)} raw CSVs; {total} observations; {len(stats)} groups; {checked_rows} table rows; {checked_fields} fields.")
print('PASS: all four LaTeX tables match the manuscript, including captions.')
print(f"N=128,k=4 auxiliary/inverse median ratios: generation {common_aux['prove_ms_median']/common_inv['prove_ms_median']:.8f}; verification {common_aux['verify_ms_median']/common_inv['verify_ms_median']:.8f}.")
print(f"Tables, statistics and three figures written to {RESULTS}")
