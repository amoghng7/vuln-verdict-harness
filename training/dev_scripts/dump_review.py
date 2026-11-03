import json,re,sys
sys.path.insert(0,'/workspace/vuln-verdict-data/dev/scripts')
from collect import alerts, ROOT
MDECL=re.compile(r'^\s*(public|private|protected|static|\s)*[\w<>\[\],\s]+\s+(\w+)\s*\([^;]*$')
for i,(rp,r,_) in enumerate(alerts()):
    L=open(ROOT+rp+'/'+r['path'],errors='replace').read().split('\n'); ln=r['start']['line']
    s=ln-1
    while s>0 and not (MDECL.match(L[s]) and not re.match(r'\s*(if|for|while|switch|catch|return|new|else)\b',L[s])): s-=1
    e=ln-1; depth=0; started=False
    for j in range(s,len(L)):
        depth+=L[j].count('{')-L[j].count('}')
        if '{' in L[j]: started=True
        if started and depth<=0: e=j;break
    a=max(s-3,0); b=min(max(e,ln+3)+1,len(L))
    if b-a>80: a=max(a,ln-45); b=min(b,ln+25)
    print(f"=== #{i} [{rp}] {r['check_id'].split('.')[-1]} {r['path']}:{ln}-{r['end']['line']}")
    for k in range(a,b): print(f"{'>' if r['start']['line']<=k+1<=r['end']['line'] else ' '}{k+1:4}|{L[k]}")
