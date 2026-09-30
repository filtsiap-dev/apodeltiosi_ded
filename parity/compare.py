import json, sys
from collections import Counter
req=[json.loads(l) for l in open(sys.argv[1], encoding="utf-8").read().split("\n") if l]
a=[l for l in open(sys.argv[2], encoding="utf-8").read().split("\n") if l]
b=[l for l in open(sys.argv[3], encoding="utf-8").read().split("\n") if l]
print("requests",len(req),"py",len(a),"java",len(b))
bad=[(r,x,y) for r,x,y in zip(req,a,b) if x!=y]
print("mismatches:",len(bad), dict(Counter(r["op"] for r,_,_ in bad)))
for r,x,y in bad[:int(sys.argv[4]) if len(sys.argv)>4 else 6]:
    print(json.dumps(r,ensure_ascii=False)[:300],"\n  py:",x[:300],"\n  jv:",y[:300])
