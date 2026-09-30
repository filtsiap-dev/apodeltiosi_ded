import json, zipfile, io, sys
from lxml import etree
reqs=[json.loads(l) for l in open("docx.jsonl")]
a=[json.loads(l) for l in open("docx.py.out",encoding="utf-8").read().split("\n") if l]
b=[json.loads(l) for l in open("docx.java.out",encoding="utf-8").read().split("\n") if l]
def c14n(x):
    try: return etree.tostring(etree.fromstring(x), method="c14n")
    except Exception as e: return b"UNPARSEABLE:"+x
bad=0; outbad=0
for r,x,y in zip(reqs,a,b):
    if x!=y:
        bad+=1
        for k in x:
            if x.get(k)!=y.get(k): print(r["path"], "field", k, "\n  py:", str(x.get(k))[:300], "\n  jv:", str(y.get(k))[:300]); break
        continue
    if "error" in x: print(r["path"], "both ->", x["error"], "|", x["msg"]); continue
    zp=zipfile.ZipFile(r["path"].replace(".docx",".py.out.docx")); zj=zipfile.ZipFile(r["out"])
    ip=zp.infolist(); ij=zj.infolist()
    meta_p=[(i.filename,i.compress_type,i.date_time) for i in ip]; meta_j=[(i.filename,i.compress_type,i.date_time) for i in ij]
    if meta_p!=meta_j: outbad+=1; print(r["path"],"zip meta differ",meta_p,meta_j); continue
    for i in ip:
        dp=zp.read(i.filename); dj=zj.read(i.filename)
        if i.filename.endswith((".xml",".rels")):
            if c14n(dp)!=c14n(dj):
                outbad+=1; print(r["path"], i.filename, "C14N differ\n  py:", dp[:400], "\n  jv:", dj[:400]); break
        elif dp!=dj: outbad+=1; print(r["path"], i.filename, "bytes differ"); break
print("docs:",len(reqs),"parse/plan mismatches:",bad,"output mismatches:",outbad)
sys.exit(1 if (bad or outbad) else 0)
