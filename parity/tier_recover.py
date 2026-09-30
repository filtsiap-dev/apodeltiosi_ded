import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, random, zipfile, io, os
sys.path.insert(0, REPO)
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import pin_python_order  # noqa: F401  (reproducible Python order)
from docx_corpus import build
from tier_docx import run_py
os.makedirs("docx", exist_ok=True)
def mutate(xml, rnd):
    k = rnd.randrange(7); n = len(xml)
    if k == 0: return xml[: rnd.randrange(n // 3, n)], "truncate"
    if k == 1:
        idx = [i for i, c in enumerate(xml) if c == ">"]; i = rnd.choice(idx[3:]); return xml[:i] + xml[i+1:], "drop>"
    if k == 2: i = rnd.randrange(n // 2, n); return xml[:i] + "<" + xml[i:], "stray<"
    if k == 3: return xml.replace("</w:t>", "</w:x>", 1), "mismatch"
    if k == 4: i = xml.find("<w:t"); j = xml.find(">", i) + 1; return xml[:j] + "&bogus;" + xml[j:], "entity"
    if k == 5: i = xml.find("<w:t"); j = xml.find(">", i) + 1; return xml[:j] + "A & B" + xml[j:], "amp"
    return xml.replace("</w:r>", "", 2), "unclosed"
rnd = random.Random(7); reqs = []; kinds = []
for i in range(400):
    base = build(5000 + i)
    zin = zipfile.ZipFile(io.BytesIO(base)); buf = io.BytesIO(); zout = zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED)
    for info in zin.infolist():
        d = zin.read(info.filename)
        if info.filename == "word/header1.xml":
            m, kind = mutate(d.decode("utf-8"), rnd); d = m.encode("utf-8"); kinds.append(kind)
        zout.writestr(info, d)
    zout.close(); p = f"docx/rec{i}.docx"; open(p, "wb").write(buf.getvalue()); reqs.append(p)
with open("rec.jsonl", "w") as f:
    for p in reqs: f.write(json.dumps({"op": "docx", "path": p, "out": p.replace(".docx", ".java.out.docx")}) + "\n")
with open("rec.py.out", "w") as f:
    for p in reqs: f.write(json.dumps(run_py(p, p.replace(".docx", ".py.out.docx")), ensure_ascii=False) + "\n")
json.dump(kinds, open("rec.kinds.json", "w"))
