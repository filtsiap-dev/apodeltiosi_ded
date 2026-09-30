import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, os, zipfile, io, dataclasses
sys.path.insert(0, REPO)
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import pin_python_order  # noqa: F401  (reproducible Python order)
from pathlib import Path
from lxml import etree
from docx_corpus import build
from pin_python_order import load_file_config
from anonymizer.docx_engine import parse_docx, write_redacted_docx
from anonymizer.detectors import detect_all
from anonymizer.resolver import resolve_redactions
from anonymizer.errors import AnonymizerError
cfg = load_file_config(Path(REPO) / "config")
os.makedirs("docx", exist_ok=True)
def unit_json(u): return [u.unit_id,u.part_name,u.unit_type,u.text,[[r.part_name,r.text_node_path,r.char_index] for r in u.char_map],u.location]
def run_py(path, out):
    data=open(path,"rb").read()
    try:
        doc=parse_docx(data, "doc")
        det=detect_all(doc, cfg.rules); plan=resolve_redactions(doc, det.resolver_spans, cfg.policy)
        red=write_redacted_docx(data, doc, plan); open(out,"wb").write(red)
        return {"units":[unit_json(u) for u in doc.text_units],"inventory":doc.parts_inventory,
                "plan":[[s.unit_id,s.start,s.end,s.text,s.category,s.action] for s in plan.spans]}
    except AnonymizerError as e:
        return {"error": type(e).__name__, "msg": str(e).split(":")[0]}
if __name__ == "__main__":
    n=int(sys.argv[1]); reqs=[]
    for i in range(n):
        kw=dict(damaged_header=(i%5==4), stored=(i%3==1), comments=(i%4!=3), custom=(i%2==0))
        p=f"docx/in{i}.docx"; open(p,"wb").write(build(i, **kw)); reqs.append(p)
    # invalid inputs
    good=build(999)
    bad = {"notzip": b"hello world", "empty": b"",
           "truncxml": None, "nobody": None, "styles_root": None, "missing": None, "badcrc": None}
    def rezip(repl=None, drop=None):
        zin=zipfile.ZipFile(io.BytesIO(good)); buf=io.BytesIO(); zout=zipfile.ZipFile(buf,"w")
        for info in zin.infolist():
            if info.filename==drop: continue
            d=zin.read(info.filename)
            if repl and info.filename in repl: d=repl[info.filename]
            zout.writestr(info, d)
        zout.close(); return buf.getvalue()
    W='xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    bad["truncxml"]=rezip({"word/document.xml": f'<w:document {W}><w:body><w:p>'.encode()})
    bad["nobody"]=rezip({"word/document.xml": f'<w:document {W}></w:document>'.encode()})
    bad["styles_root"]=rezip({"word/document.xml": f'<w:styles {W}/>'.encode()})
    bad["missing"]=rezip(drop="_rels/.rels")
    b=bytearray(rezip()); i=b.find(b"PNG fake"); b[i]^=0xFF  # stored? deflated -> corrupt data/CRC
    bad["badcrc"]=bytes(b)
    bad["emptybody"]=rezip({"word/document.xml": f'<w:document {W}><w:body/></w:document>'.encode()})
    for k,v in bad.items():
        p=f"docx/bad_{k}.docx"; open(p,"wb").write(v); reqs.append(p)
    with open("docx.jsonl","w") as f:
        for p in reqs: f.write(json.dumps({"op":"docx","path":p,"out":p.replace(".docx",".java.out.docx")})+"\n")
    with open("docx.py.out","w") as f:
        for p in reqs: f.write(json.dumps(run_py(p, p.replace(".docx",".py.out.docx")), ensure_ascii=False)+"\n")
