import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, random
sys.path.insert(0, REPO)
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import pin_python_order  # noqa: F401  (reproducible Python order)
from pathlib import Path
from corpus import document, TABLE_HEADERS, cell
from anonymizer.models import TextUnit, DocumentData
from pin_python_order import load_file_config
from anonymizer.detectors import detect_all
from anonymizer.resolver import resolve_redactions
from anonymizer.summary import build_summary
import dataclasses
cfg = load_file_config(Path(REPO) / "config")
def make_doc(seed):
    units=[]; n=0
    random.seed(seed*7+1)
    hdr = random.choice(TABLE_HEADERS)
    for r in range(3):
        for c,h in enumerate(hdr):
            units.append(dict(unit_id=f"u{n}", part_name="word/document.xml", unit_type="table_cell",
                text=(h if r==0 else cell(h)), location=dict(table_index=0,row_index=r,col_index=c,column_header=("" if r==0 else h),is_header_row=r==0))); n+=1
    for p in document(seed):
        units.append(dict(unit_id=f"u{n}", part_name="word/document.xml", unit_type="paragraph", text=p, location=dict(paragraph_index=n))); n+=1
    return {"document_id": f"d{seed}", "units": units}
def to_doc(d):
    return DocumentData(document_id=d["document_id"], text_units=[TextUnit(unit_id=u["unit_id"], part_name=u["part_name"], unit_type=u["unit_type"], text=u["text"], normalized_text=u["text"], char_map=[], location=u["location"]) for u in d["units"]], parts_inventory=[])
def sd(s): return [s.unit_id,s.start,s.end,s.text,s.category,s.detector,s.confidence,s.action,s.reason]
if __name__ == "__main__":
    reqs=[make_doc(i) for i in range(int(sys.argv[1]))]
    with open("detect.jsonl","w") as f:
        for d in reqs: f.write(json.dumps({"op":"detect","doc":d}, ensure_ascii=False)+"\n")
    with open("detect.py.out","w") as f:
        for d in reqs:
            doc=to_doc(d); det=detect_all(doc, cfg.rules)
            plan=resolve_redactions(doc, det.resolver_spans, cfg.policy)
            K=lambda r: json.dumps(r, ensure_ascii=False)
            out={"resolver":sorted(map(sd,det.resolver_spans),key=K),"review":sorted(map(sd,det.review_hints),key=K),
                 "resolver_order":[sd(s)[:3]+[sd(s)[5]] for s in det.resolver_spans],
                 "plan":[sd(s) for s in plan.spans],"warnings":plan.warnings,"summary":dataclasses.asdict(build_summary(plan))}
            f.write(json.dumps(out, ensure_ascii=False)+"\n")
