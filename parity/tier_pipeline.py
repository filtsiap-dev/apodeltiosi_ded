import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, os, zipfile, io, dataclasses, logging
sys.path.insert(0, REPO)
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import pin_python_order  # noqa: F401  (reproducible Python order)
from pathlib import Path
from docx_corpus import build
from fake_llm import FakeClient
from anonymizer.config import load_runtime_config
from pin_python_order import load_file_config
from anonymizer.pipeline import anonymize_document
from anonymizer.errors import AnonymizerError
logging.disable(logging.CRITICAL)
files = load_file_config(Path(REPO) / "config")
ENV = {"ANON_PROVIDER":"openai","OPENAI_API_KEY":"sk-test","ANON_MODEL":"gpt-test","ANON_CHUNK_SIZE_CHARS":"900","ANON_LLM_CONCURRENCY":"4"}
cfg = load_runtime_config(ENV)
os.makedirs("pipe", exist_ok=True)
n=int(sys.argv[1]); recording={}; reqs=[]; outs=[]
for i in range(n):
    data=build(1000+i, damaged_header=(i%7==3), comments=(i%3!=0), custom=(i%2==0))
    p=f"pipe/in{i}.docx"; open(p,"wb").write(data)
    try:
        r=anonymize_document(data, config=cfg, files=files, client=FakeClient(i, recording), document_id="doc")
        open(f"pipe/out{i}.py.docx","wb").write(r.redacted_docx)
        prov=dict(r.provenance); prov.pop("package_version")
        o={"summary":dataclasses.asdict(r.summary),"warnings":r.warnings,"model":r.model,"postcheck":dataclasses.asdict(r.postcheck),"provenance":prov,"timings":sorted(r.timings)}
    except AnonymizerError as e:
        o={"error":type(e).__name__,"msg":str(e)}
    outs.append(o); reqs.append({"op":"pipeline","path":p,"seed":i,"out":f"pipe/out{i}.java.docx"})
json.dump(recording, open("pipe/recording.json","w"), ensure_ascii=False)
with open("pipe.jsonl","w") as f:
    for r in reqs: f.write(json.dumps(r)+"\n")
with open("pipe.py.out","w") as f:
    for o in outs: f.write(json.dumps(o, ensure_ascii=False)+"\n")
from collections import Counter
print("recorded responses:",len(recording)," outcomes:",Counter(o.get("error","OK") for o in outs))
