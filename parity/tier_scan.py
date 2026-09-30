import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, glob, dataclasses
sys.path.insert(0, REPO)
sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import pin_python_order  # noqa: F401  (reproducible Python order)
from pathlib import Path
from pin_python_order import load_file_config
from anonymizer.postcheck import scan_redacted_docx_bytes
from anonymizer.errors import AnonymizerError
cfg = load_file_config(Path(REPO) / "config")
paths = sorted(glob.glob("docx/in*.docx")) 
paths = [p for p in paths if ".out." not in p] + sorted(glob.glob("docx/*.py.out.docx"))
with open("scan.jsonl","w") as f:
    for p in paths: f.write(json.dumps({"op":"scan","path":p})+"\n")
with open("scan.py.out","w") as f:
    for p in paths:
        try: r=dataclasses.asdict(scan_redacted_docx_bytes(open(p,"rb").read(), cfg))
        except AnonymizerError as e: r={"error":type(e).__name__}
        f.write(json.dumps(r, ensure_ascii=False)+"\n")
