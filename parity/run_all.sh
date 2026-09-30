#!/bin/sh
# Differential verification (CLAUDE.md §7): runs every tier through Python and Java and diffs.
# Prerequisites, from the repo root:
#   pip install -r requirements.txt            (Python side; FastAPI/uvicorn/httpx<0.28 for the API tier)
#   mvn -q package -DskipTests && mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
# All inputs are synthetic (corpus.py, docx_corpus.py); no real decisions are used.
set -e
cd "$(dirname "$0")"
export PY_REPO="${PY_REPO:-$(cd .. && pwd)}"
if [ -f ../env.sh ]; then . ../env.sh; JCP="$CP:../stubs/classes"; else JCP="$(cat ../target/cp.txt)"; fi
export JCP="$(cd .. && pwd)/target/classes:$JCP"
run() { echo "== $1"; }

run "compat layer: 10,000 string/regex/json/float cases"
python3 gen_basic.py && python3 probe.py < basic.jsonl > py.out && ./run_java.sh basic.jsonl java.out && python3 compare.py basic.jsonl py.out java.out 3

run "detectors + resolver + summary: 300 documents"
python3 tier_detect.py 300 && ./run_java.sh detect.jsonl detect.java.out && python3 compare.py detect.jsonl detect.py.out detect.java.out 3

run "DOCX engine: 208 packages + invalid inputs (units, char maps, plans, output bytes)"
python3 tier_docx.py 200 && ./run_java.sh docx.jsonl docx.java.out && { python3 compare_docx.py > docx.cmp.txt && tail -1 docx.cmp.txt; } || { tail -20 docx.cmp.txt; exit 1; }

run "post-redaction scan: inputs and redacted outputs"
python3 tier_scan.py && ./run_java.sh scan.jsonl scan.java.out && python3 compare.py scan.jsonl scan.py.out scan.java.out 3

run "damaged-part recovery: 400 mutated headers (informational; see CLAUDE.md O6)"
python3 tier_recover.py && ./run_java.sh rec.jsonl rec.java.out && { python3 compare.py rec.jsonl rec.py.out rec.java.out 0 | tail -1 || true; }

run "end-to-end pipeline with recorded LLM responses: 150 documents"
python3 tier_pipeline.py 150 && ./run_java.sh pipe.jsonl pipe.java.out 2>/dev/null && python3 compare.py pipe.jsonl pipe.py.out pipe.java.out 3

run "HTTP API over the wire: FastAPI/uvicorn vs Java HttpServer"
{ python3 api_live.py > api.cmp.txt && tail -3 api.cmp.txt; } || { tail -20 api.cmp.txt; exit 1; }

echo "== all tiers passed"
