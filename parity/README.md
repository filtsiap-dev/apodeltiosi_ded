# Differential verification harness

Runs the same synthetic inputs through the Python implementation and the Java port and diffs
the results (CLAUDE.md §7). Everything here is generated: no real decisions, names or numbers.

    pip install -r requirements.txt "httpx<0.28"   # Python side (+ FastAPI/uvicorn for the API tier)
    mvn -q package -DskipTests
    mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
    parity/run_all.sh

| File | Role |
|---|---|
| `run_all.sh` | runs every tier and prints mismatch counts |
| `run_java.sh` | compiles and runs `java/ParityProbe` on a JSON-lines request file |
| `java/ParityProbe.java` | Java side of every tier (ops: compat, detect, docx, scan, pipeline) |
| `java/ApiParity.java` | starts the Java HTTP server with replayed LLM responses |
| `gen_basic.py`, `probe.py`, `compare.py` | compat-layer fuzz and the generic JSON-lines diff |
| `corpus.py`, `docx_corpus.py` | synthetic Greek decision text and DOCX packages |
| `tier_*.py` | Python side of each tier (writes `*.jsonl` requests and `*.py.out` results) |
| `fake_llm.py` | scripted deterministic "model"; records responses keyed by sha256(system + user) |
| `api_live.py` | raw-HTTP comparison of uvicorn/FastAPI and the Java server |
| `pin_python_order.py` | pins Python's hash-seed-dependent set order to Java's (D12) |

Expected: 0 mismatches everywhere except the recovery tier (informational, O6) and one API
case (deviation 7). Generated artifacts (`docx/`, `pipe/`, `*.jsonl`, `*.out`, recordings) are
git-ignored.
