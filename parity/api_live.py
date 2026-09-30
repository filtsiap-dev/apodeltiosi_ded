import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, os, io, zipfile, socket, threading, time, subprocess, base64, re, dataclasses, logging
sys.path.insert(0, REPO); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(REPO)
os.environ.update({"ANON_PROVIDER":"openai","OPENAI_API_KEY":"sk-test","ANON_MODEL":"gpt-test","ANON_API_KEY":"s3cret-key",
                   "ANON_CHUNK_SIZE_CHARS":"900","ANON_MAX_UPLOAD_MB":"1","ANON_LOG_LEVEL":"CRITICAL"})
import uvicorn, anonymizer.api as api, dataclasses as dc
from fake_llm import FakeClient
from docx_corpus import build
import pin_python_order  # noqa: F401  (reproducible Python order)
api.load_file_config = pin_python_order.load_file_config
recording = {}
api.build_client = lambda cfg: FakeClient(1, recording)
threading.Thread(target=lambda: uvicorn.run(api.app, host="127.0.0.1", port=18001, log_level="critical"), daemon=True).start()
time.sleep(2)

KEY = "s3cret-key"
def raw(port, method, path, headers=None, body=b""):
    h = {"Host": f"127.0.0.1:{port}", "Connection": "close"}
    h.update(headers or {})
    if body or method in ("POST",): h["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in h.items() if v is not None) + b"\r\n" + body
    s = socket.create_connection(("127.0.0.1", port)); s.sendall(req)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        data += chunk
    s.close()
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":"); hdrs[k.strip().lower()] = v.strip()
    if hdrs.get("transfer-encoding") == "chunked":
        out = b""; r = rest
        while True:
            n, _, r = r.partition(b"\r\n"); n = int(n, 16)
            if n == 0: break
            out += r[:n]; r = r[n+2:]
        rest = out
    return status, hdrs, rest

def mp(parts, boundary="XyZbOuNdArY"):
    b = b""
    for name, filename, data in parts:
        disp = "form-data" + (f'; name="{name}"' if name is not None else "") + (f'; filename="{filename}"' if filename is not None else "")
        b += f"--{boundary}\r\nContent-Disposition: {disp}\r\n".encode() + (b"Content-Type: application/octet-stream\r\n" if filename is not None else b"") + b"\r\n" + data + b"\r\n"
    return b + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"

AUTH = {"Authorization": f"Bearer {KEY}"}
docs = [build(3000 + i, damaged_header=(i % 4 == 1)) for i in range(14)]
bad_docx = b"PK\x03\x04 not really"
cases = []
cases += [("GET", "/healthz", {}, b""), ("GET", "/nope", {}, b""), ("GET", "/anonymize", AUTH, b""), ("POST", "/healthz", {}, b""),
          ("GET", "/healthz/", {}, b""), ("POST", "/anonymize/?summary=1", AUTH, b""), ("HEAD", "/healthz", {}, b""), ("PUT", "/anonymize", {}, b"")]
for auth in [None, "Bearer", "bearer " + KEY, "Basic abc", "Bearer wrong", "  BEARER   " + KEY + "  ", "Bearer " + KEY + "x", "Bearer\t" + KEY]:
    cases.append(("POST", "/anonymize", ({"Authorization": auth} if auth else {}) | {"Content-Type": "text/plain"}, b"x"))
ct = {"Content-Type": "application/octet-stream"}
cases += [("POST", "/anonymize", AUTH | {"Content-Type": "text/plain"}, docs[0]),
          ("POST", "/anonymize", AUTH | {"Content-Type": "Multipart/form-data; boundary=x"}, b"x"),
          ("POST", "/anonymize", AUTH | {"Content-Type": "multipart/form-data"}, b"x"),
          ("POST", "/anonymize", AUTH, b""),
          ("POST", "/anonymize", AUTH | ct, b""),
          ("POST", "/anonymize", AUTH | ct, b"x" * (1024 * 1024 + 1)),
          ("POST", "/anonymize", AUTH | ct, bad_docx),
          ("POST", "/anonymize?summary=abc", AUTH | ct, docs[0]),
          ("POST", "/anonymize?summary=abc", AUTH | ct, b""),
          ("POST", "/anonymize?summary=", AUTH | ct, docs[0])]
for parts in ([("other", None, b"1")], [("file", None, b"abc")], [(None, "a.docx", docs[1])],
              [("file", "a.docx", bad_docx), ("file", "b.docx", docs[1])], [("file", "", docs[2])], [("file", "a.docx", docs[3])],
              [("file", "b.docx", docs[1]), ("file", None, b"text")]):
    body, c = mp(parts); cases.append(("POST", "/anonymize", AUTH | {"Content-Type": c}, body))
body, c = mp([("file", "a.docx", docs[4])]); cases.append(("POST", "/anonymize?summary=1", AUTH | {"Content-Type": c}, body))
for i, d in enumerate(docs[5:]):
    q = ["", "?summary=1", "?summary=%202%20", "?summary=0", "?summary=1.0", "?summary=-1&x=2", "?summary=0&summary=1", "", "?summary=1"][i]
    cases.append(("POST", "/anonymize" + q, AUTH | {"Content-Type": ["application/octet-stream", ApiDocx := "application/vnd.openxmlformats-officedocument.wordprocessingml.document"][i % 2]}, d))

py = [raw(18001, *c) for c in cases]
json.dump(recording, open(f"{HERE}/api_recording.json", "w"), ensure_ascii=False)
cp = os.environ["JCP"] + ":" + f"{HERE}/java/classes"
proc = subprocess.Popen(["java", f"-Dcfg={REPO}/config", "-cp", cp, "ApiParity", f"{HERE}/api_recording.json", "18002"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
proc.stdout.readline()
jv = [raw(18002, *c) for c in cases]
proc.kill()

def docx_parts(b):
    z = zipfile.ZipFile(io.BytesIO(b)); return [(i.filename, z.read(i.filename)) for i in z.infolist()]
def norm(status, h, body):
    keep = {k: v for k, v in h.items() if k in ("content-type", "allow", "location", "www-authenticate", "x-postcheck-findings", "x-postcheck-kinds", "content-disposition")}
    if "location" in keep: keep["location"] = re.sub(r":1800[12]/", ":PORT/", keep["location"])
    if "content-disposition" in keep: keep["content-disposition"] = re.sub(r'filename="[0-9a-f]{12}_', 'filename="ID_', keep["content-disposition"])
    if keep.get("content-type", "").startswith("application/vnd.openxml"): return status, keep, docx_parts(body)
    if keep.get("content-type") == "application/json" and body:
        j = json.loads(body)
        if isinstance(j, dict) and "docx_base64" in j:
            j["docx_base64"] = docx_parts(base64.b64decode(j["docx_base64"])); j["document_id"] = "ID"
            j["docx_base64"] = [(n, base64.b64encode(d).decode()) for n, d in j["docx_base64"]]
        return status, keep, j
    return status, keep, body
same = 0
from collections import Counter
statuses = Counter()
for c, a, b in zip(cases, py, jv):
    na, nb = norm(*a), norm(*b); statuses[a[0]] += 1
    if na == nb: same += 1
    else:
        print("DIFF", c[0], c[1], {k: v for k, v in c[2].items()}, "\n  py:", str(na)[:300], "\n  jv:", str(nb)[:300])
print(f"cases: {len(cases)}  identical: {same}  python statuses: {dict(sorted(statuses.items()))}")
