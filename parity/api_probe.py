import os as _os
REPO = _os.environ.get("PY_REPO", _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import json, sys, os, logging
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.update({"ANON_PROVIDER":"openai","OPENAI_API_KEY":"sk-test","ANON_MODEL":"gpt-test","ANON_API_KEY":"s3cret-key","ANON_CHUNK_SIZE_CHARS":"900","ANON_MAX_UPLOAD_MB":"1"})
from fastapi.testclient import TestClient
from anonymizer.api import app
logging.disable(logging.CRITICAL)
with TestClient(app, raise_server_exceptions=False) as c:
    H={"Authorization":"Bearer s3cret-key"}
    for q in ["1","0","abc",""," 2 ","1.0","1_000","+1","-1","１","2.5","1e3","true"]:
        r=c.post(f"/anonymize?summary={q}", headers={**H,"content-type":"text/plain"}, content=b"x")
        r2=c.post(f"/anonymize?summary={q}", headers={**H,"content-type":"application/octet-stream"}, content=b"PKnotadocx")
        print("summary=%r"%q, r.status_code, r2.status_code, r2.text[:200])
    for path,meth in [("/nope","GET"),("/anonymize","GET"),("/healthz","POST"),("/healthz/","GET"),("/anonymize/","POST"),("/healthz","HEAD")]:
        r=c.request(meth, path, headers=H, follow_redirects=False); print(meth,path,r.status_code,dict((k,v) for k,v in r.headers.items() if k in("allow","location","www-authenticate","content-type")),r.text[:120])
    for auth in [None,"Bearer","bearer s3cret-key","Basic abc","Bearer wrong","  BEARER   s3cret-key  "]:
        h={} if auth is None else {"Authorization":auth}
        r=c.post("/anonymize", headers={**h,"content-type":"text/plain"}, content=b"x"); print("auth",repr(auth)[:30],r.status_code,r.headers.get("www-authenticate"),r.text)
    print("multipart none", c.post("/anonymize", headers={**H,"content-type":"multipart/form-data"}, content=b"x").text)
    print("multipart nofile", c.post("/anonymize", headers=H, data={"other":"1"}).text)
    print("multipart textfile", c.post("/anonymize", headers=H, data={"file":"abc"}).text)
    print("empty raw", c.post("/anonymize", headers={**H,"content-type":"application/octet-stream"}, content=b"").text)
    print("big raw", c.post("/anonymize", headers={**H,"content-type":"application/octet-stream"}, content=b"x"*(1024*1024+1)).status_code)
    print("Multipart case", c.post("/anonymize", headers={**H,"content-type":"Multipart/form-data; boundary=x"}, content=b"x").status_code)
    print("healthz", c.get("/healthz").text)
