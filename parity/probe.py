import json, re, sys
def handle(r):
    op, s = r["op"], r.get("s")
    if op == "casefold": return s.casefold()
    if op == "strip": return s.strip()
    if op == "split": return s.split()
    if op == "splitlines": return s.splitlines()
    if op == "repr": return repr(s)
    if op == "upper": return s.upper()
    if op == "lower": return s.lower()
    if op == "isdigit": return s.isdigit()
    if op == "len": return len(s)
    if op == "dumps": return json.dumps(s, ensure_ascii=False)
    if op == "floatrepr": return repr(float(r["f"]))
    if op == "fixed": return f"{float(r['f']):.{r['n']}f}"
    if op == "finditer":
        p = re.compile(r["p"], r["flags"])
        return [[[m.start(g), m.end(g)] for g in range(0, (p.groups or 0) + 1)] for m in p.finditer(s)]
    raise ValueError(op)
for line in sys.stdin:
    print(json.dumps(handle(json.loads(line)), ensure_ascii=False))
