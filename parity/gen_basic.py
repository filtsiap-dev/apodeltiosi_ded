import json, random, struct
random.seed(7)
ALPH = list("abcAZ09_ .,-/:'\"\\\n\t\r") + list("αβγΣσςΆάέΐΰϊΫΑΦΜΟΔΥδεουπρωτόκλ") + \
  ["\u00a0","\x1c","\x1f","\x85","\u2028","\u0301","\u0308","²","³","½","٣","😀","ß","İ","ﬁ","Ａ","ǅ","\u200b","\u3000","\x7f","\x00","\u1f71","Ω","K"]
def rs(n): return "".join(random.choice(ALPH) for _ in range(random.randint(0,n)))
ops = ["casefold","strip","split","splitlines","repr","upper","lower","isdigit","len","dumps"]
out=[]
for _ in range(3000):
    out.append({"op": random.choice(ops), "s": rs(12)})
for _ in range(2000):
    f = random.choice([random.uniform(-1e3,1e3), random.uniform(0,1), 10**random.uniform(-10,25), struct.unpack('d', random.getrandbits(64).to_bytes(8,'little'))[0], 0.25, 2.5, 0.125, 1e16, 1e-5, 123456789012345678.0])
    if f != f or f in (float('inf'), float('-inf')): continue
    out.append({"op":"floatrepr","f":f}); out.append({"op":"fixed","f":f,"n":random.choice([1,3])})
PATS = [(r"\w+",0),(r"\b\w{2,}\b",2),(r"\s+",0),(r"\d+",0),(r"[^\W_]{3,}",0),(r"\W+",0),(r"[\w.+-]+@[\w-]+\.[\w.-]+",2),
        (r"(?<!\d)(\d{2})(?!\d)",0),(r"[Α-Ω][α-ω]+",2),(r"(?i:σ)",0),(r"\S+\s*$",0),(r"^.*$",0),(r"x{,2}",0),(r"[\s,.\d]+",0),(r"a{b}",0)]
for _ in range(3000):
    p,f = random.choice(PATS)
    out.append({"op":"finditer","p":p,"flags":f,"s":rs(25)+"@ab.gr "+rs(10)})
with open("basic.jsonl","w") as fh:
    for o in out: fh.write(json.dumps(o, ensure_ascii=False)+"\n")
