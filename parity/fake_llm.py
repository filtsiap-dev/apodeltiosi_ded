"""Deterministic scripted 'model' + recorder. Responses depend only on the request text."""
import hashlib, json, random, re, threading
import httpx, openai
from anonymizer.llm.prompts import SYSTEM_PROMPT_PASS1

def key(system, user): return hashlib.sha256((system + "\x00" + user).encode("utf-8")).hexdigest()
REQ = httpx.Request("POST", "https://example.invalid/v1/chat/completions")

class FakeClient:
    def __init__(self, doc_seed, recording):
        self.doc_seed = doc_seed; self.recording = recording; self.lock = threading.Lock()
        self.chat = self; self.completions = self
    def _record(self, k, entry):
        with self.lock: self.recording[k] = entry
    def create(self, model, messages, max_completion_tokens):
        system, user = messages[0]["content"], messages[1]["content"]
        k = key(system, user)
        rnd = random.Random(k + str(self.doc_seed))
        # document-level failure modes, decided by doc seed
        mode = self.doc_seed % 23
        if mode == 5 and system != SYSTEM_PROMPT_PASS1:
            self._record(k, {"error": "timeout"}); raise openai.APITimeoutError(request=REQ)
        if mode == 11 and rnd.random() < 0.5:
            self._record(k, {"error": "connection"}); raise openai.APIConnectionError(request=REQ)
        if mode == 17 and system != SYSTEM_PROMPT_PASS1:
            self._record(k, {"error": "status", "code": 429})
            raise openai.RateLimitError("rate limited", response=httpx.Response(429, request=REQ), body=None)
        content = self._respond(system, user, rnd)
        self._record(k, {"content": content})
        class M: pass
        msg = M(); msg.content = content; ch = M(); ch.message = msg; resp = M(); resp.choices = [ch]
        return resp
    def _respond(self, system, user, rnd):
        if system == SYSTEM_PROMPT_PASS1:
            r = rnd.random()
            if r < 0.05: return "I cannot parse this document, sorry."
            if r < 0.052: return ""  # empty completion -> AIProviderError
            text = user.split("DOCUMENT EXCERPT:\n", 1)[1]
            names = re.findall(r"[Α-ΩΆ-Ώ][α-ωά-ώ]+\s+[Α-ΩΆ-Ώ][α-ωά-ώ]+", text)
            items = []
            for n in names[:6]:
                items.append({"text": n, "category": rnd.choice(["PERSON", "POSSIBLE_PERSON", "APPELLANT", "bogus"]),
                              "action": rnd.choice(["REDACT", "REVIEW", "SKIP", "preserve", "maybe"])})
            items += [7, None, {"text": "   "}, {"text": ["x", 1], "category": "DATE", "action": "PRESERVE"}]
            body = json.dumps(items, ensure_ascii=False)
            return ("Here you go:\n```json\n" + body + "\n```") if rnd.random() < 0.3 else body
        # pass 2
        retry = "YOUR PREVIOUS RESPONSE WAS REJECTED" in user
        known_json = user.split("emit a final decision for every entry):\n", 1)[1]
        if retry: known_json = known_json.split("\n\nYOUR PREVIOUS RESPONSE WAS REJECTED")[0]
        known = json.loads(known_json)
        if not retry and rnd.random() < 0.08: return "{not json"
        if retry and rnd.random() < 0.01: return "still broken ["
        out = []
        for ks in known:
            if ks["action"] == "REVIEW":
                a = rnd.choice(["REDACT", "PRESERVE", "REVIEW", "SKIP"] + ([] if retry else ["OMIT", "OMIT"]))
                if retry and a == "SKIP" and rnd.random() < 0.97: a = "REDACT"
                if a == "OMIT": continue
            else:
                a = rnd.choice([ks["action"], ks["action"], "SKIP"]) if rnd.random() < 0.97 else "PRESERVE"
            cat = ks["category"] if rnd.random() < 0.9 else rnd.choice(["PERSON", "ADDRESS", "NOT_A_CAT"])
            txt = ks["text"] if rnd.random() < 0.85 else ks["text"].upper()
            out.append({"text": txt, "category": cat, "action": a})
        out.append({"text": "ΑΦΜ", "category": "AFM", "action": "REDACT"})   # short-token guard
        out.append({"text": "κείμενο που δεν υπάρχει", "category": "POSSIBLE_PERSON", "action": "REDACT"})  # unlocatable
        return json.dumps(out, ensure_ascii=False)
