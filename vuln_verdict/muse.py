"""Minimal Muse Spark (Meta Model API) client with a persistent spend cap.

Configuration (environment only; the key is never logged):
  MODEL_API_KEY     API key (required for audit/remediation)
  VV_MUSE_MODEL     model id            (default muse-spark-1.3)
  VV_MUSE_BASE      API base URL         (default https://api.meta.ai/v1)
  VV_SPEND_FILE     JSON spend log       (default ./vv_spend.json)
  VV_BUDGET_USD     hard stop, total USD in the spend log (default 5.0)

Worst-case reservations are persisted under a cross-process file lock before every call. A process
crash can therefore leave a conservative stale reservation; remove/reset the spend file only after
confirming no harness processes are running. Actual usage is recorded atomically after each response.
"""
import datetime, json, math, os, threading, time

import requests

BASE = os.environ.get("VV_MUSE_BASE", "https://api.meta.ai/v1")
MODEL = os.environ.get("VV_MUSE_MODEL", "muse-spark-1.3")
PRICE_IN = float(os.environ.get("VV_PRICE_IN_PER_M", "1.25")) / 1e6
PRICE_OUT = float(os.environ.get("VV_PRICE_OUT_PER_M", "4.25")) / 1e6
_lock = threading.Lock()
_reserved = 0.0


class BudgetExceeded(RuntimeError):
    pass


def spend_file():
    return os.environ.get("VV_SPEND_FILE", os.path.abspath("vv_spend.json"))


def budget():
    value = float(os.environ.get("VV_BUDGET_USD", "5.0"))
    if not math.isfinite(value) or value < 0:
        raise ValueError("VV_BUDGET_USD must be a finite, non-negative number")
    return value


def _load():
    p = spend_file()
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        d.setdefault("reserved_usd", 0.0)
        return d
    return {"model": MODEL, "total_usd": 0.0, "reserved_usd": 0.0, "calls": 0, "input_tokens": 0,
            "output_tokens": 0, "reasoning_tokens": 0, "failed_calls": 0, "by_tag": {}}


def _save(d):
    p = spend_file(); tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, p)


def spent():
    with _lock:
        return _load()["total_usd"]


class _FileLock:
    """Cross-process lock so reservations and spend entries cannot race between harness runs."""
    def __enter__(self):
        try:
            import fcntl
            self.f = open(spend_file() + ".lock", "a"); fcntl.flock(self.f, fcntl.LOCK_EX)
        except ImportError:
            self.f = None
        return self

    def __exit__(self, *a):
        if self.f:
            import fcntl
            fcntl.flock(self.f, fcntl.LOCK_UN); self.f.close()


def _record(tag, usage):
    with _FileLock():
        return _record_locked(tag, usage)


def _record_locked(tag, usage):
    d = _load()
    pin = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
    pout = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
    det = usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}
    rt = int(det.get("reasoning_tokens") or 0)
    pout = max(pout, rt)
    cost = pin * PRICE_IN + pout * PRICE_OUT
    d["total_usd"] = round(d["total_usd"] + cost, 6)
    d["calls"] = d.get("calls", 0) + 1
    d["input_tokens"] = d.get("input_tokens", 0) + pin
    d["output_tokens"] = d.get("output_tokens", 0) + pout
    d["reasoning_tokens"] = d.get("reasoning_tokens", 0) + rt
    t = d.setdefault("by_tag", {}).setdefault(tag, {"usd": 0.0, "calls": 0, "in": 0, "out": 0})
    t["usd"] = round(t["usd"] + cost, 6); t["calls"] += 1; t["in"] += pin; t["out"] += pout
    d["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
    _save(d)
    return cost


def _reserve(worst):
    global _reserved
    if not math.isfinite(worst) or worst < 0:
        raise ValueError("reservation must be a finite, non-negative number")
    with _lock:
        with _FileLock():
            d = _load()
            cur = d["total_usd"]
            reserved = float(d.get("reserved_usd", 0.0))
            if cur + reserved + worst > budget():
                raise BudgetExceeded(
                    f"spent ${cur:.2f} + reserved ${reserved:.2f} + worst ${worst:.3f} > cap ${budget():.2f}")
            d["reserved_usd"] = round(reserved + worst, 9)
            _save(d)
        _reserved += worst


def _release(worst):
    global _reserved
    with _lock:
        with _FileLock():
            d = _load()
            d["reserved_usd"] = round(max(0.0, float(d.get("reserved_usd", 0.0)) - worst), 9)
            _save(d)
        _reserved = max(0.0, _reserved - worst)


def chat(messages, tag, max_tokens=2500, reasoning_effort="low", schema=None, retries=3):
    """Returns (content, cost_usd)."""
    if not os.environ.get("MODEL_API_KEY"):
        raise RuntimeError("MODEL_API_KEY is not set")
    est_in = sum(len(m["content"]) for m in messages) / 3.0 + 200
    worst = est_in * PRICE_IN + max_tokens * PRICE_OUT
    reserved = False
    try:
        _reserve(worst)
        reserved = True
        body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "reasoning_effort": reasoning_effort}
        if schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": schema[0], "schema": schema[1]}}
        last = None
        for a in range(retries):
            try:
                r = requests.post(f"{BASE}/chat/completions", json=body, timeout=300,
                                  headers={"Authorization": f"Bearer {os.environ['MODEL_API_KEY']}"})
            except requests.RequestException as e:
                last = f"network error: {type(e).__name__}"; time.sleep(2 * (a + 1)); continue
            if r.status_code == 200:
                j = r.json()
                usage = j.get("usage") or {"prompt_tokens": int(est_in), "completion_tokens": max_tokens}
                with _lock:
                    cost = _record(tag, usage)
                return j["choices"][0]["message"].get("content") or "", cost
            last = f"http {r.status_code}: {r.text[:200]}"
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(3 * (a + 1)); continue
            break
        with _lock:
            with _FileLock():
                d = _load(); d["failed_calls"] = d.get("failed_calls", 0) + 1; _save(d)
        raise RuntimeError(last)
    finally:
        if reserved:
            _release(worst)


def chat_json(messages, tag, schema, **kw):
    content, cost = chat(messages, tag, schema=schema, **kw)
    s = content.strip()
    if s.startswith("```"):
        s = s.strip("`"); s = s[s.find("{"):]
    try:
        return json.loads(s[s.find("{"): s.rfind("}") + 1]), cost
    except Exception:
        raise RuntimeError(f"unparseable JSON from model: {content[:200]!r}")
