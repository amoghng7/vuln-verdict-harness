"""Meta Model API client with a hard, persistent spend budget.

Key is read from env MODEL_API_KEY (never printed). Every response's `usage` is billed into
synth/spend.json. Before each call we reserve the worst case (input estimate + max_tokens output);
if spent + reservations would exceed ABORT_AT_USD the call is refused (BudgetExceeded).
"""
import json, os, threading, time, datetime
import requests

BASE = "https://api.meta.ai/v1"
MODEL = "muse-spark-1.3"          # Standard mode (content NOT used to train Meta models)
PRICE_IN = 1.25 / 1e6             # $/token, Standard mode, verified dev.meta.ai/docs/pricing-rate-limits 2026-10-31
PRICE_OUT = 4.25 / 1e6
ABORT_AT_USD = 22.0               # round 2: hard stop $22 (round-2 budget: <= $4 more, total <= $22.8)
SPEND_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spend.json")

_lock = threading.Lock()
_reserved = 0.0


class BudgetExceeded(RuntimeError):
    pass


def _load():
    if os.path.exists(SPEND_FILE):
        return json.load(open(SPEND_FILE))
    return {"model": MODEL, "price_in_per_M": 1.25, "price_out_per_M": 4.25, "abort_at_usd": ABORT_AT_USD,
            "total_usd": 0.0, "calls": 0, "input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0,
            "failed_calls": 0, "by_tag": {}}


def spent():
    with _lock:
        return _load()["total_usd"]


def _record(tag, usage):
    d = _load()
    pin = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
    pout = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
    det = usage.get("completion_tokens_details") or usage.get("output_tokens_details") or {}
    rt = int(det.get("reasoning_tokens") or 0)
    if rt > pout:  # defensive: if reasoning were reported outside completion_tokens, bill it too
        pout += rt
    cost = pin * PRICE_IN + pout * PRICE_OUT  # cached input billed at full rate (conservative)
    d["total_usd"] = round(d["total_usd"] + cost, 6)
    d["calls"] += 1
    d["input_tokens"] += pin
    d["output_tokens"] += pout
    d["reasoning_tokens"] += rt
    t = d["by_tag"].setdefault(tag, {"usd": 0.0, "calls": 0, "in": 0, "out": 0})
    t["usd"] = round(t["usd"] + cost, 6); t["calls"] += 1; t["in"] += pin; t["out"] += pout
    d["updated"] = datetime.datetime.now().isoformat(timespec="seconds")
    tmp = SPEND_FILE + ".tmp"
    json.dump(d, open(tmp, "w"), indent=2)
    os.replace(tmp, SPEND_FILE)
    return cost, d["total_usd"]


def chat(messages, tag, max_tokens=4000, reasoning_effort="low", schema=None, temperature=None, retries=3):
    """Returns (content_str, usage). Raises BudgetExceeded before any call that could cross the cap."""
    global _reserved
    est_in = sum(len(m["content"]) for m in messages) / 3.0 + 200
    worst = est_in * PRICE_IN + max_tokens * PRICE_OUT
    with _lock:
        cur = _load()["total_usd"]
        if cur + _reserved + worst > ABORT_AT_USD:
            raise BudgetExceeded(f"spent ${cur:.2f} + reserved ${_reserved:.2f} + worst ${worst:.3f} > ${ABORT_AT_USD}")
        _reserved += worst
    try:
        body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "reasoning_effort": reasoning_effort}
        if temperature is not None:
            body["temperature"] = temperature
        if schema:
            body["response_format"] = {"type": "json_schema", "json_schema": {"name": schema[0], "schema": schema[1]}}
        last = None
        for a in range(retries):
            try:
                r = requests.post(f"{BASE}/chat/completions", json=body, timeout=300,
                                  headers={"Authorization": f"Bearer {os.environ['MODEL_API_KEY']}"})
            except requests.RequestException as e:
                last = f"net:{type(e).__name__}"; time.sleep(2 * (a + 1)); continue
            if r.status_code == 200:
                j = r.json()
                usage = j.get("usage") or {}
                with _lock:
                    if not usage:  # never seen; bill worst case so the log never undercounts
                        usage = {"prompt_tokens": int(est_in), "completion_tokens": max_tokens}
                    _record(tag, usage)
                return j["choices"][0]["message"].get("content") or "", usage
            last = f"http {r.status_code}: {r.text[:300]}"
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(3 * (a + 1)); continue
            break
        with _lock:
            d = _load(); d["failed_calls"] += 1
            json.dump(d, open(SPEND_FILE, "w"), indent=2)
        raise RuntimeError(last)
    finally:
        with _lock:
            _reserved -= worst
