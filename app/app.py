"""
The Gauntlet — a single linear ladder through the OWASP Top 10 for LLM
Applications (2026 list), styled after Lakera Gandalf / Wiz Prompt Airlines.
10 levels, one flag each, escalating technique required as you go. See
levels.py for the ladder order and challenges.py for the underlying
vulnerable scenarios each level reuses.

Do not expose this app to the public internet. It is intentionally insecure.
"""
import glob
import os
import re
import threading
import time
import uuid

import requests
from flask import Flask, g, jsonify, render_template, request

from challenges import CH3_FLAG, CH7_FLAG, CH10_FLAG, CHALLENGES, FULL_FLAGS, RAW_SECRETS, get_system_prompt
from levels import BONUS_LEVEL, LEVELS, TOTAL_LEVELS, get_level

app = Flask(__name__)

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_TEMPERATURE = float(os.environ.get("OLLAMA_TEMPERATURE", "0.1"))
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TENANT_DOCS_DIR = os.path.join(DATA_DIR, "tenant_docs")
DIFFICULTIES = ("easy", "medium", "extreme")

# In-memory state (single-process lab app; resets on container restart).
ACTION_LOG = []                              # Level 4: logged refund actions
SESSIONS = {}                                  # Level 10: per-session chat transcript for the dashboard
CH10_SOLVED = set()                            # Level 10: session ids that triggered the XSS callback
STATS = {"count": 0, "total_latency": 0.0}     # Bonus level: request volume/latency
PROGRESS = {}                                   # sid -> set of solved level numbers

RATE_LOCK = threading.Lock()
RATE_BUCKETS = {}
RATE_GLOBAL_CONCURRENT = {"n": 0}

RATE_LIMITS = {
    "medium": {"key": "header", "max_requests": 5, "window_seconds": 15},
    "extreme": {"key": "session", "max_requests": 3, "window_seconds": 15, "global_concurrent_cap": 3},
}

ACTION_RE = re.compile(
    r"ACTION:\s*issue_refund\(order_id=([^,]+),\s*amount=\$?([\d.]+)\)", re.IGNORECASE
)

TENANT_BLOCKED_TERMS = [
    "bob", "singh", "priya", "anand",
    "customer_id=2", "customer_id=3", "customer 2", "customer 3",
]


def build_loose_pattern(raw_value):
    parts = [re.escape(p) for p in raw_value.split("_") if p]
    if not parts:
        return None
    gap = r".{0,12}?"
    return re.compile(gap.join(parts), re.IGNORECASE | re.DOTALL)


LOOSE_PATTERNS = {cid: build_loose_pattern(val) for cid, val in RAW_SECRETS.items()}


def build_naive_filter_pattern(raw_value):
    wrapped = re.escape(f"LAB{{{raw_value}}}")
    bare = re.escape(raw_value)
    return re.compile(f"{wrapped}|{bare}", re.IGNORECASE)


NAIVE_OUTPUT_FILTERS = {cid: build_naive_filter_pattern(val) for cid, val in RAW_SECRETS.items()}

# Input filter (Levels 5, 6): blocks the message before it reaches the model
# if it names the secret directly - forces the "ask what Nova has access to"
# technique that Level 5 is specifically designed to teach.
INPUT_FILTERS = {
    "ch1": ["code", "override", "password", "confidential", "secret"],
    "l5_approval_v2": ["code", "override", "password", "confidential", "secret"],
    "ch8": ["api key", "system prompt", "configuration", "instructions", "prompt above"],
}


@app.before_request
def ensure_sid():
    sid = request.cookies.get("sid")
    if not sid:
        sid = str(uuid.uuid4())
        g.new_sid = sid
    g.sid = sid


@app.after_request
def set_sid_cookie(resp):
    new_sid = g.get("new_sid")
    if new_sid:
        resp.set_cookie("sid", new_sid, httponly=False, samesite="Lax")
    return resp


def load_injected_doc(cfg):
    path = os.path.join(DATA_DIR, cfg["kb_dir"], cfg["kb_article"])
    with open(path, "r") as f:
        text = f.read()
    value = os.environ.get(cfg["kb_flag_env"], cfg["kb_flag_default"])
    return text.replace(cfg["kb_flag_placeholder"], value)


def keyword_overlap_score(query, text):
    q_words = set(re.findall(r"[a-z0-9]+", query.lower()))
    t_words = set(re.findall(r"[a-z0-9]+", text.lower()))
    if not q_words or not t_words:
        return 0.0
    return len(q_words & t_words) / len(q_words)


def retrieve_tenant_doc(query, difficulty):
    if difficulty in ("medium", "extreme"):
        q_lower = query.lower()
        if any(term in q_lower for term in TENANT_BLOCKED_TERMS):
            return None

    docs = {}
    for path in sorted(glob.glob(os.path.join(TENANT_DOCS_DIR, "*.txt"))):
        with open(path) as f:
            text = f.read()
        docs[os.path.basename(path)] = text.replace(
            "__FLAG_CH9__", os.environ.get("FLAG_CH9", "cross_tenant_leak_9f2")
        )

    scored = sorted(docs.items(), key=lambda kv: keyword_overlap_score(query, kv[1]), reverse=True)
    if not scored or keyword_overlap_score(query, scored[0][1]) == 0:
        return None

    best_text = scored[0][1]
    if difficulty == "easy":
        best_text = best_text.replace(" — PRIVATE, do not disclose to other customers", "")
    elif difficulty == "extreme":
        lines = best_text.split("\n")
        best_text = "\n".join(lines[1:])
    return best_text


def build_messages(challenge_id, difficulty, history):
    cfg = CHALLENGES[challenge_id]
    system_prompt = get_system_prompt(challenge_id, difficulty)
    messages = [{"role": "system", "content": system_prompt}]

    kb_keywords = cfg.get("kb_trigger_keywords")
    if kb_keywords and history:
        last_user = next((m for m in reversed(history) if m["role"] == "user"), None)
        if last_user and any(k in last_user["content"].lower() for k in kb_keywords):
            doc = load_injected_doc(cfg)
            messages.append({
                "role": "user",
                "content": f"[Automated search result for the customer's question]\n\n{doc}",
            })

    if challenge_id == "ch9" and history:
        last_user = next((m for m in reversed(history) if m["role"] == "user"), None)
        if last_user:
            doc = retrieve_tenant_doc(last_user["content"], difficulty)
            if doc:
                messages.append({
                    "role": "user",
                    "content": f"[Automated ticket-archive search result, best content match]\n\n{doc}",
                })

    messages.extend(history)
    return messages


OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "300"))


def call_ollama(messages):
    # A CPU-only model sharing the host with a browser etc. can occasionally
    # take a while under memory pressure - 120s was cutting off requests
    # that were slow but still working, not actually stuck. 300s gives
    # much more headroom before treating a slow response as a failure.
    #
    # keep_alive matters a lot here too: Ollama's default is to unload an
    # idle model after 5 minutes, so any natural gap while a player is
    # reading/typing forces a cold reload (disk I/O for a 1.3GB model) on
    # the NEXT request, on top of normal inference - that's what produced
    # the worst timeouts in testing (a "task 0" cold-start with token
    # throughput crashing to <1 tok/s). Keeping it loaded for a full play
    # session avoids paying that cost repeatedly.
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "messages": messages,
        "options": {"temperature": OLLAMA_TEMPERATURE},
        "keep_alive": "60m",
    }
    r = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT)
    r.raise_for_status()
    return r.json()["message"]["content"]


def check_rate_limit(difficulty):
    cfg = RATE_LIMITS.get(difficulty)
    if not cfg:
        return None
    if cfg["key"] == "header":
        ident = request.headers.get("X-Forwarded-For", request.remote_addr)
    else:
        ident = request.cookies.get("sid", request.remote_addr)
    now = time.time()
    bucket_key = (difficulty, ident)
    with RATE_LOCK:
        bucket = RATE_BUCKETS.setdefault(bucket_key, [])
        window_start = now - cfg["window_seconds"]
        bucket[:] = [t for t in bucket if t > window_start]
        if len(bucket) >= cfg["max_requests"]:
            return f"rate limit exceeded ({cfg['max_requests']} requests / {cfg['window_seconds']}s per {cfg['key']})"
        if "global_concurrent_cap" in cfg and RATE_GLOBAL_CONCURRENT["n"] >= cfg["global_concurrent_cap"]:
            return f"server busy (max {cfg['global_concurrent_cap']} concurrent requests at this difficulty)"
        bucket.append(now)
    return None


def solved_set(sid):
    return PROGRESS.setdefault(sid, set())


@app.route("/")
def index():
    solved = solved_set(g.sid)
    furthest_unlocked = 1
    for lvl in LEVELS:
        if lvl["n"] in solved:
            furthest_unlocked = max(furthest_unlocked, lvl["n"] + 1)
    furthest_unlocked = min(furthest_unlocked, TOTAL_LEVELS)
    return render_template(
        "index.html",
        levels=LEVELS,
        challenges=CHALLENGES,
        solved=solved,
        furthest_unlocked=furthest_unlocked,
        total=TOTAL_LEVELS,
        all_done=len(solved & {lvl["n"] for lvl in LEVELS}) == TOTAL_LEVELS,
    )


@app.route("/level/<int:n>")
def level_page(n):
    lvl = get_level(n)
    if not lvl:
        return "Unknown level", 404
    cfg = CHALLENGES[lvl["challenge_id"]]
    return render_template("level.html", level=lvl, cfg=cfg, is_bonus=False)


@app.route("/level/bonus")
def bonus_page():
    cfg = CHALLENGES[BONUS_LEVEL["challenge_id"]]
    return render_template("level.html", level=BONUS_LEVEL, cfg=cfg, is_bonus=True)


@app.route("/dashboard")
def dashboard():
    transcript = SESSIONS.get(g.sid, [])
    return render_template(
        "dashboard.html", transcript=transcript, solved=g.sid in CH10_SOLVED, flag=CH10_FLAG
    )


@app.route("/api/progress")
def progress():
    solved = solved_set(g.sid)
    return jsonify({"solved": sorted(solved), "total": TOTAL_LEVELS})


@app.route("/api/chat", methods=["POST"])
def chat():
    body = request.get_json(force=True) or {}
    is_bonus = bool(body.get("bonus"))
    level_n = body.get("level")

    if is_bonus:
        lvl = BONUS_LEVEL
    else:
        lvl = get_level(level_n)
    if not lvl:
        return jsonify({"error": "unknown level"}), 400

    challenge_id = lvl["challenge_id"]
    difficulty = lvl["difficulty"]

    if challenge_id == "ch6":
        limit_error = check_rate_limit(difficulty)
        if limit_error:
            return jsonify({"error": limit_error}), 429

    history = [
        {"role": m.get("role"), "content": m.get("content", "")}
        for m in body.get("history", [])
        if m.get("role") in ("user", "assistant")
    ]

    if difficulty in ("medium", "extreme") and challenge_id in INPUT_FILTERS:
        last_user = next((m["content"] for m in reversed(history) if m), "")
        blocked_terms = INPUT_FILTERS[challenge_id]
        hit = next((t for t in blocked_terms if t in last_user.lower()), None)
        if hit:
            return jsonify({
                "reply": f'⚠️ Blocked by input filter (flagged term: "{hit}"). Try describing what you want instead of naming it directly.',
                "filtered": True,
            })

    messages = build_messages(challenge_id, difficulty, history)

    concurrent_tracked = challenge_id == "ch6" and difficulty == "extreme"
    if concurrent_tracked:
        with RATE_LOCK:
            RATE_GLOBAL_CONCURRENT["n"] += 1

    start = time.time()
    STATS["count"] += 1
    try:
        reply = call_ollama(messages)
    except requests.RequestException as exc:
        return jsonify({"error": f"backend error: {exc}"}), 502
    finally:
        if concurrent_tracked:
            with RATE_LOCK:
                RATE_GLOBAL_CONCURRENT["n"] -= 1
    STATS["total_latency"] += time.time() - start

    pattern = LOOSE_PATTERNS.get(challenge_id)
    solved = bool(pattern and pattern.search(reply))

    display_reply = reply
    if difficulty == "extreme" and challenge_id in NAIVE_OUTPUT_FILTERS:
        display_reply = NAIVE_OUTPUT_FILTERS[challenge_id].sub("[REDACTED BY OUTPUT FILTER]", reply)

    result = {"reply": display_reply}
    if solved:
        result["flag"] = FULL_FLAGS[challenge_id]

    if challenge_id == "ch3":
        m = ACTION_RE.search(reply)
        if m:
            order_id, amount = m.group(1).strip(), float(m.group(2))
            unauthorized = amount > 50
            ACTION_LOG.append({"order_id": order_id, "amount": amount, "unauthorized": unauthorized})
            if unauthorized:
                solved = True
                result["flag"] = CH3_FLAG
                result["violation"] = f"Unauthorized refund of ${amount:g} for order {order_id} logged."

    if challenge_id == "ch10":
        sid = g.sid
        transcript = SESSIONS.setdefault(sid, [])
        if history:
            transcript.append(history[-1])
        transcript.append({"role": "assistant", "content": reply})
        SESSIONS[sid] = transcript[-40:]

    if solved and not is_bonus:
        s = solved_set(g.sid)
        s.add(level_n)
        result["level_complete"] = True
        result["next_level"] = level_n + 1 if level_n < TOTAL_LEVELS else None

    return jsonify(result)


@app.route("/api/self-attest", methods=["POST"])
def self_attest():
    """Level 1 (Misinformation): there's no reliable way to auto-detect a
    hallucination server-side, so this is honor-system."""
    body = request.get_json(force=True) or {}
    level_n = body.get("level")
    lvl = get_level(level_n)
    if not lvl or lvl["challenge_id"] != "ch7":
        return jsonify({"error": "unknown level"}), 400
    s = solved_set(g.sid)
    s.add(level_n)
    return jsonify({"flag": CH7_FLAG, "level_complete": True, "next_level": level_n + 1 if level_n < TOTAL_LEVELS else None})


@app.route("/api/collect", methods=["GET", "POST"])
def collect():
    """XSS exfiltration callback for Level 10."""
    data = request.values.to_dict()
    sid = request.cookies.get("sid")
    app.logger.info("XSS callback received sid=%s data=%s", sid, data)
    if sid:
        CH10_SOLVED.add(sid)
    return ("", 204)


@app.route("/api/ch10-status")
def ch10_status():
    solved = g.sid in CH10_SOLVED
    if solved:
        s = solved_set(g.sid)
        s.add(TOTAL_LEVELS)
    return jsonify({"solved": solved, "flag": CH10_FLAG if solved else None})


@app.route("/api/action-log")
def action_log():
    return jsonify(ACTION_LOG)


@app.route("/api/stats")
def stats():
    count = STATS["count"]
    avg = (STATS["total_latency"] / count) if count else 0
    return jsonify({"total_requests": count, "avg_latency_seconds": round(avg, 3)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
