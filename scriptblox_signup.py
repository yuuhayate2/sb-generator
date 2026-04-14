# scriptblox_signup.py — Kuni Tool · SB Account Generator v2.4
# Deploy on Railway / Render — open http://localhost:5000

import json, os, random, re, string, threading, hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import requests, urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

from turnstile_solver import solve_turnstile_capsolver
from proxy_util import load_proxies, get_random_proxy, parse_proxy

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL  = "https://ukwltgxtfikiprsqflhi.supabase.co"
SUPABASE_KEY  = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"
SB_SIGNUP     = "https://scriptblox.com/api/auth/signup"
MW_DOMAINS    = ["aula.edu.pl", "studyhub.org"]
MW_DOMAIN     = MW_DOMAINS[0]
MW_BASE       = "https://mailwave.dev"
NO_PROXY      = {"http": None, "https": None}
ACCOUNTS_FILE = Path(__file__).parent / "scriptblox_accounts.txt"
PROXIES_FILE  = Path(__file__).parent / "proxies.txt"
WEBHOOK_FILE  = Path(__file__).parent / "webhook.txt"

# ── State ─────────────────────────────────────────────────────────────────────
proxies_list   = load_proxies()
active_webhook = ""
license_valid  = False
current_key    = None
license_record = None
session_lock   = threading.Lock()
file_lock      = threading.Lock()

if WEBHOOK_FILE.exists():
    active_webhook = WEBHOOK_FILE.read_text().strip()

app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

state = {"running": False, "created": 0, "active": 0, "failed": 0, "target": 0, "stop": False}

# ── Supabase helpers ──────────────────────────────────────────────────────────
def supa_hdrs():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}

def fetch_license(key):
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                         params={"license_key": f"eq.{key}", "select": "*"})
        if r.status_code == 200:
            d = r.json()
            return d[0] if d else None
    except:
        pass
    return None

def increment_used(key):
    try:
        rec = fetch_license(key)
        if not rec: return None
        new_val = (rec.get("accounts_used") or 0) + 1
        r = requests.patch(f"{SUPABASE_URL}/rest/v1/licenses", headers={**supa_hdrs(), "Prefer": "return=representation"},
                           params={"license_key": f"eq.{key}"}, json={"accounts_used": new_val})
        return new_val if r.status_code in (200, 201) else None
    except:
        return None

def get_hwid(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

# ── MailWave ──────────────────────────────────────────────────────────────────
def mw_create_session():
    """Create a persistent MailWave session - retry up to 3 times."""
    for attempt in range(3):
        try:
            sess = requests.Session()
            sess.proxies = NO_PROXY
            r = sess.get(f"{MW_BASE}/", timeout=15)
            token = re.search(r'<meta name="csrf-token" content="([^"]+)"', r.text)
            csrf = token.group(1) if token else None
            if not csrf:
                continue
            for _ in range(20):
                alias = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                try:
                    sess.post(f"{MW_BASE}/change",
                        data={"_token": csrf, "name": alias, "domain": MW_DOMAIN},
                        timeout=15)
                    csrf = unquote(sess.cookies.get("XSRF-TOKEN", csrf))
                    r3 = sess.post(f"{MW_BASE}/get_messages",
                        headers={"Content-Type": "application/json", "X-CSRF-TOKEN": csrf},
                        timeout=15)
                    mailbox = r3.json().get("mailbox", "")
                    if MW_DOMAIN in mailbox:
                        print(f"[mw] session ready: {mailbox}")
                        return sess, csrf, mailbox
                except Exception as e:
                    print(f"[mw] alias error: {e}")
        except Exception as e:
            print(f"[mw] session error (attempt {attempt+1}): {e}")
    return None, None, None

# ── MailWave inbox polling ────────────────────────────────────────────────────
def mw_poll_code(mw_sess, csrf, email_addr, timeout=90):
    """Poll MailWave session for ScriptBlox 7-digit code."""
    import time as _t
    deadline = _t.time() + timeout
    seen_ids = set()
    while _t.time() < deadline:
        try:
            fresh_csrf = unquote(mw_sess.cookies.get("XSRF-TOKEN", csrf))
            r = mw_sess.post(f"{MW_BASE}/get_messages",
                headers={"Content-Type": "application/json", "X-CSRF-TOKEN": fresh_csrf},
                timeout=15)
            messages = r.json().get("messages", [])
            print(f"[poll] {len(messages)} messages")
            for msg in messages:
                msg_id = msg.get("id","")
                if msg_id in seen_ids:
                    continue
                sender = (msg.get("from_email","") + msg.get("from","")).lower()
                if "scriptblox" not in sender:
                    seen_ids.add(msg_id)
                    continue
                content = msg.get("content") or msg.get("html") or msg.get("body") or ""
                if isinstance(content, bool): content = ""
                content = str(content)
                match = re.search(r"\b(\d{7})\b", content)
                if match:
                    print(f"[poll] code found: {match.group(1)}")
                    return match.group(1)
                seen_ids.add(msg_id)
        except Exception as e:
            print(f"[poll] error: {e}")
        _t.sleep(1)
    return None

def sb_login(email, password, proxy_r):
    """Login to ScriptBlox and return session cookies in Cookie-Editor format."""
    try:
        s = requests.Session()
        s.headers.update(sb_headers())
        r = s.post("https://scriptblox.com/api/auth/login",
            json={"login": email, "password": password},
            proxies=proxy_r, timeout=20, verify=False)
        if r.status_code != 200:
            return None, None
        all_cookies = []
        for name, val in s.cookies.items():
            all_cookies.append({
                "domain": "scriptblox.com", "hostOnly": True,
                "httpOnly": name == "token", "name": name, "path": "/",
                "sameSite": "strict" if name == "token" else "no_restriction",
                "secure": True, "session": False, "storeId": None, "value": val,
                "expirationDate": (__import__('time').time() + 86400 * 30)
            })
        resp_data = r.json()
        token = resp_data.get("token") or resp_data.get("data", {}).get("token")
        if token and not any(c["name"] == "token" for c in all_cookies):
            all_cookies.append({
                "domain": "scriptblox.com", "hostOnly": True, "httpOnly": True,
                "name": "token", "path": "/", "sameSite": "strict",
                "secure": True, "session": False, "storeId": None, "value": token,
                "expirationDate": (__import__('time').time() + 86400 * 30)
            })
        return all_cookies, token
    except:
        return None, None

# ── Upload cookies to sourceb.in ──────────────────────────────────────────────
def upload_cookies_online(cookies_json):
    try:
        cookie_str = "-- EXPORTED FROM COOKIE-EDITOR, ACCEPTED\n\n" + json.dumps(cookies_json, indent=4)
        r = requests.post("https://sourceb.in/api/bins",
            json={"files": [{"content": cookie_str, "languageId": 64}]},
            headers={"Content-Type": "application/json"},
            proxies=NO_PROXY, timeout=15)
        if r.status_code in (200, 201):
            key = r.json().get("key")
            if key:
                return f"https://cdn.sourceb.in/bins/{key}/0"
    except:
        pass
    return None

# ── Discord Webhook ───────────────────────────────────────────────────────────
def send_webhook(username, password, email, cookies_json=None, verified=False):
    if not active_webhook: return
    try:
        from datetime import timedelta
        post_date = datetime.now(timezone.utc) + timedelta(days=7)
        can_post = post_date.strftime("%A, %B %-d, %Y at %I:%M %p") if verified else "—"
        online_url = upload_cookies_online(cookies_json) if cookies_json else None

        desc_lines = []
        if verified:
            desc_lines.append(f"\U0001f4c5 **Can post after:** {can_post}")
        if online_url:
            desc_lines.append(f"\U0001f517 **Cookies online:** {online_url}")
        if cookies_json:
            desc_lines.append(f"\U0001f4ce Import `cookies.json` into Cookie-Editor:")

        embed = {
            "title": "\u2705 ScriptBlox Account Ready!" if verified else "\U0001f3af ScriptBlox Account Generated",
            "color": 0x57F287 if verified else 0x00ffcc,
            "description": "\n".join(desc_lines),
            "footer": {"text": "sblox gen"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if cookies_json:
            import io
            cookie_str = "-- EXPORTED FROM COOKIE-EDITOR, ACCEPTED\n\n" + json.dumps(cookies_json, indent=4)
            files = {"file": ("cookies.json", io.BytesIO(cookie_str.encode()), "application/json")}
            payload = {"payload_json": json.dumps({"embeds": [embed]})}
            requests.post(active_webhook, data=payload, files=files, proxies=NO_PROXY, timeout=15)
        else:
            requests.post(active_webhook, json={"embeds": [embed]}, proxies=NO_PROXY, timeout=10)
    except Exception as e:
        print("WEBHOOK ERROR:", e)

# ── Utils ─────────────────────────────────────────────────────────────────────
def rand_username(): return "Kuni" + "".join(random.choices(string.ascii_letters + string.digits, k=10))
def rand_password():  return "".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=14))

def proxy_to_requests(proxy):
    if not proxy: return None
    server = proxy.get("server", "")
    user, pw = proxy.get("username",""), proxy.get("password","")
    if user:
        host = re.sub(r'^https?://', '', server)
        return {"http": f"http://{user}:{pw}@{host}", "https": f"http://{user}:{pw}@{host}"}
    return {"http": server, "https": server}

def sb_headers():
    return {
        "Content-Type": "application/json", "Accept": "application/json",
        "Origin": "https://scriptblox.com", "Referer": "https://scriptblox.com/signup",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36",
    }

def log_emit(msg, tag="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    socketio.emit("log", {"msg": f"[{ts}] {msg}", "tag": tag})
    socketio.emit("stats", {k: state[k] for k in ("created","active","failed","target")})

# ── Core account creation ─────────────────────────────────────────────────────
def create_account(slot):
    global current_key, license_record
    if state["stop"]: return

    if license_record:
        limit = license_record.get("accounts_limit", 0)
        if limit < 9999:
            rec = fetch_license(current_key)
            if rec:
                used = rec.get("accounts_used") or 0
                if used >= limit:
                    state["stop"] = True
                    log_emit(f"Account limit reached ({used}/{limit}) — stopping", "err")
                    socketio.emit("limit_reached", {"used": used, "limit": limit})
                    return

    username = rand_username()
    password = rand_password()
    proxy    = get_random_proxy(proxies_list)
    proxy_r  = proxy_to_requests(proxy)

    captcha = solve_turnstile_capsolver()
    mw_sess, mw_csrf, email_addr = mw_create_session()

    if not email_addr or not captcha:
        state["failed"] += 1
        log_emit(f"[#{slot}] Setup failed (email/captcha)", "err")
        return

    log_emit(f"[#{slot}] [✓] Starting...", "dim")
    log_emit(f"[#{slot}] [✓] Loading signup page...", "dim")
    log_emit(f"[#{slot}] [✓] Solving Turnstile captcha...", "dim")

    try:
        signup_sess = requests.Session()
        signup_sess.headers.update(sb_headers())
        r = signup_sess.post(SB_SIGNUP, json={
            "email": email_addr, "username": username,
            "password": password, "repeatPassword": password,
            "terms": True, "captcha": captcha,
        }, proxies=proxy_r, timeout=30, verify=False)
        resp = r.json()
    except:
        state["failed"] += 1
        log_emit(f"[#{slot}] Request error", "err")
        return

    if resp.get("error") or (isinstance(resp.get("statusCode"), int) and resp["statusCode"] >= 400):
        state["failed"] += 1
        log_emit(f"[#{slot}] Signup failed: {resp.get('message','')}", "err")
        return

    signup_token = resp.get("token") or resp.get("data", {}).get("token", "")
    print(f"[signup] token: {signup_token[:30] if signup_token else 'none'}")

    log_emit(f"[#{slot}] [✓] Creating account...", "dim")
    log_emit(f"[#{slot}] [✓] Navigating to verification...", "dim")
    log_emit(f"[#{slot}] [✓] Waiting for verification email...", "dim")

    verify_code = mw_poll_code(mw_sess, mw_csrf, email_addr, timeout=90)

    verified = False
    if verify_code:
        log_emit(f"[#{slot}] [✓] Entering verification code...", "dim")
        try:
            vr = signup_sess.post("https://scriptblox.com/api/auth/verify",
                json={"vCode": int(verify_code)},
                proxies=proxy_r, timeout=20, verify=False)
            vdata = vr.json() if vr.content else {}
            print(f"[verify] response: {vdata}")
            if vdata.get("message") == False and vdata.get("token"):
                verified = True
                signup_sess.cookies.set("token", vdata["token"], domain="scriptblox.com")
            else:
                log_emit(f"[#{slot}] Verify failed: {vdata}", "err")
        except Exception as e:
            log_emit(f"[#{slot}] Verify error: {e}", "err")
    else:
        log_emit(f"[#{slot}] Code timeout — saving unverified", "dim")

    cookies_data = None
    if verified:
        import time as _time
        _time.sleep(2)
        log_emit(f"[#{slot}] [✓] Fetching cookies...", "dim")
        cookies_data = []
        import time as _t2
        for name, value in signup_sess.cookies.items():
            cookies_data.append({
                "domain": "scriptblox.com", "hostOnly": True,
                "httpOnly": name == "token", "name": name, "path": "/",
                "sameSite": "strict" if name == "token" else "no_restriction",
                "secure": True, "session": False, "storeId": None, "value": value,
                "expirationDate": _t2.time() + 86400 * 30
            })
        if not cookies_data:
            cookies_data, _ = sb_login(email_addr, password, proxy_r)

    with session_lock:
        increment_used(current_key)

    account = {"username": username, "password": password, "email": email_addr, "verified": verified}
    if cookies_data:
        account["cookies"] = cookies_data

    with file_lock:
        with open(ACCOUNTS_FILE, "a") as f:
            f.write(json.dumps(account) + "\n")

    send_webhook(username, password, email_addr, cookies_json=cookies_data, verified=verified)
    state["created"] += 1
    if verified and cookies_data:
        log_emit(f"[#{slot}] [►] Done!", "ok")
    elif verified:
        log_emit(f"[#{slot}] [►] Done! (no cookies)", "ok")
    else:
        log_emit(f"[#{slot}] [►] Done! (unverified)", "warn")

def run_generator(count, concurrent):
    sem = threading.Semaphore(concurrent)
    threads = []
    def worker(slot):
        with sem:
            if not state["stop"]:
                state["active"] += 1
                create_account(slot)
                state["active"] -= 1
    for i in range(count):
        if state["stop"]: break
        t = threading.Thread(target=worker, args=(i+1,), daemon=True)
        threads.append(t); t.start()
    for t in threads: t.join()
    state["running"] = False
    log_emit(f"Done — {state['created']}/{count} accounts created.", "ok")
    socketio.emit("done", {"created": state["created"], "total": count})

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/verify-key", methods=["POST"])
def verify():
    global license_valid, current_key, license_record
    try:
        key = (request.json or {}).get("key","").strip()
        if not key: return jsonify({"valid": False, "error": "no_key"})
        client_hwid = (request.json or {}).get("hwid", "").strip()
        hwid = client_hwid if client_hwid else get_hwid(request.remote_addr)
        rec  = fetch_license(key)
        if not rec:  return jsonify({"valid": False, "error": "not_found"})
        if rec.get("status") != "active": return jsonify({"valid": False, "error": "disabled"})
        exp = rec.get("expiry_date")
        if exp and datetime.fromisoformat(exp.replace("Z","")) < datetime.now():
            return jsonify({"valid": False, "error": "expired"})
        if rec.get("hwid") and rec["hwid"] != hwid:
            return jsonify({"valid": False, "error": "hwid_mismatch"})
        if not rec.get("hwid"):
            requests.patch(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                           params={"license_key": f"eq.{key}"}, json={"hwid": hwid})
        limit = rec.get("accounts_limit", 0)
        used  = rec.get("accounts_used", 0) or 0
        if limit < 9999 and used >= limit:
            return jsonify({"valid": False, "error": "limit_reached", "used": used, "limit": limit})
        license_valid = True; current_key = key; license_record = rec
        return jsonify({
            "valid": True,
            "plan":  "Unlimited" if limit >= 9999 else f"{limit} accounts",
            "used":  used, "limit": limit,
            "accounts_left": None if limit >= 9999 else (limit - used),
            "is_trial": rec.get("is_trial", False),
        })
    except Exception as e:
        print("VERIFY ERROR:", e)
        return jsonify({"valid": False, "error": "server_error"})

@app.route("/set-proxies", methods=["POST"])
def set_proxies():
    global proxies_list
    if not license_valid: return jsonify({"ok": False, "error": "not_authenticated"})
    try:
        lines = (request.json or {}).get("proxies","").strip().splitlines()
        valid = [l.strip() for l in lines if l.strip() and not l.startswith("#") and parse_proxy(l.strip())]
        PROXIES_FILE.write_text("\n".join(valid))
        proxies_list = valid
        return jsonify({"ok": True, "count": len(valid)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/set-webhook", methods=["POST"])
def set_webhook():
    global active_webhook
    if not license_valid: return jsonify({"ok": False, "error": "not_authenticated"})
    try:
        wh = (request.json or {}).get("webhook","").strip()
        if wh and not wh.startswith("https://discord.com/api/webhooks/"):
            return jsonify({"ok": False, "error": "invalid_webhook"})
        active_webhook = wh
        WEBHOOK_FILE.write_text(wh)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/get-proxies", methods=["GET"])
def get_proxies():
    if not license_valid: return jsonify({"ok": False})
    return jsonify({"ok": True, "count": len(proxies_list)})

@app.route("/get-webhook", methods=["GET"])
def get_webhook():
    if not license_valid: return jsonify({"ok": False})
    return jsonify({"ok": True, "has_webhook": bool(active_webhook)})

@app.route("/claim-trial", methods=["POST"])
def claim_trial():
    try:
        client_hwid = (request.json or {}).get("hwid", "").strip()
        hwid = client_hwid if client_hwid else get_hwid(request.remote_addr)
        r = requests.get(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                         params={"hwid": f"eq.{hwid}", "is_trial": "eq.true", "select": "id,license_key"})
        if r.status_code == 200 and r.json():
            existing = r.json()[0]
            return jsonify({"ok": False, "error": "already_claimed", "key": existing["license_key"]})
        def seg(): return __import__('random').choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6)
        key = "TRIAL-" + "".join(seg()) + "-" + "".join(seg()) + "-" + "".join(seg())
        from datetime import timedelta
        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        body = {
            "license_key": key, "accounts_limit": 1, "accounts_used": 0,
            "expiry_date": expiry, "status": "active", "is_trial": True,
            "hwid": hwid, "note": "free trial",
        }
        r2 = requests.post(f"{SUPABASE_URL}/rest/v1/licenses",
                           headers={**supa_hdrs(), "Prefer": "return=representation"}, json=body)
        if r2.status_code not in (200, 201):
            return jsonify({"ok": False, "error": "db_error"})
        return jsonify({"ok": True, "key": key})
    except Exception as e:
        print("TRIAL ERROR:", e)
        return jsonify({"ok": False, "error": "server_error"})

# ── SocketIO ──────────────────────────────────────────────────────────────────
@socketio.on("get_info")
def on_info():
    emit("info", {"proxies": len(proxies_list), "webhook": bool(active_webhook)})

@socketio.on("start")
def on_start(data):
    global license_record
    if not license_valid or state["running"]: return
    if current_key:
        fresh = fetch_license(current_key)
        if fresh: license_record = fresh
    limit = license_record.get("accounts_limit", 0) if license_record else 0
    used  = (license_record.get("accounts_used") or 0) if license_record else 0
    if limit < 9999 and used >= limit:
        emit("limit_reached", {"used": used, "limit": limit}); return
    count      = int(data.get("count", 10))
    concurrent = int(data.get("concurrent", 10))
    if license_record and limit < 9999:
        remaining = limit - used
        if count > remaining:
            count = remaining
            log_emit(f"Count capped to {remaining} (remaining allowance)", "inf")
    if count <= 0: emit("limit_reached", {"used": used, "limit": limit}); return
    state.update(running=True, stop=False, created=0, active=0, failed=0, target=count)
    emit("started", {"count": count})
    log_emit(f"Starting {count} accounts ({concurrent} concurrent)...", "inf")
    threading.Thread(target=run_generator, args=(count, concurrent), daemon=True).start()

@socketio.on("stop")
def on_stop():
    state["stop"] = True
    emit("stopped")
    log_emit("Stopping...", "inf")


# ── HTML ──────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KUNI · AUTO SB GEN</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #080b0f; --surface: #0e1318; --surface2: #141c24;
    --border: #1c2a38; --border2: #253545;
    --cyan: #00d4ff; --cyan-dim: rgba(0,212,255,0.08); --cyan-glow: rgba(0,212,255,0.18);
    --green: #00e87a; --red: #ff3b5c; --gold: #f5c842; --purple: #7289da;
    --text: #c5d8ea; --muted: #4a6070; --muted2: #2a3a4a;
    --mono: 'Space Mono', monospace; --sans: 'Syne', sans-serif;
    --radius: 10px; --radius-lg: 16px;
  }
  html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--mono); }
  ::-webkit-scrollbar { width: 4px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }
  .lic-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px; background: radial-gradient(ellipse 60% 40% at 50% 0%, rgba(0,212,255,0.06) 0%, transparent 70%), var(--bg); }
  .lic-card { width: 100%; max-width: 480px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: 36px 28px 28px; position: relative; overflow: hidden; }
  .lic-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, var(--cyan), transparent); }
  .lic-logo { font-family: var(--sans); font-size: 36px; font-weight: 800; color: var(--cyan); letter-spacing: 6px; margin-bottom: 4px; }
  .lic-sub { font-size: 10px; letter-spacing: 3px; color: var(--muted); margin-bottom: 32px; }
  .lic-label { font-size: 10px; letter-spacing: 2px; color: var(--muted); margin-bottom: 8px; display: block; }
  .lic-input { width: 100%; padding: 13px 16px; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius); color: var(--cyan); font-family: var(--mono); font-size: 13px; letter-spacing: 2px; outline: none; transition: border-color .2s, box-shadow .2s; margin-bottom: 12px; }
  .lic-input:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px var(--cyan-dim); }
  .lic-input::placeholder { color: var(--muted2); letter-spacing: 1px; }
  .lic-btn { width: 100%; padding: 13px; background: var(--cyan); border: none; border-radius: var(--radius); color: var(--bg); font-family: var(--sans); font-weight: 700; font-size: 13px; letter-spacing: 3px; text-transform: uppercase; cursor: pointer; transition: all .2s; }
  .lic-btn:hover { background: #33dbff; transform: translateY(-1px); box-shadow: 0 8px 24px var(--cyan-glow); }
  .lic-btn.loading { opacity: .7; pointer-events: none; }
  .lic-err { font-size: 11px; min-height: 18px; margin-top: 10px; text-align: center; letter-spacing: .5px; color: var(--red); }
  .price-section { margin-top: 22px; padding-top: 20px; border-top: 1px solid var(--border); }
  .price-title { font-size: 9px; letter-spacing: 3px; color: var(--muted); margin-bottom: 12px; text-align: center; }
  .price-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 16px; }
  .price-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 6px; text-align: center; }
  .price-card.featured { border-color: rgba(0,212,255,.3); background: var(--cyan-dim); }
  .price-name { font-family: var(--sans); font-size: 10px; font-weight: 700; color: var(--text); letter-spacing: 1px; margin-bottom: 4px; }
  .price-limit { font-size: 9px; color: var(--muted); letter-spacing: 1px; margin-bottom: 8px; }
  .price-amt { font-family: var(--sans); font-size: 15px; font-weight: 800; color: var(--cyan); }
  .price-php { font-size: 9px; color: var(--muted); letter-spacing: 1px; margin-top: 2px; }
  .price-dur { font-size: 8px; color: var(--muted); letter-spacing: 1px; margin-top: 2px; }
  .price-card.featured .price-amt { color: var(--green); }
  .discord-section { text-align: center; }
  .discord-label { font-size: 10px; color: var(--muted); letter-spacing: 1.5px; margin-bottom: 10px; }
  .discord-btn { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 11px 22px; background: rgba(114,137,218,.1); border: 1px solid rgba(114,137,218,.4); border-radius: 8px; color: var(--purple); font-family: var(--mono); font-size: 12px; text-decoration: none; transition: all .2s; width: 100%; }
  .discord-btn:hover { background: rgba(114,137,218,.2); border-color: var(--purple); color: #fff; transform: translateY(-1px); }
  .discord-btn strong { color: #fff; }
  .trial-divider { display: flex; align-items: center; gap: 10px; margin: 14px 0; }
  .trial-divider::before, .trial-divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }
  .trial-divider span { font-size: 9px; color: var(--muted); letter-spacing: 2px; }
  .trial-btn { width: 100%; padding: 11px; background: transparent; border: 1px dashed var(--border2); border-radius: var(--radius); color: var(--muted); font-family: var(--sans); font-weight: 700; font-size: 11px; letter-spacing: 2px; text-transform: uppercase; cursor: pointer; transition: all .2s; margin-bottom: 4px; }
  .trial-btn:hover { border-color: var(--green); color: var(--green); background: rgba(0,232,122,.05); }
  .trial-btn.loading { opacity: .6; pointer-events: none; }
  .trial-note { font-size: 9px; color: var(--muted2); text-align: center; letter-spacing: 1px; margin-bottom: 16px; }
  .trial-badge { display: inline-block; font-size: 9px; letter-spacing: 1.5px; padding: 2px 9px; border-radius: 20px; font-weight: 700; border: 1px solid rgba(0,232,122,.4); color: var(--green); background: rgba(0,232,122,.08); margin-left: 6px; }
  .lic-footer { display: flex; justify-content: space-between; font-size: 10px; color: var(--muted); margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--border); }
  .lic-dot { width: 6px; height: 6px; background: var(--muted2); border-radius: 50%; display: inline-block; margin-right: 6px; vertical-align: middle; }
  .lic-dot.active { background: var(--green); box-shadow: 0 0 6px var(--green); animation: pulse-dot 1.4s infinite; }
  .app { min-height: 100vh; max-width: 580px; margin: 0 auto; padding: 20px 16px 40px; display: flex; flex-direction: column; gap: 12px; }
  .hdr { display: flex; align-items: center; gap: 12px; padding: 16px 0 12px; border-bottom: 1px solid var(--border); }
  .hdr-logo { font-family: var(--sans); font-size: 22px; font-weight: 800; color: var(--cyan); letter-spacing: 4px; }
  .hdr-sub { font-size: 10px; color: var(--muted); letter-spacing: 2px; }
  .hdr-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
  .hdr-ver { font-size: 10px; color: var(--muted2); background: var(--surface2); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border); }
  .plan-badge { font-size: 9px; letter-spacing: 1px; color: var(--gold); background: rgba(245,200,66,.08); border: 1px solid rgba(245,200,66,.3); border-radius: 20px; padding: 3px 10px; }
  .status-bar { display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--muted); padding: 6px 0; }
  .status-bar .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--muted2); flex-shrink: 0; }
  .status-bar.running .dot { background: var(--gold); box-shadow: 0 0 6px var(--gold); animation: pulse-dot 1s infinite; }
  .status-bar.done .dot { background: var(--green); }
  .status-bar.stopped .dot, .status-bar.limit .dot { background: var(--red); }
  .status-text { color: var(--text); }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 8px 10px; text-align: center; position: relative; overflow: hidden; }
  .stat::after { content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 2px; border-radius: 0 0 var(--radius) var(--radius); opacity: .6; }
  .stat.s-created::after { background: var(--green); } .stat.s-active::after { background: var(--cyan); } .stat.s-failed::after { background: var(--red); } .stat.s-target::after { background: var(--gold); }
  .stat-val { font-family: var(--sans); font-size: 26px; font-weight: 800; display: block; line-height: 1; }
  .stat-lbl { font-size: 8px; color: var(--muted); letter-spacing: 2px; margin-top: 5px; display: block; }
  .s-created .stat-val { color: var(--green); } .s-active .stat-val { color: var(--cyan); } .s-failed .stat-val { color: var(--red); } .s-target .stat-val { color: var(--gold); }
  .limit-bar-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 16px; }
  .limit-bar-top { display: flex; justify-content: space-between; font-size: 10px; color: var(--muted); margin-bottom: 8px; }
  .limit-bar-top span:last-child { color: var(--text); }
  .limit-bar-track { height: 4px; background: var(--border); border-radius: 4px; overflow: hidden; }
  .limit-bar-fill { height: 100%; background: var(--cyan); border-radius: 4px; transition: width .4s ease; }
  .limit-bar-fill.warn { background: var(--gold); } .limit-bar-fill.danger { background: var(--red); }
  .config-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .config-card-hdr { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; border-bottom: 1px solid var(--border); font-size: 10px; letter-spacing: 2px; color: var(--muted); cursor: pointer; user-select: none; transition: background .15s; }
  .config-card-hdr:hover { background: var(--surface2); }
  .config-card-body { padding: 14px 16px; display: flex; flex-direction: column; gap: 12px; }
  .config-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  .config-field { display: flex; align-items: center; gap: 10px; }
  .config-label { font-size: 10px; letter-spacing: 2px; color: var(--muted); white-space: nowrap; }
  .config-input { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--cyan); font-family: var(--mono); font-size: 13px; padding: 6px 10px; width: 72px; outline: none; }
  .config-input:focus { border-color: var(--cyan); box-shadow: 0 0 0 2px var(--cyan-dim); }
  .panel-wrap { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .panel-label { font-size: 10px; letter-spacing: 2px; color: var(--muted); padding: 8px 12px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; cursor: pointer; user-select: none; }
  .panel-label .badge { font-size: 9px; color: var(--muted2); }
  .panel-label .badge.ok { color: var(--green); }
  .panel-inner { display: none; }
  .panel-inner.open { display: block; }
  .panel-textarea { width: 100%; min-height: 80px; padding: 10px 12px; resize: vertical; background: transparent; border: none; outline: none; color: var(--cyan); font-family: var(--mono); font-size: 11px; line-height: 1.7; }
  .panel-textarea::placeholder { color: var(--muted2); }
  .panel-actions { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-top: 1px solid var(--border); }
  .panel-btn { padding: 5px 14px; background: transparent; border: 1px solid var(--cyan); border-radius: 5px; color: var(--cyan); font-family: var(--sans); font-weight: 700; font-size: 9px; letter-spacing: 2px; cursor: pointer; transition: all .15s; }
  .panel-btn:hover { background: var(--cyan); color: var(--bg); }
  .panel-status { font-size: 10px; color: var(--muted); letter-spacing: 1px; margin-left: auto; }
  .webhook-wrap { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
  .webhook-row { display: flex; align-items: center; gap: 8px; padding: 0 12px; border-bottom: 1px solid var(--border); }
  .webhook-lbl { font-size: 10px; letter-spacing: 2px; color: var(--muted); white-space: nowrap; flex-shrink: 0; }
  .webhook-input { flex: 1; padding: 10px 8px; background: transparent; border: none; outline: none; color: var(--cyan); font-family: var(--mono); font-size: 11px; }
  .webhook-input::placeholder { color: var(--muted2); }
  .run-btn { width: 100%; padding: 15px; border: none; border-radius: var(--radius); font-family: var(--sans); font-weight: 700; font-size: 13px; letter-spacing: 3px; text-transform: uppercase; cursor: pointer; transition: all .2s; }
  .run-btn.idle { background: transparent; border: 1px solid var(--cyan); color: var(--cyan); }
  .run-btn.idle:hover { background: var(--cyan); color: var(--bg); box-shadow: 0 6px 24px var(--cyan-glow); transform: translateY(-1px); }
  .run-btn.stop { background: transparent; border: 1px solid var(--red); color: var(--red); }
  .run-btn.stop:hover { background: rgba(255,59,92,.08); }
  .run-btn.disabled-btn { opacity: .4; pointer-events: none; border: 1px solid var(--muted); color: var(--muted); background: transparent; }
  .limit-banner { background: rgba(255,59,92,.08); border: 1px solid rgba(255,59,92,.3); border-radius: var(--radius); padding: 12px 16px; font-size: 11px; color: var(--red); display: none; align-items: center; gap: 10px; }
  .limit-banner.show { display: flex; }
  .log-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
  .log-header { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 10px; letter-spacing: 2px; color: var(--muted); }
  .log-clear { font-size: 10px; color: var(--muted2); background: none; border: none; cursor: pointer; font-family: var(--mono); padding: 2px 6px; border-radius: 4px; transition: color .2s, background .2s; }
  .log-clear:hover { color: var(--text); background: var(--surface2); }
  .log-box { padding: 10px 14px; height: 220px; overflow-y: auto; font-size: 11px; line-height: 1.8; }
  .log-line { display: flex; gap: 8px; }
  .log-ts { color: var(--muted2); flex-shrink: 0; }
  .ok .log-msg { color: var(--green); } .err .log-msg { color: var(--red); } .dim .log-msg { color: var(--muted); } .inf .log-msg { color: var(--cyan); }
  .footer { display: flex; justify-content: space-between; font-size: 10px; color: var(--muted2); padding-top: 4px; }
  .footer a { color: var(--muted2); text-decoration: none; } .footer a:hover { color: var(--cyan); }
  @media (max-width: 480px) { .stats { grid-template-columns: repeat(2, 1fr); } .price-grid { grid-template-columns: 1fr; } }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
  @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
  .animate-in { animation: fadeIn .3s ease forwards; }
</style>
</head>
<body>
<div id="app"></div>
<script>
let licenseInfo = null;
const ERR_MAP = {
  not_found:'invalid license key — contact Kuni',disabled:'this license has been disabled',
  expired:'license has expired — contact Kuni',hwid_mismatch:'this key is bound to another machine',
  limit_reached:'account limit reached — upgrade your plan',server_error:'server error — try again later',
};

async function getDeviceFingerprint() {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline='top'; ctx.font='14px Arial';
    ctx.fillStyle='#f60'; ctx.fillRect(125,1,62,20);
    ctx.fillStyle='#069'; ctx.fillText('kuni-fp',2,15);
    ctx.fillStyle='rgba(102,204,0,0.7)'; ctx.fillText('kuni-fp',4,17);
    const raw = [navigator.userAgent,navigator.language,screen.width+'x'+screen.height,
      screen.colorDepth,new Date().getTimezoneOffset(),navigator.hardwareConcurrency||0,
      navigator.platform,navigator.maxTouchPoints||0,canvas.toDataURL().slice(-64)].join('|');
    const buf = await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  } catch {
    let id=localStorage.getItem('_did');
    if(!id){id=Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2);localStorage.setItem('_did',id);}
    return id;
  }
}

async function claimTrial() {
  const btn=document.getElementById('trialBtn'),err=document.getElementById('licErr');
  btn.classList.add('loading'); btn.textContent='Claiming...';
  err.textContent=''; err.style.color='var(--muted)';
  try {
    const hwid=await getDeviceFingerprint();
    const r=await fetch('/claim-trial',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hwid})});
    const d=await r.json();
    if(d.ok){
      err.style.color='var(--green)'; err.textContent='trial claimed! verifying...';
      const input=document.getElementById('licInput');
      if(input) input.value=d.key;
      setTimeout(async()=>{
        const vr=await fetch('/verify-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:d.key,hwid})});
        const vd=await vr.json();
        if(vd.valid){localStorage.setItem('license',d.key);licenseInfo=vd;showMainApp();}
      },800);
    } else if(d.error==='already_claimed'){
      err.style.color='var(--gold)'; err.textContent='device already has a trial — enter your key above';
      if(document.getElementById('licInput')) document.getElementById('licInput').value=d.key;
      btn.classList.remove('loading'); btn.textContent='🎁 Get Free Trial — 1 account';
    } else {
      err.style.color='var(--red)'; err.textContent='failed to claim trial — try again';
      btn.classList.remove('loading'); btn.textContent='🎁 Get Free Trial — 1 account';
    }
  } catch { err.style.color='var(--red)'; err.textContent='server error'; btn.classList.remove('loading'); btn.textContent='🎁 Get Free Trial — 1 account'; }
}

function showLicenseScreen() {
  document.getElementById('app').innerHTML=`
    <div class="lic-wrap animate-in"><div class="lic-card">
      <div class="lic-logo">KUNI</div>
      <div class="lic-sub">Auto SB Gen &nbsp;·&nbsp; v2.4</div>
      <span class="lic-label">LICENSE KEY</span>
      <input class="lic-input" id="licInput" type="text" placeholder="KUNI-XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false">
      <button class="lic-btn" id="licBtn" onclick="doLogin()">Verify License</button>
      <div class="lic-err" id="licErr"></div>
      <div class="trial-divider"><span>OR</span></div>
      <button class="trial-btn" id="trialBtn" onclick="claimTrial()">🎁 Get Free Trial — 1 account</button>
      <div class="trial-note">1 free trial per device · 1 account · HWID locked</div>
      <div class="price-section">
        <div class="price-title">PRICING</div>
        <div class="price-grid">
          <div class="price-card"><div class="price-name">BASIC</div><div class="price-limit">100 accounts</div><div class="price-amt">$59.99</div><div class="price-php">≈ ₱3,389</div><div class="price-dur">30 days</div></div>
          <div class="price-card featured"><div class="price-name">PRO</div><div class="price-limit">500 accounts</div><div class="price-amt">$249.99</div><div class="price-php">≈ ₱14,124</div><div class="price-dur">30 days</div></div>
          <div class="price-card"><div class="price-name">UNLIMITED</div><div class="price-limit">no limit</div><div class="price-amt">$399.99</div><div class="price-php">≈ ₱22,599</div><div class="price-dur">60 days</div></div>
        </div>
        <div class="discord-section">
          <div class="discord-label">join our server to purchase</div>
          <a class="discord-btn" href="https://discord.com/users/1482325142104178708" target="_blank">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
            DM <strong>Kuni</strong> to purchase
          </a>
        </div>
      </div>
      <div class="lic-footer"><span><span class="lic-dot" id="connDot"></span>kuni tool</span><span>v2.4</span></div>
    </div></div>`;
  document.getElementById('licInput').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
}

async function doLogin() {
  const key=document.getElementById('licInput').value.trim();
  const err=document.getElementById('licErr'),btn=document.getElementById('licBtn'),dot=document.getElementById('connDot');
  if(!key){err.style.color='#f5c842';err.textContent='please enter a license key';return;}
  btn.classList.add('loading');btn.textContent='Verifying...';
  err.style.color='#4a6070';err.textContent='connecting to license server...';
  dot&&dot.classList.add('active');
  try {
    const hwid=await getDeviceFingerprint();
    const res=await fetch('/verify-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key,hwid})});
    const data=await res.json();
    if(data.valid){localStorage.setItem('license',key);licenseInfo=data;err.style.color='#00e87a';err.textContent='license valid — loading...';setTimeout(showMainApp,600);}
    else{btn.classList.remove('loading');btn.textContent='Verify License';err.style.color='#ff3b5c';err.textContent=ERR_MAP[data.error]||'invalid license — contact Kuni';dot&&dot.classList.remove('active');}
  } catch{btn.classList.remove('loading');btn.textContent='Verify License';err.style.color='#ff3b5c';err.textContent='server error — try again';dot&&dot.classList.remove('active');}
}

function showMainApp() {
  const planLabel=licenseInfo?licenseInfo.plan:'—';
  const isUnlimited=licenseInfo&&licenseInfo.limit>=9999;
  document.getElementById('app').innerHTML=`
    <div class="app animate-in">
      <div class="hdr">
        <div><div class="hdr-logo">KUNI</div><div class="hdr-sub">AUTO SB GEN</div></div>
        <div class="hdr-right">
          <span class="plan-badge">${planLabel}</span>${licenseInfo&&licenseInfo.is_trial?'<span class="trial-badge">TRIAL</span>':''}
          <div class="hdr-ver">v2.4</div>
        </div>
      </div>
      <div class="status-bar idle" id="statusBar"><span class="dot"></span><span class="status-text" id="statusText">idle — ready</span></div>
      <div class="stats">
        <div class="stat s-created"><span class="stat-val" id="s-created">0</span><span class="stat-lbl">CREATED</span></div>
        <div class="stat s-active"><span class="stat-val" id="s-active">0</span><span class="stat-lbl">ACTIVE</span></div>
        <div class="stat s-failed"><span class="stat-val" id="s-failed">0</span><span class="stat-lbl">FAILED</span></div>
        <div class="stat s-target"><span class="stat-val" id="s-target">0</span><span class="stat-lbl">TARGET</span></div>
      </div>
      ${!isUnlimited?`<div class="limit-bar-wrap"><div class="limit-bar-top"><span>ACCOUNT USAGE</span><span id="limitText">—</span></div><div class="limit-bar-track"><div class="limit-bar-fill" id="limitBar" style="width:0%"></div></div></div>`:''}
      <div class="limit-banner" id="limitBanner">⚠ Account limit reached — contact Kuni to upgrade.</div>
      <div class="config-card">
        <div class="config-card-hdr" onclick="toggleConfig()"><span>CONFIG</span><span id="cfgToggle" style="font-size:9px;letter-spacing:2px">▲ HIDE</span></div>
        <div class="config-card-body" id="cfgBody">
          <div class="config-row">
            <div class="config-field"><span class="config-label">COUNT</span><input class="config-input" type="number" id="count" value="10" min="1" max="9999"></div>
            <div class="config-field"><span class="config-label">CONCURRENT</span><input class="config-input" type="number" id="concurrent" value="10" min="1" max="50"></div>
          </div>
          <div class="panel-wrap">
            <div class="panel-label" onclick="togglePanel('proxyPanel')"><span>PROXIES</span><span class="badge" id="proxyBadge">loading...</span></div>
            <div class="panel-inner" id="proxyPanel">
              <textarea class="panel-textarea" id="proxyTA" placeholder="paste proxies here — clears after save&#10;host:port, host:port:user:pass, http://user:pass@host:port"></textarea>
              <div class="panel-actions"><button class="panel-btn" onclick="saveProxies()">SAVE</button><span class="panel-status" id="proxySt"></span></div>
            </div>
          </div>
          <div class="webhook-wrap">
            <div class="webhook-row"><span class="webhook-lbl">WEBHOOK</span><input class="webhook-input" id="webhookInput" type="text" placeholder="https://discord.com/api/webhooks/..."></div>
            <div class="panel-actions"><button class="panel-btn" onclick="saveWebhook()">SAVE</button><span class="panel-status" id="webhookSt"></span></div>
          </div>
        </div>
      </div>
      <button class="run-btn idle" id="mainBtn" onclick="toggle()">Run Generator</button>
      <div class="log-wrap">
        <div class="log-header"><span>LOG OUTPUT</span><button class="log-clear" onclick="clearLog()">clear</button></div>
        <div class="log-box" id="logBox"></div>
      </div>
      <div class="footer"><span>kuni tool</span><a href="#" onclick="doLogout();return false;">logout</a></div>
    </div>`;
  loadSavedConfig(); updateLimitBar(); initSocket();
}

let cfgOpen=true;
function toggleConfig(){cfgOpen=!cfgOpen;document.getElementById('cfgBody').style.display=cfgOpen?'flex':'none';document.getElementById('cfgToggle').textContent=cfgOpen?'▲ HIDE':'▼ SHOW';}
function togglePanel(id){document.getElementById(id).classList.toggle('open');}

async function loadSavedConfig(){
  try{const r=await fetch('/get-proxies');const d=await r.json();if(d.ok){const b=document.getElementById('proxyBadge');b.textContent=d.count>0?d.count+' loaded':'none';b.className='badge'+(d.count>0?' ok':'');}}catch{}
  try{const r=await fetch('/get-webhook');const d=await r.json();if(d.ok&&d.has_webhook){const st=document.getElementById('webhookSt');if(st){st.style.color='var(--green)';st.textContent='webhook set ✓';}}}catch{}
}

async function saveProxies(){
  const text=document.getElementById('proxyTA').value,st=document.getElementById('proxySt');
  st.style.color='var(--muted)';st.textContent='saving...';
  try{const r=await fetch('/set-proxies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proxies:text})});const d=await r.json();
    if(d.ok){st.style.color='var(--green)';st.textContent=d.count+' proxies saved ✓';document.getElementById('proxyTA').value='';const b=document.getElementById('proxyBadge');b.textContent=d.count+' loaded';b.className='badge'+(d.count>0?' ok':'');setTimeout(()=>togglePanel('proxyPanel'),800);}
    else{st.style.color='var(--red)';st.textContent=d.error||'error';}}catch{st.style.color='var(--red)';st.textContent='request failed';}
}

async function saveWebhook(){
  const wh=document.getElementById('webhookInput').value.trim(),st=document.getElementById('webhookSt');
  st.style.color='var(--muted)';st.textContent='saving...';
  try{const r=await fetch('/set-webhook',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({webhook:wh})});const d=await r.json();
    if(d.ok){st.style.color='var(--green)';st.textContent=wh?'webhook set ✓':'cleared';}
    else{st.style.color='var(--red)';st.textContent=d.error==='invalid_webhook'?'invalid discord url':(d.error||'error');}}catch{st.style.color='var(--red)';st.textContent='request failed';}
}

function updateLimitBar(){
  if(!licenseInfo||licenseInfo.limit>=9999)return;
  const wrap=document.querySelector('.limit-bar-wrap');if(!wrap)return;
  const used=licenseInfo.limit-(licenseInfo.accounts_left??0),limit=licenseInfo.limit;
  const pct=Math.min(100,Math.round(used/limit*100));
  const fill=document.getElementById('limitBar');
  if(fill){fill.style.width=pct+'%';fill.className='limit-bar-fill'+(pct>=90?' danger':pct>=70?' warn':'');}
  const txt=document.getElementById('limitText');if(txt)txt.textContent=`${used} / ${limit} (${100-pct}% left)`;
}

function showLimitReached(used,limit){
  const b=document.getElementById('limitBanner');if(b)b.classList.add('show');
  const btn=document.getElementById('mainBtn');if(btn){btn.className='run-btn disabled-btn';btn.textContent='Limit Reached';}
  setStatus('limit',`limit reached — ${used}/${limit} used`);
}
function setStatus(mode,text){const bar=document.getElementById('statusBar');if(bar){bar.className='status-bar '+mode;document.getElementById('statusText').textContent=text;}}
function clearLog(){const b=document.getElementById('logBox');if(b)b.innerHTML='';}
function doLogout(){localStorage.removeItem('license');location.reload();}

function initSocket(){
  const socket=io();let running=false;
  window.toggle=function(){if(running)socket.emit('stop');else{const count=parseInt(document.getElementById('count').value)||10;const concurrent=parseInt(document.getElementById('concurrent').value)||10;socket.emit('start',{count,concurrent});}};
  socket.on('started',d=>{running=true;const btn=document.getElementById('mainBtn');btn.className='run-btn stop';btn.textContent='■  Stop';setStatus('running','running — '+d.count+' accounts');});
  socket.on('stopped',()=>{running=false;const btn=document.getElementById('mainBtn');btn.className='run-btn idle';btn.textContent='Run Generator';setStatus('stopped','stopped');});
  socket.on('done',d=>{running=false;const btn=document.getElementById('mainBtn');btn.className='run-btn idle';btn.textContent='Run Generator';setStatus('done','done — '+d.created+'/'+d.total+' created');});
  socket.on('stats',d=>{
    document.getElementById('s-created').textContent=d.created;
    document.getElementById('s-active').textContent=d.active;
    document.getElementById('s-failed').textContent=d.failed;
    document.getElementById('s-target').textContent=d.target;
    if(licenseInfo&&licenseInfo.limit<9999){
      const used=(licenseInfo.used||0)+d.created;const pct=Math.min(100,Math.round(used/licenseInfo.limit*100));
      const fill=document.getElementById('limitBar');if(fill){fill.style.width=pct+'%';fill.className='limit-bar-fill'+(pct>=90?' danger':pct>=70?' warn':'');}
      const txt=document.getElementById('limitText');if(txt)txt.textContent=`${used} / ${licenseInfo.limit} (${Math.max(0,100-pct)}% left)`;
    }
  });
  socket.on('log',d=>{const box=document.getElementById('logBox');if(!box)return;const line=document.createElement('div');line.className='log-line '+(d.tag||'dim');const msg=d.msg||'';const m=msg.match(/^\[(\d{2}:\d{2}:\d{2})\]\s*(.*)/s);if(m)line.innerHTML=`<span class="log-ts">${m[1]}</span><span class="log-msg">${m[2]}</span>`;else line.innerHTML=`<span class="log-msg">${msg}</span>`;box.appendChild(line);box.scrollTop=box.scrollHeight;});
  socket.on('limit_reached',d=>{running=false;showLimitReached(d.used,d.limit);});
}

const savedKey=localStorage.getItem('license');
if(savedKey){
  getDeviceFingerprint().then(hwid=>{
    fetch('/verify-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:savedKey,hwid})})
      .then(r=>r.json()).then(data=>{if(data.valid){licenseInfo=data;showMainApp();}else{localStorage.removeItem('license');showLicenseScreen();}})
      .catch(()=>showLicenseScreen());
  });
}else{showLicenseScreen();}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[KUNI] v2.4 running on http://localhost:{port}\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
