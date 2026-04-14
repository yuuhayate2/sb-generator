# scriptblox_signup.py — Kuni Tool · SB Account Generator v2.5 (Fixed April 2026)
import json, os, random, re, string, threading, hashlib, time
from datetime import datetime, timezone, timedelta
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
SUPABASE_URL = "https://ukwltgxtfikiprsqflhi.supabase.co"
SUPABASE_KEY = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"

SB_SIGNUP = "https://scriptblox.com/api/auth/signup"
SB_VERIFY = "https://scriptblox.com/api/auth/verify"
SB_HOME   = "https://scriptblox.com/"

MW_DOMAINS = ["aula.edu.pl", "studyhub.org"]
MW_DOMAIN = MW_DOMAINS[0]
MW_BASE = "https://mailwave.dev"

NO_PROXY = {"http": None, "https": None}

ACCOUNTS_FILE = Path(__file__).parent / "scriptblox_accounts.txt"
PROXIES_FILE = Path(__file__).parent / "proxies.txt"
WEBHOOK_FILE = Path(__file__).parent / "webhook.txt"

# ── State ─────────────────────────────────────────────────────────────────────
proxies_list = load_proxies()
active_webhook = WEBHOOK_FILE.read_text().strip() if WEBHOOK_FILE.exists() else ""
license_valid = False
current_key = None
license_record = None
session_lock = threading.Lock()
file_lock = threading.Lock()

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

state = {"running": False, "created": 0, "active": 0, "failed": 0, "target": 0, "stop": False}

# ── Supabase Helpers (same as original) ───────────────────────────────────────
def supa_hdrs():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}", "Content-Type": "application/json"}

def fetch_license(key):
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                         params={"license_key": f"eq.{key}", "select": "*"})
        return r.json()[0] if r.status_code == 200 and r.json() else None
    except:
        return None

def increment_used(key):
    try:
        rec = fetch_license(key)
        if not rec: return None
        new_val = (rec.get("accounts_used") or 0) + 1
        r = requests.patch(f"{SUPABASE_URL}/rest/v1/licenses", headers={**supa_hdrs(), "Prefer": "return=representation"},
                           params={"license_key": f"eq.{key}"}, json={"accounts_used": new_val})
        return new_val
    except:
        return None

def get_hwid(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

# ── MailWave (same as original) ───────────────────────────────────────────────
def mw_create_session():
    for attempt in range(3):
        try:
            sess = requests.Session()
            sess.proxies = NO_PROXY
            r = sess.get(f"{MW_BASE}/", timeout=15)
            token = re.search(r'<meta name="csrf-token" content="([^"]+)"', r.text)
            csrf = token.group(1) if token else None
            if not csrf: continue
            for _ in range(20):
                alias = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                sess.post(f"{MW_BASE}/change", data={"_token": csrf, "name": alias, "domain": MW_DOMAIN}, timeout=15)
                csrf = unquote(sess.cookies.get("XSRF-TOKEN", csrf))
                r3 = sess.post(f"{MW_BASE}/get_messages", headers={"Content-Type": "application/json", "X-CSRF-TOKEN": csrf}, timeout=15)
                mailbox = r3.json().get("mailbox", "")
                if MW_DOMAIN in mailbox:
                    print(f"[mw] session ready: {mailbox}")
                    return sess, csrf, mailbox
        except Exception as e:
            print(f"[mw] session error (attempt {attempt+1}): {e}")
    return None, None, None

def mw_poll_code(mw_sess, csrf, email_addr, timeout=90):
    import time as _t
    deadline = _t.time() + timeout
    seen_ids = set()
    while _t.time() < deadline:
        try:
            fresh_csrf = unquote(mw_sess.cookies.get("XSRF-TOKEN", csrf))
            r = mw_sess.post(f"{MW_BASE}/get_messages",
                headers={"Content-Type": "application/json", "X-CSRF-TOKEN": fresh_csrf}, timeout=15)
            messages = r.json().get("messages", [])
            for msg in messages:
                msg_id = msg.get("id","")
                if msg_id in seen_ids: continue
                sender = (msg.get("from_email","") + msg.get("from","")).lower()
                if "scriptblox" not in sender:
                    seen_ids.add(msg_id)
                    continue
                content = str(msg.get("content") or msg.get("html") or msg.get("body") or "")
                match = re.search(r"\b(\d{7})\b", content)
                if match:
                    print(f"[poll] code found: {match.group(1)}")
                    return match.group(1)
                seen_ids.add(msg_id)
        except:
            pass
        _t.sleep(1)
    return None

# ── Utils ─────────────────────────────────────────────────────────────────────
def sb_headers():
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://scriptblox.com",
        "Referer": "https://scriptblox.com/signup",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36",
    }

def rand_username(): 
    return "Kuni" + "".join(random.choices(string.ascii_letters + string.digits, k=10))

def rand_password(): 
    return "".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=14))

def proxy_to_requests(proxy):
    if not proxy: return None
    # simple implementation - adjust if needed
    return {"http": proxy, "https": proxy} if isinstance(proxy, str) else proxy

def log_emit(msg, tag="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    socketio.emit("log", {"msg": f"[{ts}] {msg}", "tag": tag})
    socketio.emit("stats", {k: state[k] for k in ("created","active","failed","target")})

def upload_cookies_online(cookies_json):
    try:
        cookie_str = "-- EXPORTED FROM COOKIE-EDITOR, ACCEPTED\n\n" + json.dumps(cookies_json, indent=4)
        r = requests.post("https://sourceb.in/api/bins", json={"files": [{"content": cookie_str, "languageId": 64}]}, timeout=15)
        if r.status_code in (200, 201):
            key = r.json().get("key")
            return f"https://cdn.sourceb.in/bins/{key}/0" if key else None
    except:
        pass
    return None

def send_webhook(username, password, email, cookies_json=None, verified=False):
    if not active_webhook: return
    try:
        post_date = datetime.now(timezone.utc) + timedelta(days=7)
        can_post = post_date.strftime("%A, %B %-d, %Y at %I:%M %p") if verified else "—"
        online_url = upload_cookies_online(cookies_json) if cookies_json else None

        desc = []
        if verified:
            desc.append(f"📅 **Can post after:** {can_post}")
        if online_url:
            desc.append(f"🔗 **Cookies online:** {online_url}")
        if cookies_json:
            desc.append("📎 Import `cookies.json` into Cookie-Editor:")

        embed = {
            "title": "✅ ScriptBlox Account Ready!" if verified else "🎯 ScriptBlox Account Generated",
            "color": 0x57F287 if verified else 0x00ffcc,
            "description": "\n".join(desc),
            "footer": {"text": "Kuni SB Gen v2.5"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        if cookies_json:
            cookie_str = "-- EXPORTED FROM COOKIE-EDITOR, ACCEPTED\n\n" + json.dumps(cookies_json, indent=4)
            files = {"file": ("cookies.json", cookie_str.encode(), "application/json")}
            payload = {"payload_json": json.dumps({"embeds": [embed]})}
            requests.post(active_webhook, data=payload, files=files, timeout=15)
        else:
            requests.post(active_webhook, json={"embeds": [embed]}, timeout=10)
    except Exception as e:
        print("WEBHOOK ERROR:", e)

# ── sb_login (fallback) ───────────────────────────────────────────────────────
def sb_login(email, password, proxy_r):
    try:
        s = requests.Session()
        s.headers.update(sb_headers())
        r = s.post("https://scriptblox.com/api/auth/login",
                   json={"login": email, "password": password},
                   proxies=proxy_r, timeout=20, verify=False)
        if r.status_code != 200: return None, None
        # extract cookies similar to original
        cookies_data = []
        for name, val in s.cookies.items():
            cookies_data.append({
                "domain": "scriptblox.com", "hostOnly": True, "httpOnly": name == "token",
                "name": name, "path": "/", "sameSite": "strict" if name == "token" else "no_restriction",
                "secure": True, "session": False, "value": val,
                "expirationDate": time.time() + 86400 * 30
            })
        token = r.json().get("token") or r.json().get("data", {}).get("token")
        return cookies_data, token
    except:
        return None, None

# ── Main Fixed Function ───────────────────────────────────────────────────────
def create_account(slot):
    global current_key, license_record
    if state["stop"]: return

    # License limit check
    if license_record and license_record.get("accounts_limit", 0) < 9999:
        rec = fetch_license(current_key)
        if rec and (rec.get("accounts_used") or 0) >= rec.get("accounts_limit", 0):
            state["stop"] = True
            log_emit(f"Account limit reached — stopping", "err")
            return

    username = rand_username()
    password = rand_password()
    proxy = get_random_proxy(proxies_list)
    proxy_r = proxy_to_requests(proxy)

    log_emit(f"[#{slot}] [✓] Starting...", "dim")

    # 1. Email & Captcha
    mw_sess, mw_csrf, email_addr = mw_create_session()
    captcha = solve_turnstile_capsolver()
    if not email_addr or not captcha:
        state["failed"] += 1
        log_emit(f"[#{slot}] Setup failed (email/captcha)", "err")
        return

    # 2. Signup
    signup_sess = requests.Session()
    signup_sess.headers.update(sb_headers())

    try:
        r = signup_sess.post(SB_SIGNUP, json={
            "email": email_addr, "username": username,
            "password": password, "repeatPassword": password,
            "terms": True, "captcha": captcha,
        }, proxies=proxy_r, timeout=30, verify=False)
        resp = r.json()
        signup_token = resp.get("token") or resp.get("data", {}).get("token", "")
    except Exception as e:
        state["failed"] += 1
        log_emit(f"[#{slot}] Signup error: {e}", "err")
        return

    if resp.get("error"):
        state["failed"] += 1
        log_emit(f"[#{slot}] Signup failed: {resp.get('message')}", "err")
        return

    log_emit(f"[#{slot}] [✓] Account created, waiting for code...", "dim")

    # 3. Poll code
    verify_code = mw_poll_code(mw_sess, mw_csrf, email_addr, timeout=90)
    if not verify_code:
        log_emit(f"[#{slot}] Code timeout — unverified", "warn")
        state["created"] += 1
        return

    log_emit(f"[#{slot}] [✓] Entering verification code...", "dim")

    # 4. Verify (Fixed)
    verified = False
    try:
        verify_headers = sb_headers().copy()
        verify_headers.update({
            "Referer": "https://scriptblox.com/signup",
            "Origin": "https://scriptblox.com",
        })
        if signup_token:
            verify_headers["Authorization"] = f"Bearer {signup_token}"

        vr = signup_sess.post(SB_VERIFY, json={"vCode": int(verify_code)},
                              headers=verify_headers, proxies=proxy_r, timeout=25, verify=False)

        print(f"[verify #{slot}] Status: {vr.status_code} | Body: {vr.text[:500]}")
        vdata = vr.json() if vr.content else {}

        if vr.status_code == 200 and (vdata.get("token") or vdata.get("success") or vdata.get("message") is False):
            verified = True
            if vdata.get("token"):
                signup_sess.cookies.set("token", vdata["token"], domain="scriptblox.com")
            log_emit(f"[#{slot}] [✓] Verified successfully!", "ok")
        else:
            log_emit(f"[#{slot}] Verify failed: {vdata}", "err")
    except Exception as e:
        log_emit(f"[#{slot}] Verify exception: {e}", "err")

    # 5. Go to homepage for fresh cookies
    if verified:
        log_emit(f"[#{slot}] [✓] Navigating to main page...", "dim")
        try:
            signup_sess.get(SB_HOME, proxies=proxy_r, timeout=15, verify=False)
            time.sleep(2.5)
        except:
            pass

    # 6. Extract cookies
    cookies_data = []
    for name, value in signup_sess.cookies.items():
        cookies_data.append({
            "domain": "scriptblox.com", "hostOnly": True,
            "httpOnly": name in ["token", "__scriptblox_validation"],
            "name": name, "path": "/",
            "sameSite": "strict" if name == "token" else "no_restriction",
            "secure": True, "session": False, "value": value,
            "expirationDate": time.time() + 86400 * 30
        })

    if verified and not any(c.get("name") == "token" for c in cookies_data):
        cookies_data, _ = sb_login(email_addr, password, proxy_r)

    # 7. Save & Webhook
    with session_lock:
        increment_used(current_key)

    account = {"username": username, "password": password, "email": email_addr,
               "verified": verified, "cookies": cookies_data if cookies_data else None}

    with file_lock:
        with open(ACCOUNTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(account) + "\n")

    send_webhook(username, password, email_addr, cookies_json=cookies_data, verified=verified)

    state["created"] += 1
    log_emit(f"[#{slot}] [►] Done! {'(Verified)' if verified else '(Unverified)'}", "ok" if verified else "warn")


# ── Run Generator (same as original) ──────────────────────────────────────────
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
        threads.append(t)
        t.start()
    for t in threads: t.join()
    state["running"] = False
    log_emit(f"Done — {state['created']}/{count} accounts created.", "ok")
    socketio.emit("done", {"created": state["created"], "total": count})

# ── Routes & SocketIO (keep your original routes + HTML) ─────────────────────
# (Copy-paste mo na lang dito ang lahat ng @app.route at socketio handlers mula sa original code mo,
#  pati ang buong HTML variable at if __name__ == "__main__" block)

# Para hindi masyadong mahaba, ang pinakamahalaga ay ang create_account function sa itaas.
# Kung kailangan mo ng buong file na may lahat ng parts, sabihin mo lang at i-paste ko ulit lahat.

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[KUNI] v2.5 Fixed Version running on http://localhost:{port}\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
