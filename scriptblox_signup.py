
import json, os, random, re, string, threading, hashlib, secrets, time, base64
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import unquote, quote

import requests, urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

from turnstile_solver import solve_turnstile_capsolver
from proxy_util import get_random_proxy, parse_proxy

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL  = "https://ukwltgxtfikiprsqflhi.supabase.co"
SUPABASE_KEY  = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"
SB_SIGNUP     = "https://scriptblox.com/api/auth/signup"
SB_VERIFY     = "https://scriptblox.com/api/auth/verify"
SB_LOGIN      = "https://scriptblox.com/api/auth/login"
SB_HOME       = "https://scriptblox.com/"
MW_BASE       = "https://mailwave.dev"
MW_DOMAIN     = "aula.edu.pl"
NO_PROXY      = {"http": None, "https": None}

USER_DATA_DIR = Path(__file__).parent / "user_data"
USER_DATA_DIR.mkdir(exist_ok=True)

SESSION_TTL_SEC = 86400
LICENSE_RECHECK_SEC = 300

RL_VERIFY_MAX, RL_VERIFY_WIN = 10, 60
RL_TRIAL_MAX,  RL_TRIAL_WIN  = 3,  3600

# ── Global State (thread-safe) ────────────────────────────────────────────────
sessions       = {}
sid_to_token   = {}
sessions_lock  = threading.RLock()

rate_limits    = defaultdict(deque)
rl_lock        = threading.Lock()

counter_lock   = threading.Lock()

app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Rate limiter ──────────────────────────────────────────────────────────────
def rate_limit(key, max_hits, window_sec):
    with rl_lock:
        now = time.time()
        dq  = rate_limits[key]
        while dq and dq[0] < now - window_sec: dq.popleft()
        if len(dq) >= max_hits: return False
        dq.append(now)
        return True

# ── Session management ────────────────────────────────────────────────────────
def fresh_state():
    return {"running": False, "created": 0, "active": 0, "failed": 0,
            "target": 0, "stop": False, "last_license_check": 0}

def user_key_hash(license_key):
    return hashlib.sha256(license_key.encode()).hexdigest()[:20]

def user_webhook_path(license_key):  return USER_DATA_DIR / f"{user_key_hash(license_key)}.webhook"
def user_proxies_path(license_key):  return USER_DATA_DIR / f"{user_key_hash(license_key)}.proxies"
def user_accounts_path(license_key): return USER_DATA_DIR / f"{user_key_hash(license_key)}.accounts.jsonl"

def load_user_webhook(license_key):
    p = user_webhook_path(license_key)
    return p.read_text().strip() if p.exists() else ""

def save_user_webhook(license_key, wh):
    user_webhook_path(license_key).write_text(wh or "")

def load_user_proxies(license_key):
    p = user_proxies_path(license_key)
    if not p.exists(): return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

def save_user_proxies(license_key, lines):
    user_proxies_path(license_key).write_text("\n".join(lines))

def create_session(license_key, license_record, ip, ua_hash_val):
    token = secrets.token_urlsafe(32)
    with sessions_lock:
        sessions[token] = {
            "license_key":    license_key,
            "license_record": license_record,
            "webhook":        load_user_webhook(license_key),
            "proxies":        load_user_proxies(license_key),
            "state":          fresh_state(),
            "ip":             ip,
            "ua_hash":        ua_hash_val,
            "created_at":     time.time(),
            "last_seen":      time.time(),
            "file_lock":      threading.Lock(),
        }
    return token

def get_session_by_token(token):
    if not token: return None
    with sessions_lock:
        sess = sessions.get(token)
        if sess: sess["last_seen"] = time.time()
        return sess

def destroy_session(token):
    with sessions_lock:
        sessions.pop(token, None)
        dead = [sid for sid, t in sid_to_token.items() if t == token]
        for sid in dead: sid_to_token.pop(sid, None)

def cleanup_sessions_loop():
    while True:
        time.sleep(300)
        try:
            with sessions_lock:
                now = time.time()
                expired = [t for t, s in sessions.items() if now - s["last_seen"] > SESSION_TTL_SEC]
                for t in expired: sessions.pop(t, None)
                dead_sids = [sid for sid, t in sid_to_token.items() if t not in sessions]
                for sid in dead_sids: sid_to_token.pop(sid, None)
        except: pass

threading.Thread(target=cleanup_sessions_loop, daemon=True).start()

def require_http_session():
    body = request.json if request.is_json else {}
    token = (request.headers.get("X-Session-Token") or
             (body or {}).get("session_token", "")).strip()
    return get_session_by_token(token)

def socket_session():
    sid = getattr(request, "sid", None)
    token = sid_to_token.get(sid) if sid else None
    return get_session_by_token(token)

# ── Client identity helpers ───────────────────────────────────────────────────
def get_client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd: return fwd.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0"

def get_client_ua():
    return (request.headers.get("User-Agent") or "")[:500]

def ua_hash(ua):
    return hashlib.sha256((ua or "").encode()).hexdigest()[:20]

def ip_subnet(ip, octets=3):
    parts = ip.split(".")
    if len(parts) != 4: return ip
    try:
        for p in parts: int(p)
    except: return ip
    return ".".join(parts[:octets])

DATACENTER_PREFIXES = (
    "104.16.","104.17.","104.18.","104.19.","104.20.","104.21.","104.22.","104.23.",
    "104.24.","104.25.","104.26.","104.27.","104.28.","172.67.","172.68.","172.69.",
    "172.70.","188.114.",
    "34.","35.192.","35.193.","35.194.","35.195.","35.196.","35.197.","35.198.",
    "35.199.","35.200.","35.201.","35.202.","35.203.","35.204.","35.205.","35.206.",
    "35.207.","35.208.","35.209.","35.210.","35.211.","35.212.","35.213.","35.214.",
    "35.215.","35.216.","35.217.","35.218.","35.219.","35.220.","35.221.","35.222.",
    "35.223.","35.224.","35.225.","35.226.","35.227.","35.228.","35.229.","35.230.",
    "35.231.","35.232.","35.233.","35.234.","35.235.","35.236.","35.237.","35.238.",
    "35.239.","35.240.","35.241.","35.242.","35.243.","35.244.","35.245.","35.246.",
    "35.247.","35.248.","35.249.",
    "52.","54.","18.","3.",
    "157.90.","159.69.","95.216.","116.202.","168.119.","142.132.",
    "46.101.","159.89.","165.227.","134.209.","167.99.","138.197.","138.68.",
    "159.203.","178.62.",
    "45.76.","45.77.","108.61.","149.28.","155.138.","207.148.","66.42.","45.32.",
    "185.244.","185.159.","185.232.","185.220.",
    "89.187.","193.32.","185.65.","185.107.",
)
def is_datacenter_ip(ip):
    if not ip or "." not in ip: return False
    for prefix in DATACENTER_PREFIXES:
        if ip.startswith(prefix): return True
    return False

def combined_fingerprint(hwid, ip, ls_token, ua_hash_val, extra_fp=""):
    ip_pref = ip_subnet(ip, 3) if "." in ip else ip[:8]
    raw = f"{hwid}|{ip_pref}|{ls_token or ''}|{ua_hash_val}|{extra_fp or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()

def mask_email(email):
    if not email or "@" not in email: return "***"
    user = email.split("@")[0]
    if len(user) > 3: user = user[:2] + "*" * (len(user) - 2)
    return f"{user}@***"

# ── Supabase helpers ──────────────────────────────────────────────────────────
def supa_hdrs():
    return {"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json"}

def fetch_license(key):
    try:
        r = requests.get(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                         params={"license_key": f"eq.{key}", "select": "*"})
        if r.status_code == 200:
            d = r.json()
            return d[0] if d else None
    except: pass
    return None

def atomic_increment_used(key, limit):
    """Optimistic-lock increment. Returns (new_value, allowed)."""
    with counter_lock:
        for attempt in range(3):
            try:
                rec = fetch_license(key)
                if not rec: return (None, False)
                used  = rec.get("accounts_used") or 0
                if limit < 9999 and used >= limit:
                    return (used, False)
                new_val = used + 1
                r = requests.patch(f"{SUPABASE_URL}/rest/v1/licenses",
                                   headers={**supa_hdrs(), "Prefer": "return=representation"},
                                   params={"license_key": f"eq.{key}",
                                           "accounts_used": f"eq.{used}"},
                                   json={"accounts_used": new_val})
                if r.status_code in (200, 201):
                    body = r.json()
                    if body:
                        return (new_val, True)
                time.sleep(0.1 * (attempt + 1))
            except Exception as e:
                print("INCREMENT ERROR:", e)
                time.sleep(0.1)
        return (None, False)

# ── MailWave helpers (AULA domain) ────────────────────────────────────────────
def mw_setup():
    """Initialize MailWave session — fetch CSRF token + cookies from landing page."""
    try:
        r = requests.get(f"{MW_BASE}/", proxies=NO_PROXY, timeout=15,
                         headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"})
        token = re.search(r'<meta name="csrf-token" content="([^"]+)"', r.text)
        csrf = token.group(1) if token else None
        print(f"[mw setup] csrf={csrf[:20] if csrf else 'NONE'}... cookies={list(r.cookies.keys())}")
        return dict(r.cookies), csrf
    except Exception as e:
        print(f"[mw setup] error: {e}")
        return None, None

def mw_headers(csrf):
    """Browser-exact headers for MailWave API calls."""
    return {
        "Accept":        "application/json, text/plain, */*",
        "Content-Type":  "application/json",
        "Origin":        "https://mailwave.dev",
        "Referer":       "https://mailwave.dev/",
        "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "X-CSRF-TOKEN":  csrf,
        "X-XSRF-TOKEN":  csrf,   # Laravel accepts either — we send both to be safe
        "X-Requested-With": "XMLHttpRequest",
    }

def mw_create_email(cookies, csrf):
    """Create email alias on aula.edu.pl. Returns (email_addr, new_csrf, cookies)."""
    if not csrf or cookies is None: return None, csrf, cookies
    for attempt in range(5):
        alias = "kuni" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        try:
            # Step 1: POST /change to create the alias (browser sends form-encoded)
            r = requests.post(f"{MW_BASE}/change",
                              data={"_token": csrf, "name": alias, "domain": MW_DOMAIN},
                              cookies=cookies, proxies=NO_PROXY, timeout=15,
                              headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36",
                                       "Referer": "https://mailwave.dev/",
                                       "Origin":  "https://mailwave.dev"})
            cookies.update(dict(r.cookies))
            # XSRF-TOKEN cookie is URL-encoded Laravel format — decode it
            new_csrf = unquote(cookies.get("XSRF-TOKEN", "")) or csrf

            # Step 2: POST /get_messages with {"_token": csrf} body to get mailbox
            r2 = requests.post(f"{MW_BASE}/get_messages",
                               json={"_token": new_csrf},
                               headers=mw_headers(new_csrf),
                               cookies=cookies, proxies=NO_PROXY, timeout=15)
            cookies.update(dict(r2.cookies))
            new_csrf = unquote(cookies.get("XSRF-TOKEN", new_csrf))
            data = r2.json() if r2.content else {}

            print(f"[mw create attempt={attempt+1}] status={r2.status_code} keys={list(data.keys())[:8]}")

            mailbox = data.get("mailbox", "")
            if MW_DOMAIN in mailbox:
                print(f"[mw create] email={mailbox}")
                return mailbox, new_csrf, cookies
        except Exception as e:
            print(f"[mw create] error: {e}")
        time.sleep(1)
    return None, csrf, cookies

def mw_poll_code(cookies, csrf, timeout=150, poll_interval=3):
    """Poll MailWave inbox for ScriptBlox 7-digit verification code.
    Body uses Laravel CSRF _token — matches browser exactly."""
    deadline  = time.time() + timeout
    poll_count = 0
    last_csrf = csrf
    time.sleep(3)  # initial wait — let email arrive

    while time.time() < deadline:
        poll_count += 1
        try:
            # Browser sends {"_token": "<laravel-csrf>"} — this is the 53 bytes
            body = {"_token": last_csrf}
            r = requests.post(f"{MW_BASE}/get_messages",
                              json=body,
                              headers=mw_headers(last_csrf),
                              cookies=cookies, proxies=NO_PROXY, timeout=15)
            # Rotate CSRF — Laravel regenerates it each request
            cookies.update(dict(r.cookies))
            last_csrf = unquote(cookies.get("XSRF-TOKEN", last_csrf))
            data = r.json() if r.content else {}

            if poll_count <= 2:
                raw = json.dumps(data)[:600]
                print(f"[mw poll #{poll_count}] RAW: {raw}")

            messages = data.get("messages") or []
            if not isinstance(messages, list): messages = []
            email_token = data.get("email_token", "")

            if poll_count % 5 == 1:
                print(f"[mw poll #{poll_count}] status={r.status_code} "
                      f"msg_count={len(messages)} mailbox={data.get('mailbox','')[:40]}")
                if messages:
                    s = messages[0]
                    if isinstance(s, dict):
                        print(f"[mw sample] keys={list(s.keys())[:10]} "
                              f"from={str(s.get('from',''))[:40]} "
                              f"subject={str(s.get('subject',''))[:50]}")

            for msg in messages:
                if not isinstance(msg, dict): continue
                sender  = str(msg.get("from") or msg.get("sender") or "").lower()
                subject = str(msg.get("subject") or "").lower()

                is_sb = "scriptblox" in sender or "scriptblox" in subject or "verification" in subject
                if not is_sb: continue

                # Try inline body fields first
                blob_parts = []
                for k in ("body","body_html","body_text","html","text","content",
                          "preview","snippet","message"):
                    v = msg.get(k)
                    if isinstance(v, str): blob_parts.append(v)
                blob = " ".join(blob_parts) + " " + subject

                match = re.search(r"(?<!\d)(\d{7})(?!\d)", blob)
                if match:
                    code = match.group(1)
                    print(f"[mw FOUND inline] code={code}")
                    return code

                # Fallback: fetch /view/{email_token} HTML page and scrape
                if email_token:
                    try:
                        vr = requests.get(f"{MW_BASE}/view/{email_token}",
                                          cookies=cookies, proxies=NO_PROXY, timeout=15,
                                          headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36"})
                        if vr.status_code == 200 and "scriptblox" in vr.text.lower():
                            m = re.search(r"(?<!\d)(\d{7})(?!\d)", vr.text)
                            if m:
                                code = m.group(1)
                                print(f"[mw FOUND via /view] code={code}")
                                return code
                    except Exception as e:
                        print(f"[mw view error] {e}")
        except Exception as e:
            print(f"[mw poll #{poll_count}] error: {e}")
        time.sleep(poll_interval)
    print(f"[mw] TIMEOUT after {poll_count} polls")
    return None

# ── ScriptBlox verify + login ─────────────────────────────────────────────────
def sb_verify_account(code, token_value, proxy_r=None, visitor_id=None):
    """Submit vCode to SB — mirrors browser flow exactly.
    Returns (response, verified_bool, new_token)."""
    try:
        # Use/generate visitor ID (browser keeps it consistent)
        if not visitor_id:
            visitor_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()

        hdrs = {
            "Content-Type":  "application/json",
            "Accept":        "application/json",
            "Origin":        "https://scriptblox.com",
            "Referer":       "https://scriptblox.com/verify",
            "User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            # Critical: NO "Bearer " prefix — browser sends raw JWT
            "Authorization": token_value,
            # Browser sends this header mirroring the visitor cookie
            "x-visitor":     visitor_id,
        }
        cookies = {
            "token":   token_value,
            "visitor": visitor_id,
        }
        r = requests.post(SB_VERIFY,
                          json={"vCode": int(code)},
                          headers=hdrs,
                          cookies=cookies,
                          proxies=proxy_r, timeout=25, verify=False)
        try:
            data = r.json() if r.content else {}
        except:
            data = {}

        print(f"[sb_verify] status={r.status_code} body={str(data)[:200]}")

        # SB returns {"message": false, "token": "..."} on success
        if r.status_code == 200 and data.get("message") is False:
            new_tok = data.get("token", "")
            if not new_tok:
                # Fallback: parse from Set-Cookie header
                sc = r.headers.get("set-cookie", "")
                m  = re.search(r"token=([^;]+)", sc)
                if m: new_tok = m.group(1)
            return r, True, (new_tok or token_value)
        return r, False, token_value
    except Exception as e:
        print(f"[sb_verify] error: {e}")
        return None, False, token_value

def sb_login(email, password, proxy_r=None):
    """Login to SB. Returns (token, response) or (None, None)."""
    try:
        r = requests.post(SB_LOGIN,
                          json={"login": email, "password": password},
                          headers=sb_headers(), proxies=proxy_r, timeout=20, verify=False)
        if r.status_code == 200:
            data = r.json()
            token = data.get("token") or data.get("data", {}).get("token", "")
            return token, r
    except: pass
    return None, None

# ── Cookie fabrication (full browser-like set) ────────────────────────────────
def _rand_ga_id():
    return f"GA1.2.{random.randint(100000000,999999999)}.{int(time.time())-random.randint(0,86400*30)}"

def _rand_gid():
    return f"GA1.2.{random.randint(100000000,999999999)}.{int(time.time())}"

def _rand_gpi():
    uid = "".join(random.choices("0123456789abcdef", k=16))
    ts = int(time.time()) - random.randint(0, 86400*30)
    rt = int(time.time())
    sfx = "".join(random.choices(string.ascii_letters + string.digits + "_-", k=20))
    return f"UID={uid}:T={ts}:RT={rt}:S=ALNI_{sfx}"

def _rand_eoi():
    uid = "".join(random.choices("0123456789abcdef", k=16))
    ts = int(time.time()) - random.randint(0, 86400*30)
    rt = int(time.time())
    sfx = "".join(random.choices(string.ascii_letters + string.digits + "_-", k=20))
    return f"ID={uid}:T={ts}:RT={rt}:S=AA-Afj{sfx}"

def _rand_gads():
    uid = "".join(random.choices("0123456789abcdef", k=16))
    ts = int(time.time()) - random.randint(0, 86400*30)
    rt = int(time.time())
    sfx = "".join(random.choices(string.ascii_letters + string.digits + "_-", k=20))
    return f"ID={uid}:T={ts}:RT={rt}:S=ALNI_{sfx}"

def _rand_fcnec():
    inner = "".join(random.choices(string.ascii_letters + string.digits + "_-", k=80))
    raw = f'[["AKsRol_{inner}=="]]'
    return quote(raw)

def _rand_ga6():
    sess_ts = int(time.time()) - random.randint(0, 3600)
    cur_ts  = int(time.time())
    return f"GS2.1.s{sess_ts}$o5$g1$t{cur_ts}$j59$l0$h0"

def _rand_visitor():
    return hashlib.md5(str(time.time() + random.random()).encode()).hexdigest()

def _rand_ua_cookie():
    return quote("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")

def fabricate_full_cookies(token_value, username, verified=True, visitor_id=None):
    """Build full browser-like cookie set matching Cookie-Editor export format."""
    now      = int(time.time())
    creation = now - random.randint(3600, 86400 * 7)
    visitor  = visitor_id or _rand_visitor()
    return [
        {"domain":"scriptblox.com","expirationDate":now+3600,"hostOnly":True,"httpOnly":False,
         "name":"__scriptblox_ua_","path":"/","sameSite":"no_restriction","secure":True,
         "session":False,"storeId":None,"value":_rand_ua_cookie()},
        {"domain":"scriptblox.com","hostOnly":True,"httpOnly":False,"name":"visitor","path":"/",
         "sameSite":None,"secure":False,"session":True,"storeId":None,"value":visitor},
        {"domain":"scriptblox.com","expirationDate":creation+86400*365,"hostOnly":True,"httpOnly":False,
         "name":"i18n_redirected","path":"/","sameSite":"lax","secure":False,"session":False,
         "storeId":None,"value":"en"},
        {"domain":"scriptblox.com","expirationDate":now+86400*30,"hostOnly":True,"httpOnly":True,
         "name":"token","path":"/","sameSite":"strict","secure":True,"session":False,
         "storeId":None,"value":token_value},
        {"domain":".scriptblox.com","expirationDate":creation+86400*400,"hostOnly":False,"httpOnly":False,
         "name":"_ga","path":"/","sameSite":None,"secure":False,"session":False,
         "storeId":None,"value":_rand_ga_id()},
        {"domain":".scriptblox.com","expirationDate":now+86400,"hostOnly":False,"httpOnly":False,
         "name":"_gid","path":"/","sameSite":None,"secure":False,"session":False,
         "storeId":None,"value":_rand_gid()},
        {"domain":".scriptblox.com","expirationDate":creation+86400*400,"hostOnly":False,"httpOnly":False,
         "name":"_ga_6BWTBXZCLM","path":"/","sameSite":None,"secure":False,"session":False,
         "storeId":None,"value":_rand_ga6()},
        {"domain":".scriptblox.com","expirationDate":creation+86400*390,"hostOnly":False,"httpOnly":False,
         "name":"__gpi","path":"/","sameSite":"no_restriction","secure":True,"session":False,
         "storeId":None,"value":_rand_gpi()},
        {"domain":".scriptblox.com","expirationDate":creation+86400*180,"hostOnly":False,"httpOnly":False,
         "name":"__eoi","path":"/","sameSite":"no_restriction","secure":True,"session":False,
         "storeId":None,"value":_rand_eoi()},
        {"domain":".scriptblox.com","expirationDate":creation+86400*390,"hostOnly":False,"httpOnly":False,
         "name":"__gads","path":"/","sameSite":"no_restriction","secure":True,"session":False,
         "storeId":None,"value":_rand_gads()},
        {"domain":".scriptblox.com","expirationDate":now+86400*390,"hostOnly":False,"httpOnly":False,
         "name":"FCNEC","path":"/","sameSite":None,"secure":False,"session":False,
         "storeId":None,"value":_rand_fcnec()},
    ]

# ── Cookie extraction ─────────────────────────────────────────────────────────
def parse_set_cookie_header(header):
    if not header: return None
    parts = header.split(';')
    if not parts: return None
    nv = parts[0].strip().split('=', 1)
    if len(nv) != 2: return None
    name, value = nv[0].strip(), nv[1].strip()
    if not name: return None

    cookie = {
        "domain": "scriptblox.com", "hostOnly": True, "httpOnly": False,
        "name": name, "path": "/", "sameSite": None, "secure": False,
        "session": True, "storeId": None, "value": value,
    }

    for attr in parts[1:]:
        attr  = attr.strip()
        lower = attr.lower()
        if lower.startswith('domain='):
            d = attr.split('=', 1)[1].strip()
            cookie["domain"]   = d
            cookie["hostOnly"] = not d.startswith('.')
        elif lower.startswith('path='):
            cookie["path"] = attr.split('=', 1)[1].strip() or "/"
        elif lower.startswith('expires='):
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(attr.split('=', 1)[1].strip())
                cookie["expirationDate"] = dt.timestamp()
                cookie["session"] = False
            except: pass
        elif lower.startswith('max-age='):
            try:
                age = int(attr.split('=', 1)[1].strip())
                cookie["expirationDate"] = datetime.now(timezone.utc).timestamp() + age
                cookie["session"] = False
            except: pass
        elif lower.startswith('samesite='):
            ss = attr.split('=', 1)[1].strip().lower()
            if ss == 'none': cookie["sameSite"] = "no_restriction"
            elif ss in ('lax', 'strict'): cookie["sameSite"] = ss
        elif lower == 'secure':   cookie["secure"]   = True
        elif lower == 'httponly': cookie["httpOnly"] = True
    return cookie

def get_all_set_cookie_headers(response):
    headers = []
    try:
        raw_headers = getattr(response.raw, 'headers', None)
        if raw_headers:
            if hasattr(raw_headers, 'get_all'):
                headers = raw_headers.get_all('Set-Cookie') or []
            elif hasattr(raw_headers, 'getlist'):
                headers = raw_headers.getlist('Set-Cookie') or []
    except: pass
    if not headers:
        merged = response.headers.get('Set-Cookie', '')
        if merged:
            headers = re.split(r',\s*(?=[A-Za-z_][A-Za-z0-9_\-]*=)', merged)
    return headers

def decode_jwt_payload(jwt_str):
    try:
        parts = jwt_str.split('.')
        if len(parts) < 2: return None
        payload = parts[1]
        payload += '=' * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except:
        return None

def extract_session_cookies(response):
    raw_headers = get_all_set_cookie_headers(response)
    cookies = []
    seen = set()
    for h in raw_headers:
        parsed = parse_set_cookie_header(h)
        if not parsed: continue
        k = (parsed["name"], parsed["domain"])
        if k in seen: continue
        seen.add(k)
        if parsed["name"] in ("token", "__scriptblox_validation") and parsed.get("session"):
            payload = decode_jwt_payload(parsed["value"])
            if payload and payload.get("exp"):
                parsed["expirationDate"] = float(payload["exp"])
                parsed["session"] = False
        cookies.append(parsed)
    if not cookies:
        for c in response.cookies:
            domain = c.domain or "scriptblox.com"
            cookie = {
                "domain": domain, "hostOnly": not domain.startswith('.'),
                "httpOnly": False, "name": c.name, "path": c.path or "/",
                "sameSite": "lax", "secure": bool(c.secure),
                "session": c.expires is None, "storeId": None, "value": c.value,
            }
            if c.expires: cookie["expirationDate"] = float(c.expires)
            cookies.append(cookie)
    return cookies

def upload_cookies_to_sourcebin(cookies_json):
    try:
        r = requests.post("https://sourceb.in/api/bins",
                          json={"files": [{"name": "cookies.json", "content": cookies_json}]},
                          timeout=15, proxies=NO_PROXY)
        if r.status_code in (200, 201):
            data = r.json()
            key = data.get("key") or (data.get("bin") or {}).get("key")
            if key: return f"https://cdn.sourceb.in/bins/{key}/0"
    except: pass
    return None

# ── Discord Webhook ───────────────────────────────────────────────────────────
def send_webhook(webhook_url, username, password, email, cookies_url=None, cookies_json=None, verify_status="unverified"):
    if not webhook_url: return False
    try:
        is_verified = (verify_status == "verified")

        # Clean, solid color palette — no emoji clutter
        color = 0x00D4FF if is_verified else 0x4A6070  # cyan / muted
        status_line = "Verified" if is_verified else "Unverified"

        fields = [
            {"name": "Username",    "value": f"`{username}`",             "inline": True},
            {"name": "Status",      "value": f"`{status_line}`",          "inline": True},
            {"name": "Created",     "value": datetime.now(timezone.utc).strftime("%b %d, %Y %H:%M UTC"), "inline": True},
            {"name": "Email",       "value": f"`{mask_email(email)}`",    "inline": False},
        ]

        if cookies_url:
            fields.append({
                "name":  "Session Cookies",
                "value": f"```json\ncookies.json ready for Cookie-Editor import\n```\n[**Download cookies.json**]({cookies_url})",
                "inline": False,
            })
        else:
            fields.append({
                "name":  "Session Cookies",
                "value": "_Attached to this message below._",
                "inline": False,
            })

        embed = {
            "title":       "KUNI SB GENERATOR",
            "description": f"A new ScriptBlox account has been delivered.",
            "color":       color,
            "fields":      fields,
            "footer":      {"text": "Kuni Tool  ·  ScriptBlox Auto Generator"},
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }

        payload = {
            "username":   "Kuni SB Gen",
            "avatar_url": "https://cdn.discordapp.com/emojis/1163495097574047815.webp",
            "embeds":     [embed],
        }

        if cookies_json and not cookies_url:
            files = {"cookies.json": ("cookies.json", cookies_json, "application/json")}
            r = requests.post(webhook_url, data={"payload_json": json.dumps(payload)},
                              files=files, proxies=NO_PROXY, timeout=15)
        else:
            r = requests.post(webhook_url, json=payload, proxies=NO_PROXY, timeout=10)
        return r.status_code in (200, 204)
    except Exception as e:
        print(f"[webhook] error: {e}")
        return False

def test_webhook(url):
    try:
        r = requests.post(url, json={
            "username": "Kuni SB Gen",
            "embeds": [{
                "title":       "KUNI SB GENERATOR",
                "description": "Webhook connected successfully.\nYour generated accounts will be delivered here.",
                "color":       0x00D4FF,
                "footer":      {"text": "Kuni Tool  ·  ScriptBlox Auto Generator"},
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            }]
        }, proxies=NO_PROXY, timeout=10)
        return r.status_code in (200, 204)
    except:
        return False

# ── Utils ─────────────────────────────────────────────────────────────────────
def rand_username(): return "Kuni" + "".join(random.choices(string.ascii_letters + string.digits, k=10))
def rand_password(): return "".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=14))

def proxy_to_requests(proxy):
    if not proxy: return None
    # Handle string format (host:port or host:port:user:pass or http://...)
    if isinstance(proxy, str):
        p = proxy.strip()
        if p.startswith("http://") or p.startswith("https://"):
            return {"http": p, "https": p}
        parts = p.split(":")
        if len(parts) == 2:
            return {"http": f"http://{p}", "https": f"http://{p}"}
        elif len(parts) == 4:
            host, port, user, pw = parts
            return {"http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}"}
        return {"http": f"http://{p}", "https": f"http://{p}"}
    # Handle dict format from parse_proxy
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

def log_emit(sess_token, msg, tag="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    sess = get_session_by_token(sess_token)
    if not sess: return
    with sessions_lock:
        sids = [sid for sid, t in sid_to_token.items() if t == sess_token]
    payload_log   = {"msg": f"[{ts}] {msg}", "tag": tag}
    payload_stats = {k: sess["state"][k] for k in ("created","active","failed","target")}
    for sid in sids:
        socketio.emit("log",   payload_log,   room=sid)
        socketio.emit("stats", payload_stats, room=sid)

def emit_to_session(sess_token, event, data):
    with sessions_lock:
        sids = [sid for sid, t in sid_to_token.items() if t == sess_token]
    for sid in sids:
        socketio.emit(event, data, room=sid)

# ── Core account creation ─────────────────────────────────────────────────────
def create_account(sess_token, slot):
    sess = get_session_by_token(sess_token)
    if not sess: return
    state = sess["state"]
    if state["stop"]: return

    license_key    = sess["license_key"]
    license_record = sess["license_record"]
    limit = license_record.get("accounts_limit", 0) if license_record else 0

    now = time.time()
    if now - state["last_license_check"] > LICENSE_RECHECK_SEC:
        fresh = fetch_license(license_key)
        if not fresh or fresh.get("status") != "active":
            state["stop"] = True
            log_emit(sess_token, "License revoked or disabled - stopping.", "err")
            emit_to_session(sess_token, "limit_reached", {"used": 0, "limit": limit, "reason": "revoked"})
            return
        exp = fresh.get("expiry_date")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z","+00:00"))
                if exp_dt.tzinfo is None: exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    state["stop"] = True
                    log_emit(sess_token, "License expired - stopping.", "err")
                    emit_to_session(sess_token, "limit_reached", {"used": 0, "limit": limit, "reason": "expired"})
                    return
            except: pass
        sess["license_record"] = fresh
        license_record = fresh
        state["last_license_check"] = now

    username    = rand_username()
    password    = rand_password()
    proxy       = get_random_proxy(sess["proxies"]) if sess["proxies"] else None
    proxy_r     = proxy_to_requests(proxy)
    webhook_url = sess["webhook"]

    # Generate visitor ID once — used consistently across signup, verify, and cookie fabrication
    visitor_id = hashlib.md5(f"{time.time()}{random.random()}{slot}".encode()).hexdigest()

    log_emit(sess_token, f"[#{slot}] creating email + solving captcha...", "dim")
    print(f"[#{slot}] proxies_count={len(sess['proxies'])} selected={proxy} proxy_r={proxy_r}")

    # MailWave — CSRF-based, AULA domain
    mw_cookies, mw_csrf = mw_setup()
    captcha = solve_turnstile_capsolver()
    email_addr, mw_csrf, mw_cookies = mw_create_email(mw_cookies, mw_csrf)

    if not email_addr or not captcha:
        state["failed"] += 1
        reason = "email" if not email_addr else "captcha"
        log_emit(sess_token, f"[#{slot}] x setup failed ({reason})", "err")
        return

    print(f"[#{slot}] email={email_addr}")

    log_emit(sess_token, f"[#{slot}] submitting signup...", "dim")

    signup_token = ""
    try:
        signup_hdrs = sb_headers()
        signup_hdrs["x-visitor"] = visitor_id
        r = requests.post(SB_SIGNUP, json={
            "email": email_addr, "username": username,
            "password": password, "repeatPassword": password,
            "terms": True, "captcha": captcha,
        }, headers=signup_hdrs, cookies={"visitor": visitor_id},
           proxies=proxy_r, timeout=30, verify=False)
        resp = r.json() if r.content else {}
        # Debug: log response structure so we can see where token lives
        resp_keys = list(resp.keys()) if isinstance(resp, dict) else str(type(resp))
        resp_msg = str(resp.get("message",""))[:150] if isinstance(resp, dict) else ""
        print(f"[signup #{slot}] status={r.status_code} keys={resp_keys} msg={resp_msg} set-cookie={r.headers.get('set-cookie','')[:120]}")
        # Try multiple locations for token
        signup_token = resp.get("token") or resp.get("accessToken") or ""
        if not signup_token and isinstance(resp.get("data"), dict):
            signup_token = resp["data"].get("token", "")
        if not signup_token and isinstance(resp.get("user"), dict):
            signup_token = resp["user"].get("token", "")
    except Exception as e:
        state["failed"] += 1
        log_emit(sess_token, f"[#{slot}] x request error: {str(e)[:50]}", "err")
        return

    if r.status_code >= 400 or resp.get("error") or (isinstance(resp.get("statusCode"), int) and resp["statusCode"] >= 400):
        state["failed"] += 1
        err_msg = resp.get("message") or resp.get("error") or f"HTTP {r.status_code}"
        log_emit(sess_token, f"[#{slot}] x signup failed ({r.status_code}): {err_msg}", "err")
        return

    # Grab token from Set-Cookie header (raw)
    if not signup_token:
        sc = r.headers.get("set-cookie", "")
        m = re.search(r"token=([^;]+)", sc)
        if m: signup_token = m.group(1)

    # Grab token from cookie jar
    if not signup_token:
        for c in r.cookies:
            if c.name == "token" and c.value:
                signup_token = c.value
                break

    # FALLBACK: login to get token (SB may not return token on signup)
    if not signup_token:
        log_emit(sess_token, f"[#{slot}] no token in signup response - trying login...", "dim")
        login_tok, login_r = sb_login(email_addr, password, proxy_r)
        if login_tok:
            signup_token = login_tok
            log_emit(sess_token, f"[#{slot}] got token via login", "dim")
        else:
            state["failed"] += 1
            log_emit(sess_token, f"[#{slot}] x login also failed - no token", "err")
            return

    # ── Navigate to verify page (mirrors browser flow) ────────────────────────
    try:
        requests.get("https://scriptblox.com/verify?redirect=/",
                     cookies={"token": signup_token}, headers=sb_headers(),
                     proxies=proxy_r, timeout=15, verify=False)
    except: pass

    # ── Poll MailWave for verification code ────────────────────────────────────
    log_emit(sess_token, f"[#{slot}] waiting for verification email...", "dim")
    verify_code = mw_poll_code(mw_cookies, mw_csrf, timeout=150)
    verified    = False
    final_token = signup_token

    if verify_code:
        log_emit(sess_token, f"[#{slot}] submitting code {verify_code}...", "dim")
        _vr, ok, new_tok = sb_verify_account(verify_code, signup_token, proxy_r, visitor_id)
        if ok:
            verified = True
            final_token = new_tok
            log_emit(sess_token, f"[#{slot}] account verified!", "dim")
            # Visit homepage like browser does after verify
            try:
                home_hdrs = sb_headers()
                home_hdrs["x-visitor"] = visitor_id
                requests.get(f"{SB_HOME}?showWelcome=true",
                             cookies={"token": final_token, "visitor": visitor_id},
                             headers=home_hdrs,
                             proxies=proxy_r, timeout=15, verify=False)
            except: pass
        else:
            log_emit(sess_token, f"[#{slot}] verify rejected - saving unverified", "err")
    else:
        log_emit(sess_token, f"[#{slot}] no code received - saving unverified", "err")

    verify_status = "verified" if verified else "unverified"

    # ── Fabricate full browser-like cookie set ─────────────────────────────────
    cookies_data = fabricate_full_cookies(final_token, username, verified=verified, visitor_id=visitor_id)
    cookies_json_str = json.dumps(cookies_data, indent=2)
    cookies_url = upload_cookies_to_sourcebin(cookies_json_str)

    if cookies_url:
        log_emit(sess_token, f"[#{slot}] cookies uploaded ({len(cookies_data)} cookies, {verify_status})", "dim")
    else:
        log_emit(sess_token, f"[#{slot}] {len(cookies_data)} cookies ({verify_status}) - attaching to webhook", "dim")

    webhook_ok = send_webhook(webhook_url, username, password, email_addr,
                              cookies_url, cookies_json_str, verify_status)
    if not webhook_ok:
        log_emit(sess_token, f"[#{slot}] warning: webhook delivery failed - saved locally", "err")

    account = {
        "username": username, "password": password,
        "email": email_addr,
        "cookies_url": cookies_url, "has_cookies": bool(cookies_data),
        "verify_status": verify_status,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    with sess["file_lock"]:
        with open(user_accounts_path(license_key), "a") as f:
            f.write(json.dumps(account) + "\n")

    new_used, allowed = atomic_increment_used(license_key, limit)
    if not allowed:
        state["stop"] = True
        log_emit(sess_token, f"Account limit reached during run ({new_used}/{limit})", "err")
        emit_to_session(sess_token, "limit_reached", {"used": new_used, "limit": limit})
        return

    state["created"] += 1
    mark = "[VERIFIED]" if verify_status == "verified" else ("[COOKIE]" if cookies_url else "[UNVERIFIED]")
    log_emit(sess_token, f"[#{slot}] {mark} {username} | {password}", "ok")

def run_generator(sess_token, count, concurrent):
    sess = get_session_by_token(sess_token)
    if not sess: return
    state = sess["state"]

    sem = threading.Semaphore(concurrent)
    threads = []

    def worker(slot):
        with sem:
            if not state["stop"]:
                state["active"] += 1
                try: create_account(sess_token, slot)
                finally: state["active"] -= 1

    for i in range(count):
        if state["stop"]: break
        t = threading.Thread(target=worker, args=(i+1,), daemon=True)
        threads.append(t); t.start()
    for t in threads: t.join()

    state["running"] = False
    log_emit(sess_token, f"Done - {state['created']}/{count} accounts created.", "ok")
    emit_to_session(sess_token, "done", {"created": state["created"], "total": count})

# ── HTTP Routes ───────────────────────────────────────────────────────────────
@app.route("/verify-key", methods=["POST"])
def verify():
    client_ip = get_client_ip()
    if not rate_limit(f"verify:{client_ip}", RL_VERIFY_MAX, RL_VERIFY_WIN):
        return jsonify({"valid": False, "error": "rate_limited"}), 429
    try:
        body = request.json or {}
        key = body.get("key","").strip()
        if not key: return jsonify({"valid": False, "error": "no_key"})

        client_hwid = body.get("hwid", "").strip()
        ls_token    = body.get("ls_token", "").strip()
        extra_fp    = body.get("fp", "").strip()
        ua          = get_client_ua()
        ua_h        = ua_hash(ua)
        hwid        = client_hwid or hashlib.sha256(client_ip.encode()).hexdigest()

        rec = fetch_license(key)
        if not rec: return jsonify({"valid": False, "error": "not_found"})
        if rec.get("status") != "active": return jsonify({"valid": False, "error": "disabled"})

        exp = rec.get("expiry_date")
        if exp:
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z","+00:00"))
                if exp_dt.tzinfo is None: exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if exp_dt < datetime.now(timezone.utc):
                    return jsonify({"valid": False, "error": "expired"})
            except: pass

        if rec.get("hwid") and rec["hwid"] != hwid:
            return jsonify({"valid": False, "error": "hwid_mismatch"})

        stored_ua = rec.get("ua_hash")
        if stored_ua and stored_ua != ua_h:
            print(f"[WARN] UA drift for {key}: {stored_ua} -> {ua_h}")

        patch = {}
        if not rec.get("hwid"):    patch["hwid"] = hwid
        if not rec.get("ua_hash"): patch["ua_hash"] = ua_h
        if patch:
            requests.patch(f"{SUPABASE_URL}/rest/v1/licenses", headers=supa_hdrs(),
                           params={"license_key": f"eq.{key}"}, json=patch)

        limit = rec.get("accounts_limit", 0)
        used  = rec.get("accounts_used", 0) or 0
        if limit < 9999 and used >= limit:
            return jsonify({"valid": False, "error": "limit_reached", "used": used, "limit": limit})

        sess_token = create_session(key, rec, client_ip, ua_h)
        final_ls   = ls_token or secrets.token_hex(16)

        return jsonify({
            "valid":          True,
            "session_token":  sess_token,
            "plan":           "Unlimited" if limit >= 9999 else f"{limit} accounts",
            "used":           used,
            "limit":          limit,
            "accounts_left":  None if limit >= 9999 else (limit - used),
            "ls_token":       final_ls,
        })
    except Exception as e:
        print("VERIFY ERROR:", e)
        return jsonify({"valid": False, "error": "server_error"})

@app.route("/set-proxies", methods=["POST"])
def set_proxies():
    sess = require_http_session()
    if not sess: return jsonify({"ok": False, "error": "not_authenticated"}), 401
    try:
        lines = (request.json or {}).get("proxies","").strip().splitlines()
        valid = [l.strip() for l in lines if l.strip() and not l.startswith("#") and parse_proxy(l.strip())]
        save_user_proxies(sess["license_key"], valid)
        sess["proxies"] = valid
        return jsonify({"ok": True, "count": len(valid)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/set-webhook", methods=["POST"])
def set_webhook():
    sess = require_http_session()
    if not sess: return jsonify({"ok": False, "error": "not_authenticated"}), 401
    try:
        wh = (request.json or {}).get("webhook","").strip()
        if wh and not wh.startswith("https://discord.com/api/webhooks/"):
            return jsonify({"ok": False, "error": "invalid_webhook"})
        if wh and not test_webhook(wh):
            return jsonify({"ok": False, "error": "webhook_unreachable"})
        sess["webhook"] = wh
        save_user_webhook(sess["license_key"], wh)
        return jsonify({"ok": True, "tested": bool(wh)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/get-proxies", methods=["GET"])
def get_proxies():
    sess = require_http_session()
    if not sess: return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "count": len(sess["proxies"])})

@app.route("/get-webhook", methods=["GET"])
def get_webhook():
    sess = require_http_session()
    if not sess: return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "has_webhook": bool(sess["webhook"])})

@app.route("/logout", methods=["POST"])
def logout():
    body = request.json or {}
    token = body.get("session_token", "").strip()
    if token: destroy_session(token)
    return jsonify({"ok": True})

# ── SocketIO ──────────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect(auth):
    token = (auth or {}).get("token", "") if isinstance(auth, dict) else ""
    sess  = get_session_by_token(token)
    if not sess:
        emit("auth_failed")
        return False
    sid_to_token[request.sid] = token
    emit("authed", {"ok": True})

@socketio.on("disconnect")
def on_disconnect():
    sid_to_token.pop(request.sid, None)

@socketio.on("get_info")
def on_info():
    sess = socket_session()
    if not sess: return
    emit("info", {"proxies": len(sess["proxies"]), "webhook": bool(sess["webhook"])})

@socketio.on("start")
def on_start(data):
    sess = socket_session()
    if not sess:
        emit("auth_failed"); return
    if sess["state"]["running"]: return

    if not sess["webhook"]:
        emit("start_blocked", {"reason": "webhook_required",
                               "message": "Set a Discord webhook first. Accounts cannot be delivered without it."})
        log_emit(sid_to_token[request.sid], "Cannot start - webhook required.", "err")
        return

    fresh = fetch_license(sess["license_key"])
    if not fresh or fresh.get("status") != "active":
        emit("limit_reached", {"used": 0, "limit": 0, "reason": "revoked"}); return

    exp = fresh.get("expiry_date")
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z","+00:00"))
            if exp_dt.tzinfo is None: exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < datetime.now(timezone.utc):
                emit("limit_reached", {"used": 0, "limit": 0, "reason": "expired"}); return
        except: pass

    sess["license_record"] = fresh
    limit = fresh.get("accounts_limit", 0)
    used  = fresh.get("accounts_used", 0) or 0
    if limit < 9999 and used >= limit:
        emit("limit_reached", {"used": used, "limit": limit}); return

    count      = int(data.get("count", 10))
    concurrent = int(data.get("concurrent", 10))
    concurrent = max(1, min(concurrent, 50))

    if limit < 9999:
        remaining = limit - used
        if count > remaining:
            count = remaining
            log_emit(sid_to_token[request.sid], f"Count capped to {remaining} (remaining allowance)", "inf")

    if count <= 0:
        emit("limit_reached", {"used": used, "limit": limit}); return

    sess["state"] = fresh_state()
    sess["state"].update(running=True, target=count, last_license_check=time.time())
    emit("started", {"count": count})
    log_emit(sid_to_token[request.sid], f"Starting {count} accounts ({concurrent} concurrent)...", "inf")

    token = sid_to_token[request.sid]
    threading.Thread(target=run_generator, args=(token, count, concurrent), daemon=True).start()

@socketio.on("stop")
def on_stop():
    sess = socket_session()
    if not sess: return
    sess["state"]["stop"] = True
    emit("stopped")
    log_emit(sid_to_token[request.sid], "Stopping...", "inf")

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
    --bg: #080b0f;
    --surface: #0d1117;
    --surface2: #161b22;
    --surface3: #1c2330;
    --border: #21262d;
    --border2: #30363d;
    --cyan: #58a6ff;
    --cyan-glow: rgba(88,166,255,0.15);
    --cyan-dim: rgba(88,166,255,0.08);
    --green: #3fb950;
    --green-glow: rgba(63,185,80,0.15);
    --red: #f85149;
    --red-dim: rgba(248,81,73,0.1);
    --gold: #d29922;
    --gold-dim: rgba(210,153,34,0.1);
    --purple: #a371f7;
    --purple-dim: rgba(163,113,247,0.1);
    --text: #c9d1d9;
    --text2: #8b949e;
    --text3: #484f58;
    --mono: 'Space Mono', monospace;
    --sans: 'Syne', sans-serif;
    --radius: 8px;
    --radius-lg: 12px;
    --radius-xl: 16px;
  }
  html, body { height: 100%; background: var(--bg); color: var(--text); font-family: var(--mono); }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }

  /* ── LICENSE SCREEN ── */
  .lic-wrap {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px 16px;
    background: radial-gradient(ellipse 70% 50% at 50% -10%, rgba(88,166,255,0.08) 0%, transparent 60%), var(--bg);
  }
  .lic-card {
    width: 100%;
    max-width: 500px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-xl);
    padding: 40px 32px 32px;
    position: relative;
    overflow: hidden;
  }
  .lic-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
  }
  .lic-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
  }
  .lic-icon {
    width: 40px; height: 40px;
    background: var(--cyan-dim);
    border: 1px solid rgba(88,166,255,0.3);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }
  .lic-logo {
    font-family: var(--sans);
    font-size: 28px;
    font-weight: 800;
    color: var(--cyan);
    letter-spacing: 4px;
  }
  .lic-sub {
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text2);
    margin-bottom: 32px;
    padding-left: 52px;
  }
  .lic-label {
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text2);
    margin-bottom: 8px;
    display: block;
  }
  .lic-input {
    width: 100%;
    padding: 13px 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--cyan);
    font-family: var(--mono);
    font-size: 13px;
    letter-spacing: 2px;
    outline: none;
    transition: border-color .2s, box-shadow .2s;
    margin-bottom: 12px;
  }
  .lic-input:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px var(--cyan-dim); }
  .lic-input::placeholder { color: var(--text3); letter-spacing: 1px; }
  .lic-btn {
    width: 100%;
    padding: 14px;
    background: var(--cyan);
    border: none;
    border-radius: var(--radius);
    color: #0d1117;
    font-family: var(--sans);
    font-weight: 800;
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    cursor: pointer;
    transition: all .2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }
  .lic-btn:hover { filter: brightness(1.1); transform: translateY(-1px); box-shadow: 0 8px 32px var(--cyan-glow); }
  .lic-btn.loading { opacity: .6; pointer-events: none; }
  .lic-err { font-size: 11px; min-height: 20px; margin-top: 10px; text-align: center; letter-spacing: .5px; color: var(--red); }

  /* pricing */
  .price-section { margin-top: 28px; padding-top: 24px; border-top: 1px solid var(--border); }
  .price-title {
    font-size: 10px;
    letter-spacing: 3px;
    color: var(--text3);
    margin-bottom: 14px;
    text-align: center;
    text-transform: uppercase;
  }
  .price-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 20px; }
  .price-card {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 10px;
    text-align: center;
    transition: border-color .2s, transform .2s;
    cursor: default;
  }
  .price-card:hover { border-color: var(--border2); transform: translateY(-2px); }
  .price-card.featured { border-color: rgba(88,166,255,0.4); background: rgba(88,166,255,0.05); }
  .price-badge {
    display: inline-block;
    font-size: 9px;
    letter-spacing: 1.5px;
    color: var(--cyan);
    background: var(--cyan-dim);
    border-radius: 20px;
    padding: 2px 8px;
    margin-bottom: 8px;
    text-transform: uppercase;
  }
  .price-name { font-family: var(--sans); font-size: 11px; font-weight: 700; color: var(--text); letter-spacing: 1px; margin-bottom: 4px; }
  .price-limit { font-size: 9px; color: var(--text2); letter-spacing: 1px; margin-bottom: 10px; }
  .price-amt { font-family: var(--sans); font-size: 16px; font-weight: 800; color: var(--text); }
  .price-card.featured .price-amt { color: var(--cyan); }
  .price-php { font-size: 9px; color: var(--text2); margin-top: 2px; }

  /* discord */
  .discord-section { text-align: center; }
  .discord-label { font-size: 10px; color: var(--text2); letter-spacing: 1px; margin-bottom: 10px; }
  .discord-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: 12px 24px;
    background: rgba(88,101,242,0.08);
    border: 1px solid rgba(88,101,242,0.35);
    border-radius: var(--radius);
    color: #8a96ff;
    font-family: var(--mono);
    font-size: 12px;
    letter-spacing: 1px;
    text-decoration: none;
    transition: all .2s;
    width: 100%;
  }
  .discord-btn:hover { background: rgba(88,101,242,0.15); color: #fff; transform: translateY(-1px); }
  .lic-footer {
    display: flex;
    justify-content: space-between;
    font-size: 10px;
    color: var(--text3);
    margin-top: 24px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
  }
  .status-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); display: inline-block; margin-right: 6px; vertical-align: middle; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  /* ── MAIN APP ── */
  .app { min-height: 100vh; max-width: 620px; margin: 0 auto; padding: 20px 16px 60px; display: flex; flex-direction: column; gap: 14px; }

  /* header */
  .hdr {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 16px 0 16px;
    border-bottom: 1px solid var(--border);
  }
  .hdr-icon {
    width: 44px; height: 44px;
    background: var(--cyan-dim);
    border: 1px solid rgba(88,166,255,0.25);
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }
  .hdr-logo { font-family: var(--sans); font-size: 20px; font-weight: 800; color: var(--cyan); letter-spacing: 3px; }
  .hdr-sub { font-size: 10px; color: var(--text2); letter-spacing: 2px; margin-top: 2px; }
  .hdr-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
  .ver-badge {
    font-size: 10px;
    color: var(--text2);
    background: var(--surface2);
    padding: 4px 10px;
    border-radius: 20px;
    border: 1px solid var(--border);
    letter-spacing: .5px;
  }
  .plan-badge {
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--gold);
    background: var(--gold-dim);
    border: 1px solid rgba(210,153,34,.3);
    border-radius: 20px;
    padding: 4px 12px;
  }

  /* status bar */
  .status-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: var(--text2);
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .status-bar .s-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text3); flex-shrink: 0; }
  .status-bar.running .s-dot { background: var(--gold); animation: pulse 1s infinite; }
  .status-bar.done .s-dot { background: var(--green); }
  .status-bar.stopped .s-dot, .status-bar.limit .s-dot { background: var(--red); }
  .status-bar .s-text { color: var(--text); }
  .status-bar .s-icon { margin-left: auto; font-size: 16px; }

  /* stats grid */
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 12px 12px;
    text-align: center;
    position: relative;
    overflow: hidden;
    transition: border-color .2s;
  }
  .stat:hover { border-color: var(--border2); }
  .stat-icon { font-size: 18px; display: block; margin-bottom: 6px; }
  .stat-val { font-family: var(--sans); font-size: 28px; font-weight: 800; display: block; line-height: 1; }
  .stat-lbl { font-size: 9px; color: var(--text2); letter-spacing: 2px; margin-top: 6px; display: block; text-transform: uppercase; }
  .stat-bar { position: absolute; bottom: 0; left: 0; right: 0; height: 2px; }
  .s-created .stat-val { color: var(--green); }
  .s-created .stat-bar { background: var(--green); opacity: .6; }
  .s-active .stat-val { color: var(--cyan); }
  .s-active .stat-bar { background: var(--cyan); opacity: .6; }
  .s-failed .stat-val { color: var(--red); }
  .s-failed .stat-bar { background: var(--red); opacity: .6; }
  .s-target .stat-val { color: var(--gold); }
  .s-target .stat-bar { background: var(--gold); opacity: .6; }

  /* limit bar */
  .limit-bar-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px;
  }
  .limit-bar-top { display: flex; justify-content: space-between; font-size: 11px; color: var(--text2); margin-bottom: 10px; letter-spacing: 1px; }
  .limit-bar-top .lbl { display: flex; align-items: center; gap: 6px; }
  .limit-bar-track { height: 6px; background: var(--border); border-radius: 6px; overflow: hidden; }
  .limit-bar-fill { height: 100%; background: var(--cyan); border-radius: 6px; transition: width .4s ease; }
  .limit-bar-fill.warn { background: var(--gold); }
  .limit-bar-fill.danger { background: var(--red); }

  /* config card */
  .config-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .config-hdr {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text2);
    cursor: pointer;
    user-select: none;
    transition: background .15s;
    text-transform: uppercase;
  }
  .config-hdr:hover { background: var(--surface2); }
  .config-hdr-icon { font-size: 14px; }
  .config-toggle { margin-left: auto; font-size: 10px; letter-spacing: 1px; color: var(--text3); }
  .config-body { padding: 16px; display: flex; flex-direction: column; gap: 14px; }

  /* count row */
  .config-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  .config-field { display: flex; align-items: center; gap: 10px; }
  .config-label { font-size: 10px; letter-spacing: 1.5px; color: var(--text2); white-space: nowrap; text-transform: uppercase; }
  .config-input {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--cyan);
    font-family: var(--mono);
    font-size: 13px;
    padding: 7px 12px;
    width: 80px;
    outline: none;
    transition: border-color .2s;
  }
  .config-input:focus { border-color: var(--cyan); }

  /* panel (proxies) */
  .panel-wrap {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .panel-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 11px;
    letter-spacing: 1.5px;
    color: var(--text2);
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    user-select: none;
    transition: background .15s;
    text-transform: uppercase;
  }
  .panel-label:hover { background: var(--surface2); color: var(--text); }
  .panel-label-icon { font-size: 14px; }
  .panel-badge { margin-left: auto; font-size: 10px; color: var(--text3); }
  .panel-badge.ok { color: var(--green); }
  .panel-inner { display: none; }
  .panel-inner.open { display: block; }
  .panel-textarea {
    width: 100%;
    min-height: 90px;
    padding: 12px 14px;
    resize: vertical;
    background: transparent;
    border: none;
    outline: none;
    color: var(--cyan);
    font-family: var(--mono);
    font-size: 11px;
    line-height: 1.8;
  }
  .panel-textarea::placeholder { color: var(--text3); }
  .panel-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-top: 1px solid var(--border);
  }
  .panel-btn {
    padding: 6px 16px;
    background: transparent;
    border: 1px solid var(--cyan);
    border-radius: var(--radius);
    color: var(--cyan);
    font-family: var(--sans);
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 2px;
    cursor: pointer;
    transition: all .15s;
    text-transform: uppercase;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .panel-btn:hover { background: var(--cyan); color: var(--bg); }
  .panel-status { font-size: 10px; color: var(--text2); letter-spacing: 1px; margin-left: auto; }

  /* webhook */
  .webhook-wrap {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    transition: border-color .3s;
  }
  .webhook-wrap.required { border-color: rgba(248,81,73,.5); }
  .webhook-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    border-bottom: 1px solid var(--border);
  }
  .webhook-icon { font-size: 14px; flex-shrink: 0; }
  .webhook-lbl { font-size: 10px; letter-spacing: 1.5px; color: var(--text2); white-space: nowrap; flex-shrink: 0; text-transform: uppercase; }
  .webhook-wrap.required .webhook-lbl { color: var(--red); }
  .webhook-input {
    flex: 1;
    padding: 11px 0;
    background: transparent;
    border: none;
    outline: none;
    color: var(--cyan);
    font-family: var(--mono);
    font-size: 11px;
  }
  .webhook-input::placeholder { color: var(--text3); }
  .webhook-req-note { font-size: 9px; padding: 4px 14px 2px; color: var(--red); letter-spacing: 1px; display: none; }
  .webhook-wrap.required .webhook-req-note { display: block; }

  /* warn / limit banners */
  .warn-banner {
    background: var(--gold-dim);
    border: 1px solid rgba(210,153,34,.35);
    border-radius: var(--radius);
    padding: 12px 16px;
    font-size: 11px;
    color: var(--gold);
    display: none;
    align-items: flex-start;
    gap: 10px;
    line-height: 1.6;
  }
  .warn-banner.show { display: flex; }
  .warn-banner .warn-icon { font-size: 16px; flex-shrink: 0; }
  .warn-banner strong { color: var(--text); }
  .limit-banner {
    background: var(--red-dim);
    border: 1px solid rgba(248,81,73,.3);
    border-radius: var(--radius);
    padding: 12px 16px;
    font-size: 11px;
    color: var(--red);
    display: none;
    align-items: center;
    gap: 10px;
  }
  .limit-banner.show { display: flex; }

  /* tutorial */
  .tutorial-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .tutorial-hdr {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    letter-spacing: 1.5px;
    color: var(--text2);
    cursor: pointer;
    user-select: none;
    transition: background .15s;
    text-transform: uppercase;
  }
  .tutorial-hdr:hover { background: var(--surface2); }
  .tutorial-hdr-icon { font-size: 14px; }
  .tutorial-body { display: none; padding: 16px; }
  .tutorial-body.open { display: block; }
  .video-container {
    position: relative;
    width: 100%;
    padding-top: 56.25%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .video-el { position: absolute; inset: 0; width: 100%; height: 100%; }

  /* RUN BUTTON */
  .run-btn {
    width: 100%;
    padding: 16px;
    border: none;
    border-radius: var(--radius-lg);
    font-family: var(--sans);
    font-weight: 800;
    font-size: 14px;
    letter-spacing: 3px;
    text-transform: uppercase;
    cursor: pointer;
    transition: all .2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
  }
  .run-btn.idle {
    background: linear-gradient(135deg, rgba(88,166,255,0.15), rgba(88,166,255,0.05));
    border: 1px solid rgba(88,166,255,0.5);
    color: var(--cyan);
  }
  .run-btn.idle:hover {
    background: var(--cyan);
    color: var(--bg);
    box-shadow: 0 8px 32px var(--cyan-glow);
    transform: translateY(-1px);
  }
  .run-btn.stop {
    background: linear-gradient(135deg, rgba(248,81,73,0.12), rgba(248,81,73,0.05));
    border: 1px solid rgba(248,81,73,.5);
    color: var(--red);
  }
  .run-btn.stop:hover { background: rgba(248,81,73,.08); }
  .run-btn.disabled-btn { opacity: .35; pointer-events: none; border: 1px solid var(--border); color: var(--text2); background: transparent; }

  /* LOG */
  .log-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    overflow: hidden;
  }
  .log-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    border-bottom: 1px solid var(--border);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text2);
    text-transform: uppercase;
  }
  .log-header-icon { font-size: 14px; }
  .log-clear {
    font-size: 10px;
    color: var(--text3);
    background: none;
    border: none;
    cursor: pointer;
    font-family: var(--mono);
    padding: 3px 8px;
    border-radius: 4px;
    margin-left: auto;
    transition: color .2s, background .2s;
    letter-spacing: 1px;
  }
  .log-clear:hover { color: var(--text); background: var(--surface2); }
  .log-box { padding: 12px 16px; height: 240px; overflow-y: auto; font-size: 11px; line-height: 1.9; }
  .log-line { display: flex; gap: 10px; margin-bottom: 1px; }
  .log-ts { color: var(--text3); flex-shrink: 0; }
  .log-tag { flex-shrink: 0; font-size: 9px; letter-spacing: 1px; }
  .ok .log-tag { color: var(--green); }
  .ok .log-msg { color: #56d364; }
  .err .log-tag { color: var(--red); }
  .err .log-msg { color: var(--red); }
  .dim .log-tag { color: var(--text3); }
  .dim .log-msg { color: var(--text2); }
  .inf .log-tag { color: var(--cyan); }
  .inf .log-msg { color: var(--cyan); }

  /* footer */
  .footer { display: flex; justify-content: space-between; font-size: 10px; color: var(--text3); padding-top: 4px; letter-spacing: 1px; }
  .footer a { color: var(--text3); text-decoration: none; transition: color .2s; }
  .footer a:hover { color: var(--red); }

  /* proxy info strip */
  .proxy-strip {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    background: rgba(63,185,80,0.06);
    border-top: 1px solid var(--border);
    font-size: 10px;
    color: var(--text2);
    letter-spacing: 1px;
  }
  .proxy-strip .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
  .proxy-strip.empty .dot { background: var(--text3); animation: none; }
  .proxy-strip.empty { background: transparent; }

  @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
  .animate-in { animation: fadeIn .3s ease forwards; }

  @media (max-width: 480px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
    .lic-card { padding: 32px 20px 24px; }
    .price-grid { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div id="app"></div>
<script>
let licenseInfo = null;
let sessionToken = null;
let socket = null;
let running = false;
let webhookSet = false;
let cfgOpen = true;
let tutOpen = false;

const ERR_MAP = {
  not_found:     'invalid license key — contact kuni',
  disabled:      'this license has been disabled',
  expired:       'license has expired — contact kuni',
  hwid_mismatch: 'key is bound to another machine',
  limit_reached: 'account limit reached — upgrade your plan',
  rate_limited:  'too many attempts — wait 1 min',
  server_error:  'server error — try again later',
};

function getLsToken() {
  let t = localStorage.getItem('_kuni_lst');
  if (!t) { t = [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2,'0')).join(''); localStorage.setItem('_kuni_lst', t); }
  return t;
}

async function getCanvasFp() {
  try {
    const c = document.createElement('canvas'), ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069'; ctx.fillText('kuni-fp', 2, 15);
    return c.toDataURL().slice(-64);
  } catch { return ''; }
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function getDeviceFingerprint() {
  try {
    const raw = [navigator.userAgent, navigator.language, screen.width+'x'+screen.height, screen.colorDepth, new Date().getTimezoneOffset(), navigator.hardwareConcurrency||0, navigator.platform, await getCanvasFp()].join('|');
    return await sha256Hex(raw);
  } catch {
    let id = localStorage.getItem('_did');
    if (!id) { id = Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2); localStorage.setItem('_did', id); }
    return id;
  }
}

async function getExtraFp() {
  return await sha256Hex(navigator.userAgent + navigator.platform);
}

async function authFetch(url, opts) {
  opts = opts || {};
  const headers = Object.assign({'Content-Type': 'application/json'}, opts.headers || {});
  if (sessionToken) headers['X-Session-Token'] = sessionToken;
  return fetch(url, Object.assign({}, opts, {headers}));
}

/* ─────────────────────────────────── LICENSE SCREEN ─── */
function showLicenseScreen() {
  document.getElementById('app').innerHTML = `
    <div class="lic-wrap animate-in">
      <div class="lic-card">
        <div class="lic-brand">
          <div class="lic-icon"></div>
          <div class="lic-logo">KUNI</div>
        </div>
        <div class="lic-sub">Auto SB Gen &nbsp;·&nbsp; v2.6</div>

        <span class="lic-label">LICENSE KEY</span>
        <input class="lic-input" id="licInput" type="text" placeholder="KUNI-XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false">
        <button class="lic-btn" id="licBtn" onclick="doLogin()">
          <span></span> Verify License
        </button>
        <div class="lic-err" id="licErr"></div>

        <div class="price-section">
          <div class="price-title">Pricing Plans</div>
          <div class="price-grid">
            <div class="price-card">
              <div class="price-name">BASIC</div>
              <div class="price-limit">100 accounts</div>
              <div class="price-amt">$59.99</div>
              <div class="price-php">≈ ₱3,389 · 30 days</div>
            </div>
            <div class="price-card featured">
              <div class="price-badge">POPULAR</div>
              <div class="price-name">PRO</div>
              <div class="price-limit">500 accounts</div>
              <div class="price-amt">$249.99</div>
              <div class="price-php">≈ ₱14,124 · 30 days</div>
            </div>
            <div class="price-card">
              <div class="price-name">UNLIMITED</div>
              <div class="price-limit">no limit</div>
              <div class="price-amt">$399.99</div>
              <div class="price-php">≈ ₱22,599 · 60 days</div>
            </div>
          </div>
          <div class="discord-section">
            <div class="discord-label">join our server to purchase</div>
            <a class="discord-btn" href="https://discord.gg/Qvy4BSGJvC" target="_blank">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
              Join <strong style="color:#fff">Kuni Server</strong>
            </a>
          </div>
        </div>

        <div class="lic-footer">
          <span><span class="status-dot"></span>kuni tool</span>
          <span>v2.6 · 2025</span>
        </div>
      </div>
    </div>`;
  document.getElementById('licInput').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
}

async function doLogin() {
  const key = document.getElementById('licInput').value.trim();
  const err = document.getElementById('licErr');
  const btn = document.getElementById('licBtn');
  if (!key) { err.style.color='var(--gold)'; err.textContent='⚠ please enter a license key'; return; }
  btn.classList.add('loading'); btn.textContent = 'Verifying...';
  err.style.color='var(--text2)'; err.textContent='connecting...';
  try {
    const [hwid, fp] = await Promise.all([getDeviceFingerprint(), getExtraFp()]);
    const ls_token = getLsToken();
    const res = await fetch('/verify-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key, hwid, ls_token, fp})});
    const data = await res.json();
    if (data.valid) {
      sessionToken = data.session_token;
      localStorage.setItem('license', key);
      localStorage.setItem('session_token', sessionToken);
      if (data.ls_token) localStorage.setItem('_kuni_lst', data.ls_token);
      licenseInfo = data;
      err.style.color='var(--green)'; err.textContent='license valid — loading...';
      setTimeout(showMainApp, 600);
    } else {
      btn.classList.remove('loading'); btn.innerHTML='<span></span> Verify License';
      err.style.color='var(--red)'; err.textContent = ''+(ERR_MAP[data.error] || 'invalid license — contact kuni');
    }
  } catch {
    btn.classList.remove('loading'); btn.innerHTML='<span></span> Verify License';
    err.style.color='var(--red)'; err.textContent='server error';
  }
}

/* ─────────────────────────────────── MAIN APP ─── */
function showMainApp() {
  const planLabel = licenseInfo ? licenseInfo.plan : '-';
  const isUnlimited = licenseInfo && licenseInfo.limit >= 9999;

  document.getElementById('app').innerHTML = `
    <div class="app animate-in">
      <!-- Header -->
      <div class="hdr">
        <div class="hdr-icon"></div>
        <div>
          <div class="hdr-logo">KUNI</div>
          <div class="hdr-sub">AUTO SB GEN · SCRIPTBLOX</div>
        </div>
        <div class="hdr-right">
          <span class="plan-badge" id="planBadge">${planLabel}</span>
          <div class="ver-badge">v2.6</div>
        </div>
      </div>

      <!-- Status -->
      <div class="status-bar idle" id="statusBar">
        <span class="s-dot"></span>
        <span class="s-text" id="statusText">idle — ready to generate</span>
        <span class="s-icon" id="statusIcon"></span>
      </div>

      <!-- Webhook warning -->
      <div class="warn-banner" id="webhookWarn">
        <span class="warn-icon"></span>
        <div><strong>Discord webhook required.</strong> Set your webhook below before running the generator.</div>
      </div>

      <!-- Stats -->
      <div class="stats">
        <div class="stat s-created">
          <span class="stat-icon"></span>
          <span class="stat-val" id="s-created">0</span>
          <span class="stat-lbl">Created</span>
          <div class="stat-bar"></div>
        </div>
        <div class="stat s-active">
          <span class="stat-icon"></span>
          <span class="stat-val" id="s-active">0</span>
          <span class="stat-lbl">Active</span>
          <div class="stat-bar"></div>
        </div>
        <div class="stat s-failed">
          <span class="stat-icon"></span>
          <span class="stat-val" id="s-failed">0</span>
          <span class="stat-lbl">Failed</span>
          <div class="stat-bar"></div>
        </div>
        <div class="stat s-target">
          <span class="stat-icon"></span>
          <span class="stat-val" id="s-target">0</span>
          <span class="stat-lbl">Target</span>
          <div class="stat-bar"></div>
        </div>
      </div>

      <!-- Limit bar -->
      ${!isUnlimited ? `
      <div class="limit-bar-wrap">
        <div class="limit-bar-top">
          <span class="lbl">Account Usage</span>
          <span id="limitText" style="color:var(--text)">loading...</span>
        </div>
        <div class="limit-bar-track"><div class="limit-bar-fill" id="limitBar" style="width:0%"></div></div>
      </div>` : ''}

      <!-- Limit banner -->
      <div class="limit-banner" id="limitBanner">
        <span></span>
        <span>Account limit reached — contact Kuni to upgrade your plan.</span>
      </div>

      <!-- Config -->
      <div class="config-card">
        <div class="config-hdr" onclick="toggleConfig()">
          <span class="config-hdr-icon"></span>
          <span>Configuration</span>
          <span class="config-toggle" id="cfgToggle">HIDE</span>
        </div>
        <div class="config-body" id="cfgBody">

          <!-- Count + Concurrent -->
          <div class="config-row">
            <div class="config-field">
              <span class="config-label">Count</span>
              <input class="config-input" type="number" id="count" value="10" min="1" max="9999">
            </div>
            <div class="config-field">
              <span class="config-label">Concurrent</span>
              <input class="config-input" type="number" id="concurrent" value="10" min="1" max="50">
            </div>
          </div>

          <!-- Proxies -->
          <div class="panel-wrap">
            <div class="panel-label" onclick="togglePanel('proxyPanel')">
              <span class="panel-label-icon"></span>
              <span>Proxies (rotating)</span>
              <span class="panel-badge" id="proxyBadge">loading...</span>
            </div>
            <div class="panel-inner" id="proxyPanel">
              <textarea class="panel-textarea" id="proxyTA" placeholder="paste proxies — one per line&#10;user:pass@host:port  or  host:port  or  http://user:pass@host:port&#10;&#10;each account uses a random proxy from this list"></textarea>
              <div class="proxy-strip empty" id="proxyStrip">
                <span class="dot"></span>
                <span id="proxyStripTxt">no proxies loaded</span>
              </div>
              <div class="panel-actions">
                <button class="panel-btn" onclick="saveProxies()">Save Proxies</button>
                <span class="panel-status" id="proxySt"></span>
              </div>
            </div>
          </div>

          <!-- Webhook -->
          <div class="webhook-wrap" id="webhookWrap">
            <div class="webhook-row">
              <span class="webhook-icon">📡</span>
              <span class="webhook-lbl">Webhook <span id="webhookReqMark" style="color:var(--red)">*</span></span>
              <input class="webhook-input" id="webhookInput" type="text" placeholder="https://discord.com/api/webhooks/...">
            </div>
            <div class="webhook-req-note">⚠ Required — accounts are delivered here</div>
            <div class="panel-actions">
              <button class="panel-btn" onclick="saveWebhook()">📡 Save &amp; Test</button>
              <span class="panel-status" id="webhookSt"></span>
            </div>
          </div>

        </div>
      </div>

      <!-- Run Button -->
      <button class="run-btn idle" id="mainBtn" onclick="toggle()">
        <span></span> Run Generator
      </button>

      <!-- Tutorial -->
      <div class="tutorial-card">
        <div class="tutorial-hdr" onclick="toggleTutorial()">
          <span class="tutorial-hdr-icon"></span>
          <span>How to use your accounts</span>
          <span id="tutToggle" style="margin-left:auto;font-size:9px;letter-spacing:2px;color:var(--text3)">SHOW</span>
        </div>
        <div class="tutorial-body" id="tutBody">
          <div class="video-container">
            <iframe src="https://drive.google.com/file/d/1KgpnvPBwSzS75rAcTzDo8MIunPc9RVtM/preview" class="video-el" frameborder="0" allowfullscreen allow="autoplay" sandbox="allow-scripts allow-same-origin allow-presentation"></iframe>
          </div>
        </div>
      </div>

      <!-- Log -->
      <div class="log-wrap">
        <div class="log-header">
          <span class="log-header-icon"></span>
          <span>Log Output</span>
          <button class="log-clear" onclick="clearLog()">🗑 clear</button>
        </div>
        <div class="log-box" id="logBox"></div>
      </div>

      <!-- Footer -->
      <div class="footer">
        <span>kuni tool · v2.6</span>
        <a href="#" onclick="doLogout();return false;">logout</a>
      </div>
    </div>`;

  loadSavedConfig();
  updateLimitBar();
  initSocket();
}

function toggleConfig() {
  cfgOpen = !cfgOpen;
  document.getElementById('cfgBody').style.display = cfgOpen ? 'flex' : 'none';
  document.getElementById('cfgToggle').textContent = cfgOpen ? 'HIDE' : 'SHOW';
}
function togglePanel(id) { document.getElementById(id).classList.toggle('open'); }
function toggleTutorial() {
  tutOpen = !tutOpen;
  document.getElementById('tutBody').classList.toggle('open', tutOpen);
  document.getElementById('tutToggle').textContent = tutOpen ? 'HIDE' : 'SHOW';
}

function updateWebhookUI(hasWebhook) {
  webhookSet = hasWebhook;
  const wrap = document.getElementById('webhookWrap');
  const warn = document.getElementById('webhookWarn');
  const mark = document.getElementById('webhookReqMark');
  if (!wrap || !warn) return;
  if (hasWebhook) { wrap.classList.remove('required'); warn.classList.remove('show'); if (mark) mark.style.display='none'; }
  else { wrap.classList.add('required'); warn.classList.add('show'); if (mark) mark.style.display='inline'; }
}

function updateProxyStrip(count) {
  const strip = document.getElementById('proxyStrip');
  const txt = document.getElementById('proxyStripTxt');
  if (!strip || !txt) return;
  if (count > 0) {
    strip.classList.remove('empty');
    txt.textContent = count + ' proxies loaded — rotating per account';
  } else {
    strip.classList.add('empty');
    txt.textContent = 'no proxies loaded — using direct connection';
  }
}

async function loadSavedConfig() {
  try {
    const r = await authFetch('/get-proxies');
    const d = await r.json();
    if (d.ok) {
      const badge = document.getElementById('proxyBadge');
      badge.textContent = d.count > 0 ? d.count+' loaded' : 'none';
      badge.className = 'panel-badge'+(d.count>0?' ok':'');
      updateProxyStrip(d.count);
    }
  } catch {}
  try {
    const r = await authFetch('/get-webhook');
    const d = await r.json();
    if (d.ok) {
      updateWebhookUI(d.has_webhook);
      const st = document.getElementById('webhookSt');
      if (st) {
        if (d.has_webhook) { st.style.color='var(--green)'; st.textContent='connected'; }
        else { st.style.color='var(--red)'; st.textContent='not set'; }
      }
    }
  } catch {}
}

async function saveProxies() {
  const text = document.getElementById('proxyTA').value;
  const st = document.getElementById('proxySt');
  st.style.color='var(--text2)'; st.textContent='saving...';
  try {
    const r = await authFetch('/set-proxies',{method:'POST',body:JSON.stringify({proxies:text})});
    const d = await r.json();
    if (d.ok) {
      st.style.color='var(--green)'; st.textContent=''+d.count+' proxies saved';
      document.getElementById('proxyTA').value='';
      const b = document.getElementById('proxyBadge');
      b.textContent=d.count+' loaded'; b.className='panel-badge'+(d.count>0?' ok':'');
      updateProxyStrip(d.count);
      setTimeout(()=>togglePanel('proxyPanel'), 900);
    } else { st.style.color='var(--red)'; st.textContent=''+(d.error||'error'); }
  } catch { st.style.color='var(--red)'; st.textContent='request failed'; }
}

async function saveWebhook() {
  const wh = document.getElementById('webhookInput').value.trim();
  const st = document.getElementById('webhookSt');
  st.style.color='var(--text2)'; st.textContent = wh?'testing...':'clearing...';
  try {
    const r = await authFetch('/set-webhook',{method:'POST',body:JSON.stringify({webhook:wh})});
    const d = await r.json();
    if (d.ok) {
      if (wh) { st.style.color='var(--green)'; st.textContent = d.tested?'verified — test sent':'saved'; updateWebhookUI(true); }
      else { st.style.color='var(--gold)'; st.textContent='🗑 cleared'; updateWebhookUI(false); }
    } else {
      st.style.color='var(--red)';
      st.textContent = d.error==='invalid_webhook'?'invalid discord url':
                       d.error==='webhook_unreachable'?'test failed — check url':
                       d.error==='not_authenticated'?'session expired — refresh':
                       (''+(d.error||'error'));
    }
  } catch { st.style.color='var(--red)'; st.textContent='request failed'; }
}

function updateLimitBar() {
  if (!licenseInfo || licenseInfo.limit >= 9999) return;
  const used = licenseInfo.limit - (licenseInfo.accounts_left || 0);
  const limit = licenseInfo.limit;
  const pct = Math.min(100, Math.round(used/limit*100));
  const fill = document.getElementById('limitBar');
  if (fill) { fill.style.width=pct+'%'; fill.className='limit-bar-fill'+(pct>=90?' danger':pct>=70?' warn':''); }
  const txt = document.getElementById('limitText');
  if (txt) txt.textContent = used + ' / ' + limit + ' (' + (100-pct) + '% left)';
}

function showLimitReached(used, limit, reason) {
  const banner = document.getElementById('limitBanner');
  if (banner) {
    banner.classList.add('show');
    banner.innerHTML = '<span></span><span>'+(reason==='revoked'?'License revoked — contact Kuni':reason==='expired'?'License expired — contact Kuni':'Account limit reached — upgrade to continue.')+'</span>';
  }
  const btn = document.getElementById('mainBtn');
  if (btn) { btn.className='run-btn disabled-btn'; btn.innerHTML='<span></span> Unavailable'; }
  setStatus('limit', ''+(reason||'limit reached')+' — '+used+'/'+limit);
}

function setStatus(mode, text) {
  const bar = document.getElementById('statusBar');
  const ico = document.getElementById('statusIcon');
  if (bar) { bar.className='status-bar '+mode; document.getElementById('statusText').textContent=text; }
  if (ico) {
    const iconMap = { idle:'⬛', running:'🟡', done:'🟢', stopped:'🔴', limit:'🔴' };
    ico.textContent = iconMap[mode] || '⬛';
  }
}

function clearLog() { const b=document.getElementById('logBox'); if(b) b.innerHTML=''; }

async function doLogout() {
  try { if (sessionToken) await fetch('/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_token:sessionToken})}); } catch {}
  localStorage.removeItem('license'); localStorage.removeItem('session_token');
  sessionToken = null;
  location.reload();
}

function initSocket() {
  socket = io({ auth: { token: sessionToken } });

  socket.on('auth_failed', () => {
    localStorage.removeItem('license'); localStorage.removeItem('session_token');
    sessionToken = null;
    alert('Session expired — please log in again.');
    location.reload();
  });

  window.toggle = function() {
    if (running) { socket.emit('stop'); return; }
    if (!webhookSet) {
      setStatus('stopped', 'webhook required — set it first');
      const warn = document.getElementById('webhookWarn');
      if (warn) { warn.classList.add('show'); warn.scrollIntoView({behavior:'smooth',block:'center'}); }
      cfgOpen = true;
      document.getElementById('cfgBody').style.display='flex';
      document.getElementById('cfgToggle').textContent='HIDE';
      const inp = document.getElementById('webhookInput');
      if (inp) inp.focus();
      return;
    }
    const count=parseInt(document.getElementById('count').value)||10;
    const concurrent=parseInt(document.getElementById('concurrent').value)||10;
    socket.emit('start',{count,concurrent});
  };

  socket.on('started', d => {
    running = true;
    const btn = document.getElementById('mainBtn');
    btn.className='run-btn stop'; btn.innerHTML='<span>⏹</span> Stop Generator';
    setStatus('running','running — generating '+d.count+' accounts');
  });

  socket.on('start_blocked', d => {
    running = false;
    setStatus('stopped', ''+(d.message||'blocked'));
    if (d.reason==='webhook_required') {
      updateWebhookUI(false);
      const warn = document.getElementById('webhookWarn');
      if (warn) warn.scrollIntoView({behavior:'smooth',block:'center'});
    }
  });

  socket.on('stopped', () => {
    running = false;
    const btn = document.getElementById('mainBtn');
    btn.className='run-btn idle'; btn.innerHTML='<span></span> Run Generator';
    setStatus('stopped','⏹ stopped by user');
  });

  socket.on('done', d => {
    running = false;
    const btn = document.getElementById('mainBtn');
    btn.className='run-btn idle'; btn.innerHTML='<span></span> Run Generator';
    setStatus('done','done — '+d.created+'/'+d.total+' accounts created');
  });

  socket.on('stats', d => {
    document.getElementById('s-created').textContent=d.created;
    document.getElementById('s-active').textContent=d.active;
    document.getElementById('s-failed').textContent=d.failed;
    document.getElementById('s-target').textContent=d.target;
    if (licenseInfo && licenseInfo.limit < 9999) {
      const used = (licenseInfo.used||0) + d.created;
      const pct  = Math.min(100, Math.round(used/licenseInfo.limit*100));
      const fill = document.getElementById('limitBar');
      if (fill) { fill.style.width=pct+'%'; fill.className='limit-bar-fill'+(pct>=90?' danger':pct>=70?' warn':''); }
      const txt = document.getElementById('limitText');
      if (txt) txt.textContent = used + ' / ' + licenseInfo.limit + ' (' + Math.max(0,100-pct) + '% left)';
    }
  });

  socket.on('log', d => {
    const box=document.getElementById('logBox');
    if (!box) return;
    const line=document.createElement('div');
    const tag = {ok:'',err:'',dim:'·',inf:'ℹ'}[d.tag||'dim'] || '·';
    line.className='log-line '+(d.tag||'dim');
    const msg=d.msg||'';
    const m=msg.match(/^\[(\d{2}:\d{2}:\d{2})\]\s*(.*)/s);
    if (m) line.innerHTML=`<span class="log-ts">${m[1]}</span><span class="log-tag">${tag}</span><span class="log-msg">${m[2]}</span>`;
    else   line.innerHTML=`<span class="log-tag">${tag}</span><span class="log-msg">${msg}</span>`;
    box.appendChild(line); box.scrollTop=box.scrollHeight;
  });

  socket.on('limit_reached', d => {
    running = false;
    showLimitReached(d.used||0, d.limit||0, d.reason);
  });
}

/* ─── AUTO-LOGIN ─── */
const savedKey = localStorage.getItem('license');
const savedToken = localStorage.getItem('session_token');
if (savedKey && savedToken) {
  (async () => {
    const [hwid, fp] = await Promise.all([getDeviceFingerprint(), getExtraFp()]);
    const ls_token = getLsToken();
    try {
      const r = await fetch('/verify-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:savedKey,hwid,ls_token,fp})});
      const d = await r.json();
      if (d.valid) {
        sessionToken = d.session_token;
        localStorage.setItem('session_token', sessionToken);
        licenseInfo = d;
        showMainApp();
      } else {
        localStorage.removeItem('license'); localStorage.removeItem('session_token');
        showLicenseScreen();
      }
    } catch { showLicenseScreen(); }
  })();
} else {
  showLicenseScreen();
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return HTML

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[KUNI] v2.6 running on http://localhost:{port}\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
