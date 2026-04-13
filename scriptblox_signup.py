# scriptblox_signup.py — Kuni Tool · SB Account Generator
# Web UI — deploy on Railway, Render, or run locally
# Open http://localhost:5000 in browser

import asyncio
import json
import os
import random
import re
import string
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote


import requests
import urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
from flask import Flask, request, jsonify
import hashlib
from flask_socketio import SocketIO, emit

from turnstile_solver import solve_turnstile_capsolver
from proxy_util import load_proxies, get_random_proxy, proxy_display

load_dotenv()
SUPABASE_URL = "https://ukwltgxtfikrpsqfihi.supabase.co"
SUPABASE_KEY = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"

license_valid = False
current_key = None

def get_hwid(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

ACCOUNTS_FILE   = Path(__file__).parent / "scriptblox_accounts.txt"
SB_SIGNUP       = "https://scriptblox.com/api/auth/signup"
MW_DOMAIN       = "aula.edu.pl"
MW_BASE         = "https://mailwave.dev"
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")
NO_PROXY        = {"http": None, "https": None}

proxies_list = load_proxies()
file_lock    = threading.Lock()

app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

state = {
    "running": False,
    "created": 0,
    "active":  0,
    "failed":  0,
    "target":  0,
    "stop":    False,
}


# ── MailWave ──────────────────────────────────────────────────────────────────

def mw_setup():
    try:
        r = requests.get(f"{MW_BASE}/", proxies=NO_PROXY, timeout=15)
        token = re.search(r'<meta name="csrf-token" content="([^"]+)"', r.text)
        csrf = token.group(1) if token else None
        return dict(r.cookies), csrf
    except:
        return None, None

def mw_get_email(cookies, csrf):
    if not csrf or cookies is None:
        return None, csrf
    for _ in range(20):
        alias = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        try:
            r = requests.post(f"{MW_BASE}/change",
                data={"_token": csrf, "name": alias, "domain": MW_DOMAIN},
                cookies=cookies, proxies=NO_PROXY, timeout=15)
            cookies.update(dict(r.cookies))
            new_csrf = unquote(cookies.get("XSRF-TOKEN", csrf))
            r2 = requests.post(f"{MW_BASE}/get_messages",
                headers={"Content-Type": "application/json", "X-CSRF-TOKEN": new_csrf},
                cookies=cookies, proxies=NO_PROXY, timeout=15)
            data = r2.json()
            mailbox = data.get("mailbox", "")
            if MW_DOMAIN in mailbox:
                return mailbox, new_csrf
        except:
            pass
    return None, csrf


# ── Discord Webhook ───────────────────────────────────────────────────────────

def send_webhook(username, password, email):
    if not DISCORD_WEBHOOK:
        return
    try:
        embed = {
            "title": "🎯 New Account Generated",
            "color": 0x00ffcc,
            "description": f"**{username}** | {email}",
            "fields": [
                {"name": "👤 Username", "value": f"```{username}```", "inline": True},
                {"name": "🔑 Password", "value": f"```{password}```", "inline": True},
                {"name": "📧 Email",    "value": f"```{email}```",    "inline": False},
                {"name": "📅 Created",  "value": datetime.now(timezone.utc).strftime("%b %d, %Y"), "inline": True},
                {"name": "⚡ Status",   "value": "⚠️ Unverified", "inline": True},
            ],
            "footer": {"text": "Kuni SB Generator"},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        requests.post(DISCORD_WEBHOOK,
            json={"content": "@everyone", "embeds": [embed]},
            proxies=NO_PROXY, timeout=10)
    except:
        pass


# ── Utils ─────────────────────────────────────────────────────────────────────

def rand_username(): return "Kuni" + "".join(random.choices(string.ascii_letters + string.digits, k=10))
def rand_password():  return "".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=14))

def proxy_to_requests(proxy):
    if not proxy: return None
    server = proxy.get("server", "")
    user   = proxy.get("username", "")
    pw     = proxy.get("password", "")
    if user:
        host = server.replace("http://", "").replace("https://", "")
        return {"http": f"http://{user}:{pw}@{host}", "https": f"http://{user}:{pw}@{host}"}
    return {"http": server, "https": server}

def sb_headers():
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Origin": "https://scriptblox.com",
        "Referer": "https://scriptblox.com/signup",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/143.0.0.0 Safari/537.36",
    }

def log_emit(msg, tag="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    socketio.emit("log", {"msg": f"[{ts}] {msg}", "tag": tag})
    socketio.emit("stats", {
        "created": state["created"],
        "active":  state["active"],
        "failed":  state["failed"],
        "target":  state["target"],
    })


# ── Core ──────────────────────────────────────────────────────────────────────

def create_account(slot):
    if state["stop"]: return

    username  = rand_username()
    password  = rand_password()
    proxy     = get_random_proxy(proxies_list)
    proxy_req = proxy_to_requests(proxy)

    # Get email + solve captcha
    cookies, csrf = mw_setup()
    captcha = solve_turnstile_capsolver()

    email_addr, _ = mw_get_email(cookies, csrf)

    if not email_addr or not captcha:
        state["failed"] += 1
        log_emit(f"[#{slot}] ✗ Setup failed", "err")
        return

    log_emit(f"[#{slot}] {email_addr} | Captcha ✓", "dim")

    try:
        r = requests.post(SB_SIGNUP, json={
            "email": email_addr, "username": username,
            "password": password, "repeatPassword": password,
            "terms": True, "captcha": captcha,
        }, headers=sb_headers(), proxies=proxy_req, timeout=30, verify=False)
        resp = r.json()
    except Exception as e:
        state["failed"] += 1
        log_emit(f"[#{slot}] ✗ Request error", "err")
        return

    if resp.get("error") or (isinstance(resp.get("statusCode"), int) and resp["statusCode"] >= 400):
        state["failed"] += 1
        log_emit(f"[#{slot}] ✗ Signup failed: {resp.get('message','')}", "err")
        return

    account = {"username": username, "password": password, "email": email_addr}
    with file_lock:
        with open(ACCOUNTS_FILE, "a") as f:
            f.write(json.dumps(account) + "\n")

    send_webhook(username, password, email_addr)
    state["created"] += 1
    log_emit(f"[#{slot}] ✓ {username}", "ok")


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
        t = threading.Thread(target=worker, args=(i + 1,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    state["running"] = False
    log_emit(f"✓ Done! {state['created']}/{count} accounts created.", "ok")
    socketio.emit("done", {"created": state["created"], "total": count})
@app.route("/verify-key", methods=["POST"])
def verify():

    global license_valid

    data = request.json
    key = data.get("key")

    hwid = get_hwid(request.remote_addr)

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }

    res = requests.get(
        f"{SUPABASE_URL}/rest/v1/licenses",
        headers=headers,
        params={"license_key": f"eq.{key}"}
    )

    data = res.json()

    if not data:
        return jsonify({"valid": False})

    license = data[0]

    if license["status"] != "active":
        return jsonify({"valid": False})

    if license["hwid"] and license["hwid"] != hwid:
        return jsonify({"valid": False})

    if not license["hwid"]:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/licenses",
            headers=headers,
            params={"license_key": f"eq.{key}"},
            json={"hwid": hwid}
        )

    license_valid = True
    current_key = key
    return jsonify({"valid": True})

# ── HTML ──────────────────────────────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KUNI · AUTO SB GEN</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#080c10;color:#c8d8e8;font-family:'IBM Plex Mono',monospace;min-height:100vh;padding:20px}
.container{max-width:480px;margin:0 auto}
.header{display:flex;align-items:baseline;gap:10px;padding:16px 0;border-bottom:1px solid #3a4a5a}
.header h1{font-size:28px;color:#00e5ff;font-weight:700;letter-spacing:2px}
.header span{color:#3a4a5a;font-size:11px}
.version{margin-left:auto;color:#3a4a5a;font-size:11px}
.status{color:#ffd700;font-size:11px;padding:10px 0}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:12px 0}
.stat{background:#111820;padding:12px 8px;text-align:center;border-radius:4px}
.stat-val{font-size:22px;font-weight:700;display:block}
.stat-lbl{font-size:9px;color:#3a4a5a;margin-top:4px;display:block;letter-spacing:1px}
.created{color:#00ff88}.active{color:#00e5ff}.failed{color:#ff3355}.target{color:#ffd700}
.config{display:flex;align-items:center;gap:12px;padding:12px 0;flex-wrap:wrap}
.config label{color:#3a4a5a;font-size:11px;letter-spacing:1px}
.config input{background:#111820;border:none;color:#00e5ff;font-family:'IBM Plex Mono',monospace;font-size:13px;padding:6px 10px;width:70px;outline:none;border-radius:3px}
.proxy-info{color:#3a4a5a;font-size:10px;text-align:right;padding-bottom:8px}
.btn{width:100%;padding:14px;font-family:'IBM Plex Mono',monospace;font-size:12px;font-weight:700;cursor:pointer;border:none;border-radius:4px;letter-spacing:3px;transition:all .2s}
.btn-idle{background:#111820;color:#00e5ff;border:1px solid #00e5ff}
.btn-idle:hover{background:#00e5ff;color:#080c10}
.btn-stop{background:#1a0008;color:#ff3355;border:1px solid #ff3355}
.log-header{color:#3a4a5a;font-size:10px;padding:12px 0 4px;letter-spacing:2px}
.log-box{background:#0d1117;padding:10px;height:240px;overflow-y:auto;font-size:11px;line-height:1.7;border-radius:4px}
.log-box::-webkit-scrollbar{width:3px}
.log-box::-webkit-scrollbar-thumb{background:#3a4a5a}
.ok{color:#00ff88}.err{color:#ff3355}.dim{color:#3a4a5a}.inf{color:#00e5ff}
.footer{border-top:1px solid #3a4a5a;padding:10px 0;color:#3a4a5a;font-size:10px;display:flex;justify-content:space-between;margin-top:8px}

/* License screen */
.license-screen{display:flex;align-items:center;justify-content:center;height:100vh;background:#080c10}
.license-box{text-align:center}
.license-title{font-size:32px;color:#00e5ff;font-weight:700;letter-spacing:4px;margin-bottom:6px}
.license-sub{color:#3a4a5a;font-size:11px;letter-spacing:2px;margin-bottom:32px}
.license-input{display:block;width:300px;padding:12px 16px;background:#111820;border:1px solid #1e2e3e;color:#00e5ff;font-family:'IBM Plex Mono',monospace;font-size:13px;outline:none;border-radius:4px;margin:0 auto 12px;letter-spacing:2px;transition:border-color .2s}
.license-input:focus{border-color:#00e5ff}
.license-input::placeholder{color:#2a3a4a;letter-spacing:1px}
.license-btn{display:block;width:300px;margin:0 auto;padding:12px;background:#00e5ff;border:none;color:#080c10;font-family:'IBM Plex Mono',monospace;font-weight:700;font-size:12px;letter-spacing:3px;cursor:pointer;border-radius:4px;transition:all .2s}
.license-btn:hover{background:transparent;color:#00e5ff;border:1px solid #00e5ff}
.license-err{color:#ff3355;font-size:11px;margin-top:10px;min-height:16px}
.license-divider{width:300px;margin:24px auto;border:none;border-top:1px solid #1e2e3e}
.license-footer{color:#3a4a5a;font-size:10px;letter-spacing:1px}
</style>
</head>
<body>
<div id="app"></div>

<script>
function showLicenseScreen() {
  document.getElementById('app').innerHTML = `
    <div class="license-screen">
      <div class="license-box">
        <div class="license-title">KUNI</div>
        <div class="license-sub">LICENSE VERIFICATION &nbsp;·&nbsp; AUTO SB GEN v2.3</div>
        <input class="license-input" id="licenseInput" type="text" placeholder="ENTER LICENSE KEY" autocomplete="off" />
        <button class="license-btn" onclick="doLogin()">LOGIN</button>
        <div class="license-err" id="licenseErr"></div>
        <hr class="license-divider" />
        <div class="license-footer">by kuni &nbsp;·&nbsp; unauthorized access prohibited</div>
      </div>
    </div>
  `;
  document.getElementById('licenseInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
}

async function doLogin() {
  const key = document.getElementById('licenseInput').value.trim();
  const err = document.getElementById('licenseErr');
  if (!key) { err.textContent = '⚠ please enter a license key'; return; }
  err.style.color = '#ffd700';
  err.textContent = '● verifying...';
  try {
    const res = await fetch('/verify-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key })
    });
    const data = await res.json();
    if (data.valid) {
      localStorage.setItem('license', key);
      showMainApp();
    } else {
      err.style.color = '#ff3355';
      err.textContent = '✕ invalid license — contact your reseller';
    }
  } catch (e) {
    err.style.color = '#ff3355';
    err.textContent = '✕ server error — try again';
  }
}

function showMainApp() {
  document.getElementById('app').innerHTML = `
    <div class="container">
      <div class="header">
        <h1>KUNI</h1>
        <span>AUTO SB GEN</span>
        <span class="version">v2.3</span>
      </div>
      <div class="status" id="status">● idle — ready</div>
      <div class="stats">
        <div class="stat"><span class="stat-val created" id="s-created">0</span><span class="stat-lbl">CREATED</span></div>
        <div class="stat"><span class="stat-val active" id="s-active">0</span><span class="stat-lbl">ACTIVE</span></div>
        <div class="stat"><span class="stat-val failed" id="s-failed">0</span><span class="stat-lbl">FAILED</span></div>
        <div class="stat"><span class="stat-val target" id="s-target">0</span><span class="stat-lbl">TARGET</span></div>
      </div>
      <div class="config">
        <label>COUNT</label>
        <input type="number" id="count" value="10" min="1" max="9999">
        <label>CONCURRENT</label>
        <input type="number" id="concurrent" value="10" min="1" max="50">
      </div>
      <div class="proxy-info" id="proxy-info">loading proxies...</div>
      <button class="btn btn-idle" id="mainBtn" onclick="toggle()">RUN GENERATOR</button>
      <div class="log-header">LOG</div>
      <div class="log-box" id="logBox"></div>
      <div class="footer">
        <span>by kuni</span>
        <span id="footer-status">idle</span>
      </div>
    </div>
  `;
  initSocket();
}

function initSocket() {
  const socket = io();
  let running = false;

  window.toggle = function() {
    if (running) {
      socket.emit('stop');
    } else {
      const count = parseInt(document.getElementById('count').value) || 10;
      const concurrent = parseInt(document.getElementById('concurrent').value) || 10;
      socket.emit('start', { count, concurrent });
    }
  };

  socket.on('connect', () => socket.emit('get_info'));

  socket.on('info', d => {
    document.getElementById('proxy-info').textContent = `proxy ready — ${d.proxies} loaded`;
  });

  socket.on('log', d => {
    const box = document.getElementById('logBox');
    const line = document.createElement('div');
    line.className = d.tag || 'dim';
    line.textContent = d.msg;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
  });

  socket.on('stats', d => {
    document.getElementById('s-created').textContent = d.created;
    document.getElementById('s-active').textContent = d.active;
    document.getElementById('s-failed').textContent = d.failed;
    document.getElementById('s-target').textContent = d.target;
  });

  socket.on('started', d => {
    running = true;
    document.getElementById('mainBtn').className = 'btn btn-stop';
    document.getElementById('mainBtn').textContent = '■  STOP';
    document.getElementById('status').textContent = `● running — ${d.count} accounts`;
    document.getElementById('footer-status').textContent = 'running';
  });

  socket.on('stopped', () => {
    running = false;
    document.getElementById('mainBtn').className = 'btn btn-idle';
    document.getElementById('mainBtn').textContent = 'RUN GENERATOR';
    document.getElementById('status').textContent = '● stopped';
    document.getElementById('footer-status').textContent = 'idle';
  });

  socket.on('done', d => {
    running = false;
    document.getElementById('mainBtn').className = 'btn btn-idle';
    document.getElementById('mainBtn').textContent = 'RUN GENERATOR';
    document.getElementById('status').textContent = `● done — ${d.created}/${d.total} created`;
    document.getElementById('footer-status').textContent = 'done';
  });
}

// Init
if (localStorage.getItem('license')) {
  showMainApp();
} else {
  showLicenseScreen();
}
</script>
</body>
</html>
"""

# ── Flask Routes + SocketIO Events ────────────────────────────────────────────

@app.route("/")
def index():
    return HTML


@socketio.on("get_info")
def on_info():
    emit("info", {"proxies": len(proxies_list)})


@socketio.on("start")
def on_start(data):

    if not license_valid:
        return
    if state["running"]:
        return
    count      = int(data.get("count", 10))
    concurrent = int(data.get("concurrent", 10))

    state["running"] = True
    state["stop"]    = False
    state["created"] = 0
    state["active"]  = 0
    state["failed"]  = 0
    state["target"]  = count

    emit("started", {"count": count})
    log_emit(f"Starting {count} accounts ({concurrent} concurrent)...", "inf")

    threading.Thread(
        target=run_generator,
        args=(count, concurrent),
        daemon=True
    ).start()


@socketio.on("stop")
def on_stop():
    state["stop"] = True
    emit("stopped")
    log_emit("Stopping...", "inf")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[KUNI] SB Generator running!")
    print(f"[KUNI] Open http://localhost:{port} in your browser\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
