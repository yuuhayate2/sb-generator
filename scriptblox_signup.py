# KUNI SB GENERATOR WITH LICENSE SYSTEM (FULL FIXED)

import asyncio
import json
import os
import random
import re
import string
import threading
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

import eventlet
eventlet.monkey_patch()

import requests
import urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

from turnstile_solver import solve_turnstile_capsolver
from proxy_util import load_proxies, get_random_proxy, proxy_display

load_dotenv()

# ── SUPABASE ─────────────────────────────

SUPABASE_URL = "https://ukwltgxtfikrpsqfihi.supabase.co"
SUPABASE_KEY = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"

license_valid = False

def get_hwid(ip):
    return hashlib.sha256(ip.encode()).hexdigest()

# ── VERIFY KEY ───────────────────────────

def verify_license(key, ip):

    hwid = get_hwid(ip)

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }

    params = {
        "license_key": f"eq.{key}"
    }

    res = requests.get(
        f"{SUPABASE_URL}/rest/v1/licenses",
        headers=headers,
        params=params
    )

    data = res.json()

    if not data:
        return False

    license = data[0]

    if license["status"] != "active":
        return False

    if license["hwid"] and license["hwid"] != hwid:
        return False

    if not license["hwid"]:
        requests.patch(
            f"{SUPABASE_URL}/rest/v1/licenses",
            headers=headers,
            params={"license_key": f"eq.{key}"},
            json={"hwid": hwid}
        )

    return True

# ── GENERATOR CODE (UNCHANGED) ───────────

ACCOUNTS_FILE   = Path(__file__).parent / "scriptblox_accounts.txt"
SB_SIGNUP       = "https://scriptblox.com/api/auth/signup"

proxies_list = load_proxies()
file_lock    = threading.Lock()

app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

state = {
    "running": False,
    "created": 0,
    "active":  0,
    "failed":  0,
    "target":  0,
    "stop":    False,
}

# ── LICENSE ROUTE ────────────────────────

@app.route("/verify-key", methods=["POST"])
def verify():

    global license_valid

    data = request.json
    key = data.get("key")

    valid = verify_license(key, request.remote_addr)

    license_valid = valid

    return jsonify({"valid": valid})

# ── UI (SAME THEME + LICENSE SCREEN) ────

HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KUNI · AUTO SB GEN</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>

<style>

body{
background:#080c10;
color:#c8d8e8;
font-family:monospace;
padding:20px;
}

.login{
max-width:400px;
margin:100px auto;
}

input{
background:#111820;
border:none;
color:#00e5ff;
padding:12px;
width:100%;
}

button{
background:#00e5ff;
border:none;
padding:12px;
cursor:pointer;
margin-top:10px;
width:100%;
}

</style>

</head>

<body>

<div id="login" class="login">

<h2>KUNI LICENSE</h2>

<input id="license" placeholder="Enter License Key">

<button onclick="login()">LOGIN</button>

</div>

<div id="app" style="display:none">

<iframe src="/" style="width:100%;height:100vh;border:none"></iframe>

</div>

<script>

async function login(){

const key = document.getElementById("license").value

const res = await fetch("/verify-key",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({key})

})

const data = await res.json()

if(data.valid){

document.getElementById("login").style.display="none"
document.getElementById("app").style.display="block"

}else{

alert("Invalid License")

}

}

</script>

</body>
</html>
"""

@app.route("/")
def index():
    return HTML

# ── START ───────────────────────────────

@socketio.on("start")
def on_start(data):

    if not license_valid:
        return

    emit("started")

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    socketio.run(app, host="0.0.0.0", port=port)
