# FULL FIXED VERSION
# KUNI SB GENERATOR + KEY SYSTEM

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

import requests
import urllib3
urllib3.disable_warnings()

from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit

from turnstile_solver import solve_turnstile_capsolver
from proxy_util import load_proxies, get_random_proxy, proxy_display

load_dotenv()

SUPABASE_URL = "https://ukwltgxtfikrpsqfihi.supabase.co"
SUPABASE_KEY = "sb_publishable_NhI5Z-LriMN_huWOV14AtA_YtmDZeQ3"

ACCOUNTS_FILE   = Path(__file__).parent / "scriptblox_accounts.txt"
SB_SIGNUP       = "https://scriptblox.com/api/auth/signup"
MW_DOMAIN       = "aula.edu.pl"
MW_BASE         = "https://mailwave.dev"

proxies_list = load_proxies()
file_lock    = threading.Lock()

app      = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

current_license = None

state = {
    "running": False,
    "created": 0,
    "active":  0,
    "failed":  0,
    "target":  0,
    "stop":    False,
}


def get_hwid(ip):
    return hashlib.sha256(ip.encode()).hexdigest()


@app.route("/verify-key", methods=["POST"])
def verify_key():

    global current_license

    data = request.json
    key = data.get("key")

    hwid = get_hwid(request.remote_addr)

    url = f"{SUPABASE_URL}/rest/v1/licenses"

    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json"
    }

    params = {
        "license_key": f"eq.{key}"
    }

    res = requests.get(url, headers=headers, params=params)
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
            url,
            headers=headers,
            params={"license_key": f"eq.{key}"},
            json={"hwid": hwid}
        )

    current_license = license

    return jsonify({"valid": True})


def rand_username():
    return "Kuni" + "".join(random.choices(string.ascii_letters + string.digits, k=10))


def rand_password():
    return "".join(random.choices(string.ascii_letters + string.digits, k=14))


def create_account(slot):

    global current_license

    if current_license:
        if current_license["accounts_used"] >= current_license["accounts_limit"]:
            return

    username = rand_username()
    password = rand_password()

    try:
        r = requests.post(
            SB_SIGNUP,
            json={
                "username": username,
                "password": password,
            }
        )

        if r.status_code == 200:

            state["created"] += 1

            requests.patch(
                f"{SUPABASE_URL}/rest/v1/licenses",
                headers={
                    "apikey": SUPABASE_KEY,
                    "Authorization": f"Bearer {SUPABASE_KEY}"
                },
                params={
                    "license_key": f"eq.{current_license['license_key']}"
                },
                json={
                    "accounts_used": current_license["accounts_used"] + 1
                }
            )

    except:
        state["failed"] += 1


@app.route("/")
def index():
    return "KUNI GENERATOR"


@socketio.on("start")
def start(data):

    count = data.get("count", 10)

    state["created"] = 0

    for i in range(count):
        create_account(i)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)