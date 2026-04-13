# turnstile_solver.py — CapSolver Turnstile bypass (server version, no playwright)
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

CAPSOLVER_KEY    = os.getenv("CAPSOLVER_KEY", "")
SB_TURNSTILE_KEY = "0x4AAAAAAADI1KFhXIM1zitP"
SB_SIGNUP_URL    = "https://scriptblox.com/signup"
NO_PROXY         = {"http": None, "https": None}


def capsolver_create_task(site_key, page_url):
    try:
        r = requests.post("https://api.capsolver.com/createTask", json={
            "clientKey": CAPSOLVER_KEY,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": site_key,
                "metadata": {"action": ""}
            }
        }, timeout=30, proxies=NO_PROXY)
        data = r.json()
        if data.get("errorId", 1) == 0:
            return data.get("taskId")
        print(f"[!] CapSolver error: {data.get('errorDescription')}")
        return None
    except Exception as e:
        print(f"[!] CapSolver exception: {e}")
        return None


def capsolver_get_result(task_id, retries=30, interval=2.0):
    for _ in range(retries):
        try:
            r = requests.post("https://api.capsolver.com/getTaskResult", json={
                "clientKey": CAPSOLVER_KEY, "taskId": task_id
            }, timeout=30, proxies=NO_PROXY)
            data = r.json()
            if data.get("status") == "ready":
                return data.get("solution", {}).get("token")
            if data.get("errorId", 0) != 0:
                print(f"[!] CapSolver poll error: {data.get('errorDescription')}")
                return None
        except Exception as e:
            print(f"[!] CapSolver poll exception: {e}")
        time.sleep(interval)
    return None


def solve_turnstile_capsolver(page_url=SB_SIGNUP_URL, site_key=SB_TURNSTILE_KEY):
    print(f"[→] CapSolver: creating task...")
    task_id = capsolver_create_task(site_key, page_url)
    if not task_id: return None
    print(f"[→] CapSolver: waiting... (taskId={task_id[:12]}...)")
    token = capsolver_get_result(task_id)
    if token: print(f"[✓] CapSolver: token received!")
    else: print(f"[✗] CapSolver: failed")
    return token
