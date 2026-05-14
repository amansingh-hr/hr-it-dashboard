#!/usr/bin/env python3
"""
Iru (Kandji) Device Dashboard - Local Server
============================================
Run:   python3 iru_dashboard.py
Then open: http://localhost:8080   (it opens automatically)

On first run you'll be prompted for your subdomain + API token,
which are saved to iru_config.json next to this script.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Timer

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iru_config.json")
CACHE_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iru_cache.json")
USERS_FILE        = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard_users.json")
OFFBOARDING_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offboarding.json")
PORT              = int(os.environ.get("PORT", 8080))
CACHE_TTL   = 15 * 60   # used for staleness checks; auto-refresh is disabled (refresh on login instead)

# Cloud deployment: load API credentials from environment variables
# Local development:  falls back to iru_config.json
def _config_from_env():
    sub = os.environ.get("IRU_SUBDOMAIN", "")
    tok = os.environ.get("IRU_TOKEN", "")
    if sub and tok:
        return {
            "subdomain":           sub,
            "token":               tok,
            "region":              os.environ.get("IRU_REGION", "us"),
            "okta_domain":         os.environ.get("OKTA_DOMAIN", ""),
            "okta_token":          os.environ.get("OKTA_TOKEN", ""),
            "jumpcloud_api_key":   os.environ.get("JUMPCLOUD_API_KEY", ""),
            "fedex_client_id":              os.environ.get("FEDEX_CLIENT_ID", ""),
            "fedex_client_secret":           os.environ.get("FEDEX_CLIENT_SECRET", ""),
            "google_sheet_id":              os.environ.get("GOOGLE_SHEET_ID", ""),
            "google_service_account_json":  os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON", ""),
        }
    return None

# True when running in cloud mode (config from env vars — settings panel hidden)
CLOUD_MODE = _config_from_env() is not None

# ---------------------------------------------------------------------------
# Auth  (session-based login, multi-user)
# ---------------------------------------------------------------------------
SESSION_TTL    = 8 * 3600   # 8 hours
_sessions      = {}          # token → {"expiry": float, "username": str}
_sessions_lock = threading.Lock()
_users_lock    = threading.Lock()


def _hash_password(password):
    """Hash a password with PBKDF2-SHA256 + random salt."""
    salt = os.urandom(16)
    key  = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 260000)
    return base64.b64encode(salt + key).decode('ascii')


def _verify_password(password, stored_hash):
    """Return True if password matches stored_hash."""
    try:
        decoded = base64.b64decode(stored_hash.encode('ascii'))
        salt, key = decoded[:16], decoded[16:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 260000)
        return hmac.compare_digest(key, new_key)
    except Exception:
        return False


def _load_users():
    """Return list of user dicts from dashboard_users.json."""
    with _users_lock:
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
    return []


def _save_users(users):
    with _users_lock:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)


# ---------------------------------------------------------------------------
# Offboarding records
# ---------------------------------------------------------------------------
_offboarding_lock = threading.Lock()


def _load_offboarding():
    with _offboarding_lock:
        if os.path.exists(OFFBOARDING_FILE):
            try:
                with open(OFFBOARDING_FILE) as f:
                    return json.load(f)
            except Exception:
                pass
    return {}


def _save_offboarding(data):
    with _offboarding_lock:
        with open(OFFBOARDING_FILE, 'w') as f:
            json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Google Sheets sync
# ---------------------------------------------------------------------------
_SHEETS_HEADERS = [
    "Email", "Slack Deactivated", "Google Deactivated", "Box Shipped",
    "Outbound Tracking", "Equipment Returned", "Return Tracking",
    "Notes", "Devices", "Last Updated",
]

def _sheets_sync(email, rec):
    """Upsert one offboarding record into the configured Google Sheet."""
    try:
        cfg      = getattr(_sheets_sync, "_cfg", None) or {}
        sa_json  = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON") or cfg.get("google_service_account_json", "")
        sheet_id = os.environ.get("GOOGLE_SHEET_ID")             or cfg.get("google_sheet_id", "")
        if not sa_json or not sheet_id:
            return

        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build

        creds   = Credentials.from_service_account_info(
            json.loads(sa_json),
            scopes=["https://www.googleapis.com/auth/spreadsheets"],
        )
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        api     = service.spreadsheets().values()

        def yn(v): return "Yes" if v else "No"

        devices_str = "; ".join(
            f"{did}: {'received' if dv.get('received') else 'pending'}"
            for did, dv in (rec.get("devices") or {}).items()
        )
        row = [
            email,
            yn(rec.get("slack_deactivated")),
            yn(rec.get("google_deactivated")),
            yn(rec.get("box_shipped")),
            rec.get("outbound_tracking") or "",
            yn(rec.get("equipment_returned")),
            rec.get("return_tracking") or "",
            rec.get("notes") or "",
            devices_str,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ]

        # Read column A to find existing row (or detect empty sheet)
        existing = api.get(spreadsheetId=sheet_id, range="A:A").execute().get("values", [])

        # Ensure header row exists
        if not existing or existing[0][0] != "Email":
            api.update(
                spreadsheetId=sheet_id, range="A1",
                valueInputOption="RAW",
                body={"values": [_SHEETS_HEADERS]},
            ).execute()
            existing = [_SHEETS_HEADERS]

        # Find existing row for this email
        row_idx = next((i + 1 for i, r in enumerate(existing) if r and r[0] == email), None)

        if row_idx:
            api.update(
                spreadsheetId=sheet_id, range=f"A{row_idx}",
                valueInputOption="RAW", body={"values": [row]},
            ).execute()
        else:
            api.append(
                spreadsheetId=sheet_id, range="A:A",
                valueInputOption="RAW", insertDataOption="INSERT_ROWS",
                body={"values": [row]},
            ).execute()

    except Exception as exc:
        print(f"[Sheets sync error] {exc}", flush=True)


def _sheets_sync_bg(email, rec, cfg):
    """Fire-and-forget wrapper — runs _sheets_sync on a daemon thread."""
    _sheets_sync._cfg = cfg
    threading.Thread(target=_sheets_sync, args=(email, rec), daemon=True).start()


def _sheets_restore(cfg):
    """On startup: always restore offboarding data from Google Sheet (Sheet is source of truth in cloud mode)."""
    sa_json  = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON") or cfg.get("google_service_account_json", "")
    sheet_id = os.environ.get("GOOGLE_SHEET_ID")             or cfg.get("google_sheet_id", "")
    if not sa_json or not sheet_id:
        return

    try:
        from google.oauth2.service_account import Credentials
        from googleapiclient.discovery import build

        creds   = Credentials.from_service_account_info(
            json.loads(sa_json),
            scopes=["https://www.googleapis.com/auth/spreadsheets"],
        )
        service = build("sheets", "v4", credentials=creds, cache_discovery=False)
        rows    = service.spreadsheets().values().get(
            spreadsheetId=sheet_id, range="A:J"
        ).execute().get("values", [])

        if len(rows) < 2:
            return  # no data rows

        def frombool(v): return v == "Yes"

        data = {}
        for row in rows[1:]:  # skip header
            if not row:
                continue
            email = (row[0] if len(row) > 0 else "").strip().lower()
            if not email:
                continue
            rec = {
                "slack_deactivated":  frombool(row[1] if len(row) > 1 else ""),
                "google_deactivated": frombool(row[2] if len(row) > 2 else ""),
                "box_shipped":        frombool(row[3] if len(row) > 3 else ""),
                "outbound_tracking":  row[4] if len(row) > 4 else "",
                "equipment_returned": frombool(row[5] if len(row) > 5 else ""),
                "return_tracking":    row[6] if len(row) > 6 else "",
                "notes":              row[7] if len(row) > 7 else "",
                "devices":            {},
                "restored_from_sheet": True,
            }
            # Parse devices string: "device_id: received/pending; ..."
            devices_str = row[8] if len(row) > 8 else ""
            for part in devices_str.split(";"):
                part = part.strip()
                if ":" in part:
                    did, status = part.split(":", 1)
                    did = did.strip()
                    received = status.strip() == "received"
                    if did:
                        rec["devices"][did] = {"received": received, "received_at": None}
            data[email] = rec

        if data:
            _save_offboarding(data)
            print(f"[Sheets] Restored {len(data)} offboarding record(s) from Google Sheet.", flush=True)

    except Exception as exc:
        print(f"[Sheets restore error] {exc}", flush=True)


# ---------------------------------------------------------------------------
# FedEx Tracking API
# ---------------------------------------------------------------------------
_fedex_token_cache = {"token": None, "expires": 0}
_fedex_token_lock  = threading.Lock()


def _get_fedex_token(client_id, client_secret):
    with _fedex_token_lock:
        if _fedex_token_cache["token"] and time.time() < _fedex_token_cache["expires"] - 60:
            return _fedex_token_cache["token"]
        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
        }).encode()
        req = urllib.request.Request(
            "https://apis.fedex.com/oauth/token",
            data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
        _fedex_token_cache["token"]   = result["access_token"]
        _fedex_token_cache["expires"] = time.time() + result.get("expires_in", 3600)
        return _fedex_token_cache["token"]


def _track_fedex(tracking_number, client_id, client_secret):
    token   = _get_fedex_token(client_id, client_secret)
    payload = json.dumps({
        "includeDetailedScans": False,
        "trackingInfo": [{"trackingNumberInfo": {"trackingNumber": tracking_number}}],
    }).encode()
    req = urllib.request.Request(
        "https://apis.fedex.com/track/v1/trackingnumbers",
        data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
            "x-locale":      "en_US",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _get_dashboard_creds():
    """Return (user, pass) — env vars take priority, then iru_config.json, then defaults."""
    u = os.environ.get("DASHBOARD_USER", "")
    p = os.environ.get("DASHBOARD_PASS", "")
    if not u or not p:
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE) as _f:
                    _c = json.load(_f)
                u = u or _c.get("dashboard_user", "admin")
                p = p or _c.get("dashboard_pass", "")
        except Exception:
            pass
    return u or "admin", p


def _init_users():
    """On first run: migrate from single-user config to new multi-user users file."""
    if os.path.exists(USERS_FILE):
        return
    u_old, p_old = _get_dashboard_creds()
    if p_old:
        users = [{
            "username":     u_old,
            "password_hash": _hash_password(p_old),
            "created_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]
        _save_users(users)
        print(f"[Auth] Migrated user '{u_old}' to dashboard_users.json")


def _create_session(username):
    token = str(uuid.uuid4())
    with _sessions_lock:
        _sessions[token] = {"expiry": time.time() + SESSION_TTL, "username": username}
    return token


def _valid_session(token):
    if not token:
        return False
    with _sessions_lock:
        entry = _sessions.get(token)
        if not entry:
            return False
        if time.time() > entry["expiry"]:
            del _sessions[token]
            return False
        # Sliding window — refresh expiry on activity
        entry["expiry"] = time.time() + SESSION_TTL
    return True


def _get_session_username(token):
    if not token:
        return None
    with _sessions_lock:
        entry = _sessions.get(token)
        return entry["username"] if entry else None


def _check_credentials(username, password):
    users = _load_users()
    if users:
        for user in users:
            if hmac.compare_digest(username.strip(), user["username"]):
                return _verify_password(password.strip(), user["password_hash"])
        return False
    # Fallback: no users file yet — use old single-user config
    u, p = _get_dashboard_creds()
    if not p:
        return False
    return hmac.compare_digest(username.strip(), u) and hmac.compare_digest(password.strip(), p)


DASHBOARD_USER, DASHBOARD_PASS = _get_dashboard_creds()

# ---------------------------------------------------------------------------
# Cache  (in-memory + disk-persistent)
# ---------------------------------------------------------------------------
_cache_data   = {}             # key → {"data": any, "ts": float}
_cache_lock   = threading.RLock()
_refresh_flag = threading.Event()   # set to trigger an immediate refresh
_refresh_busy = threading.Event()   # set while a refresh is running


def _cache_get(key):
    with _cache_lock:
        e = _cache_data.get(key)
        return (e["data"], e["ts"]) if e else (None, 0)


def _cache_set(key, data):
    with _cache_lock:
        _cache_data[key] = {"data": data, "ts": time.time()}
    _persist_cache()


def _cache_age(key):
    _, ts = _cache_get(key)
    return (time.time() - ts) if ts else float("inf")


def _persist_cache():
    try:
        with _cache_lock:
            snap = {k: {"data": v["data"], "ts": v["ts"]} for k, v in _cache_data.items()}
        with open(CACHE_FILE, "w") as f:
            json.dump(snap, f)
    except Exception as e:
        print(f"[Cache] Persist error: {e}")


def _load_cache_from_disk():
    if not os.path.exists(CACHE_FILE):
        return
    try:
        with open(CACHE_FILE) as f:
            loaded = json.load(f)
        with _cache_lock:
            _cache_data.update(loaded)
        ages = {k: f"{int((time.time()-v['ts'])/60)}m" for k, v in loaded.items() if v.get("ts")}
        print(f"[Cache] Loaded from disk: {ages}")
    except Exception as e:
        print(f"[Cache] Load error: {e}")


def _refresh_all(cfg, force=False):
    """Fetch all enabled APIs and update the cache. Thread-safe."""
    if not cfg:
        return
    _refresh_busy.set()
    try:
        # ── Iru / Kandji devices ─────────────────────────────────────────
        if force or _cache_age("devices") > CACHE_TTL:
            try:
                print("[Cache] Fetching Iru devices…")
                data = fetch_all_devices(cfg["subdomain"], cfg["token"], cfg.get("region", "us"))
                _cache_set("devices", data)
                print(f"[Cache] Iru done — {len(data)} devices")
            except Exception as e:
                print(f"[Cache] Iru error: {e}")

        # ── Okta users ───────────────────────────────────────────────────
        if cfg.get("okta_domain") and cfg.get("okta_token"):
            if force or _cache_age("okta_users") > CACHE_TTL:
                try:
                    print("[Cache] Fetching Okta users…")
                    data = fetch_all_okta_users(cfg["okta_domain"], cfg["okta_token"])
                    _cache_set("okta_users", data)
                    print(f"[Cache] Okta done — {len(data)} users")
                except Exception as e:
                    print(f"[Cache] Okta error: {e}")

        # ── JumpCloud devices ────────────────────────────────────────────
        if cfg.get("jumpcloud_api_key"):
            if force or _cache_age("jc_devices") > CACHE_TTL:
                try:
                    print("[Cache] Fetching JumpCloud devices…")
                    data = fetch_jumpcloud_devices(cfg["jumpcloud_api_key"])
                    _cache_set("jc_devices", data)
                    print(f"[Cache] JumpCloud done — {len(data)} devices")
                except Exception as e:
                    print(f"[Cache] JumpCloud error: {e}")
    finally:
        _refresh_busy.clear()


def _background_refresh_loop():
    """Daemon thread: only refreshes when explicitly signalled (e.g. on login or manual refresh)."""
    while True:
        _refresh_flag.wait()   # block indefinitely until signalled
        _refresh_flag.clear()
        cfg = DashboardHandler.config
        _refresh_all(cfg, force=True)


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return None


def save_config(subdomain, token, region="us", okta_domain="", okta_token="", jumpcloud_api_key="",
                dashboard_user="", dashboard_pass="", fedex_client_id="", fedex_client_secret=""):
    existing = load_config() or {}
    cfg = {
        "subdomain":           subdomain.strip(),
        "token":               token.strip(),
        "region":              region.strip() or "us",
        "okta_domain":         okta_domain.strip(),
        "okta_token":          okta_token.strip(),
        "jumpcloud_api_key":   jumpcloud_api_key.strip(),
        "dashboard_user":      dashboard_user.strip() or existing.get("dashboard_user", "admin"),
        "dashboard_pass":      dashboard_pass.strip() or existing.get("dashboard_pass", ""),
        "fedex_client_id":     fedex_client_id.strip() or existing.get("fedex_client_id", ""),
        "fedex_client_secret": fedex_client_secret.strip() or existing.get("fedex_client_secret", ""),
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    return cfg


# ---------------------------------------------------------------------------
# Iru API
# ---------------------------------------------------------------------------
def fetch_all_devices(subdomain, token, region="us"):
    """Fetch every device from the Iru API, handling pagination."""
    if region == "eu":
        base = f"https://{subdomain}.api.eu.kandji.io"
    else:
        base = f"https://{subdomain}.api.kandji.io"

    all_devices = []
    limit = 300
    offset = 0

    while True:
        url = f"{base}/api/v1/devices?limit={limit}&offset={offset}"
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())

        # API returns either a plain list or {"count":N,"results":[...]}
        if isinstance(data, list):
            all_devices.extend(data)
            break
        else:
            results = data.get("results", [])
            all_devices.extend(results)
            if not data.get("next") or not results:
                break
            offset += limit

    return all_devices


def fetch_iru_device_details(subdomain, token, region, device_id):
    """Fetch the /details endpoint for a single Iru device."""
    if region == "eu":
        base = f"https://{subdomain}.api.eu.kandji.io"
    else:
        base = f"https://{subdomain}.api.kandji.io"
    url = f"{base}/api/v1/devices/{device_id}/details"
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Okta API
# ---------------------------------------------------------------------------
def _okta_get(url, token):
    """Single Okta API GET, returns (data, next_url)."""
    req = urllib.request.Request(
        url, headers={"Authorization": f"SSWS {token}", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
        link = resp.headers.get("Link", "")
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        return data, (match.group(1) if match else None)


def _okta_paginate(start_url, token, label=""):
    """Fetch all pages from an Okta API URL following Link: rel="next" headers."""
    url, results, page = start_url, [], 1
    while url:
        data, next_url = _okta_get(url, token)
        results.extend(data)
        print(f"  [Okta {label}] page {page}: {len(data)} users (total: {len(results)})")
        url, page = next_url, page + 1
    return results


def fetch_all_okta_users(okta_domain, okta_token):
    """Bulk-fetch Okta users (all statuses the API will return in one sweep)."""
    import urllib.parse
    base = f"https://{okta_domain}/api/v1/users"
    print(f"\n[Okta] Bulk fetching users from {okta_domain}...")

    users = _okta_paginate(
        f"{base}?search={urllib.parse.quote('profile.login pr')}&limit=200",
        okta_token, label="search"
    )
    deprovisioned_filter = urllib.parse.quote('status eq "DEPROVISIONED"')
    users.extend(_okta_paginate(
        f"{base}?filter={deprovisioned_filter}&limit=200",
        okta_token, label="DEPROVISIONED"
    ))

    seen, unique = set(), []
    for u in users:
        uid = u.get("id")
        if uid and uid not in seen:
            seen.add(uid)
            unique.append(u)
    print(f"[Okta] Bulk done — {len(unique)} unique users.\n")
    return unique


def fetch_okta_users_by_emails(okta_domain, okta_token, emails):
    """Targeted lookup: find specific Okta users by email address.

    Uses the search API with exact email matches — reliable even when the
    bulk endpoint hits Okta's 200-user cap.  Called as a fallback for any
    device-assigned email that wasn't returned by the bulk fetch.
    """
    import urllib.parse
    if not emails:
        return []
    base   = f"https://{okta_domain}/api/v1/users"
    results = []
    batch_size = 20   # keep URL short
    batches = [emails[i:i+batch_size] for i in range(0, len(emails), batch_size)]
    print(f"[Okta] Targeted lookup for {len(emails)} missing emails ({len(batches)} batches)...")
    for i, batch in enumerate(batches):
        conditions = " OR ".join(
            [f'profile.email eq "{e}" OR profile.login eq "{e}"' for e in batch]
        )
        url = f"{base}?search={urllib.parse.quote(conditions)}&limit=200"
        data, _ = _okta_get(url, okta_token)
        results.extend(data)
        print(f"  [Okta targeted] batch {i+1}/{len(batches)}: found {len(data)} users")
    return results


# ---------------------------------------------------------------------------
# JumpCloud API  (OAuth2 client-credentials)
# ---------------------------------------------------------------------------
def _jc_paginate(path, api_key, label=""):
    """Fetch all pages from a JumpCloud v1 API endpoint (totalCount / skip / results)."""
    base = f"https://console.jumpcloud.com{path}"
    headers = {
        "x-api-key":    api_key,
        "Content-Type": "application/json",
        "Accept":       "application/json",
    }
    all_results, limit, skip = [], 100, 0
    while True:
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}limit={limit}&skip={skip}"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        results = data.get("results", [])
        total   = data.get("totalCount", 0)
        all_results.extend(results)
        print(f"  [JumpCloud {label}] skip={skip}: {len(results)} (total: {total})")
        if len(all_results) >= total or not results:
            break
        skip += limit
    return all_results


def _jc_paginate_array(path, api_key, label=""):
    """Paginate a JumpCloud endpoint that returns a plain JSON array (v2 system insights)."""
    base    = f"https://console.jumpcloud.com{path}"
    headers = {"x-api-key": api_key, "Accept": "application/json"}
    all_results, limit, skip = [], 100, 0
    while True:
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}limit={limit}&skip={skip}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            if isinstance(data, list):
                all_results.extend(data)
                if len(data) < limit:
                    break
            else:
                # Some v2 endpoints wrap in results/totalCount
                results = data.get("results", []) if isinstance(data, dict) else []
                all_results.extend(results)
                if not results or len(results) < limit:
                    break
            skip += limit
        except Exception as e:
            print(f"  [JumpCloud {label}] error at skip={skip}: {e}")
            break
    print(f"  [JumpCloud {label}] total: {len(all_results)}")
    return all_results


def fetch_jumpcloud_devices(api_key):
    """Return JumpCloud systems normalised to the same flat dict shape as Iru devices."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    print("\n[JumpCloud] Fetching systems and users...")
    systems    = _jc_paginate("/api/systems",    api_key, label="systems")
    users_list = _jc_paginate("/api/systemusers", api_key, label="users")

    # Build user _id → user object map
    user_map = {u["_id"]: u for u in users_list if u.get("_id")}

    # Fetch user bindings for every system in parallel (v2 associations API, systems direction)
    _first_error_logged = [False]

    def get_system_users(sys_obj):
        sid = sys_obj.get("_id") or sys_obj.get("id", "")
        if not sid:
            return sid, []
        url = (f"https://console.jumpcloud.com/api/v2/systems/{sid}"
               f"/associations?targets=user&limit=100")
        req = urllib.request.Request(url, headers={
            "x-api-key": api_key, "Accept": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            user_ids = []
            for item in data:
                uid = (item.get("to") or {}).get("id") or item.get("id")
                if uid:
                    user_ids.append(uid)
            return sid, user_ids
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if not _first_error_logged[0]:
                print(f"  [JumpCloud binding error] system={sid}: HTTP {e.code} — {body[:300]}")
                _first_error_logged[0] = True
            return sid, []
        except Exception as e:
            return sid, []

    print(f"[JumpCloud] Fetching system→user bindings for {len(systems)} systems...")
    system_to_user = {}   # system _id → first bound user object
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(get_system_users, s): s for s in systems}
        for fut in as_completed(futures):
            sid, user_ids = fut.result()
            for uid in user_ids:
                if sid not in system_to_user:
                    system_to_user[sid] = user_map.get(uid, {})
    print(f"[JumpCloud] Bindings found for {len(system_to_user)} systems.")

    # ── System Insights: hardware model, CPU, memory ─────────────────────────
    print("[JumpCloud] Fetching system insights (hardware, CPU, memory)...")
    sys_info_map, hw_info_map = {}, {}
    try:
        sys_info_list = _jc_paginate_array("/api/v2/systeminsights/system_info",  api_key, "sys_info")
        hw_info_list  = _jc_paginate_array("/api/v2/systeminsights/hardware_info", api_key, "hw_info")
        sys_info_map  = {r["system_id"]: r for r in sys_info_list if r.get("system_id")}
        hw_info_map   = {r["system_id"]: r for r in hw_info_list  if r.get("system_id")}
        print(f"  [JumpCloud] sys_info: {len(sys_info_map)}, hw_info: {len(hw_info_map)}")
    except Exception as e:
        print(f"  [JumpCloud] System insights unavailable: {e}")

    devices = []
    for sys in systems:
        os_name = (sys.get("os") or sys.get("osFamily") or "").strip()
        os_low  = os_name.lower()
        if "windows" in os_low:
            family = "Windows"
        elif "mac" in os_low or "darwin" in os_low:
            family = "Mac"
        elif "linux" in os_low or "ubuntu" in os_low:
            family = "Linux"
        else:
            family = "Other"

        name = (sys.get("hostname") or sys.get("displayName") or "").strip() or "Unknown"

        sid = sys.get("_id") or sys.get("id", "")
        u   = system_to_user.get(sid, {})
        fn  = (u.get("firstname") or "").strip()
        ln  = (u.get("lastname") or "").strip()
        user_name  = f"{fn} {ln}".strip() or u.get("username", "")
        user_email = (u.get("email") or "").lower().strip()

        # OS version: prefer system's `version` string, fall back to osVersionDetail
        os_ver_str = sys.get("version") or ""
        if not os_ver_str:
            ov = sys.get("osVersionDetail") or {}
            os_ver_str = ".".join(filter(None, [
                str(ov.get("major", "")), str(ov.get("minor", "")), str(ov.get("patch", ""))
            ]))

        # OS display: "Windows 11 Pro (26200.8246)"
        os_display = os_name
        if os_ver_str and os_ver_str not in os_name:
            os_display = f"{os_name} ({os_ver_str})" if os_name else os_ver_str

        # System insights
        si = sys_info_map.get(sid, {})
        hi = hw_info_map.get(sid, {})

        hw_vendor = (hi.get("hardware_vendor") or sys.get("hwVendor") or "").strip()
        hw_model  = (hi.get("hardware_model")  or "").strip()
        cpu_model = (si.get("cpu_brand") or "").strip()

        mem_bytes = si.get("physical_memory") or 0
        try:
            mem_gb = f"{round(int(mem_bytes) / (1024 ** 3))} GB" if mem_bytes else ""
        except Exception:
            mem_gb = ""

        # Model column: hardware model > vendor+os > os_name > family
        model_display = hw_model or (f"{hw_vendor} {os_name}".strip() if hw_vendor else os_name or family)

        devices.append({
            "device_name":      name,
            "model":            model_display,
            "device_family":    family,
            "serial_number":    sys.get("serialNumber") or "",
            "user":             {"name": user_name, "email": user_email},
            "last_check_in":    sys.get("lastContact"),
            "first_enrollment": sys.get("created"),
            "source":           "jumpcloud",
            "_extra": {
                "os_name":       os_name,
                "os_version":    os_ver_str,
                "os_display":    os_display,
                "hw_vendor":     hw_vendor,
                "hw_model":      hw_model,
                "cpu_model":     cpu_model,
                "memory_gb":     mem_gb,
                "arch":          sys.get("arch") or sys.get("archFamily") or "",
                "fde_encrypted": (sys.get("fde") or {}).get("encrypted"),
                "mdm_enabled":   (sys.get("mdm") or {}).get("enabled"),
                "azure_ad_joined": sys.get("azureAdJoined") or False,
                "active":        sys.get("active") or False,
                "agent_version": sys.get("agentVersion") or "",
                "domain_info":   (sys.get("domainInfo") or {}).get("domainName") or "",
                "jc_system_id":  sid,
            },
        })

    print(f"[JumpCloud] Done — {len(devices)} devices.\n")
    return devices


# ---------------------------------------------------------------------------
# Embedded HTML
# ---------------------------------------------------------------------------
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hungryroot IT Dashboard — Login</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0f172a;display:flex;align-items:center;justify-content:center;
       min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
  .card{background:#1e293b;border:1px solid #334155;border-radius:16px;
        padding:48px 40px;width:100%;max-width:400px;box-shadow:0 25px 50px rgba(0,0,0,.5)}
  .logo{display:flex;align-items:center;gap:14px;margin-bottom:32px}
  .logo-icon{width:48px;height:48px;background:#eb4534;border-radius:12px;
              display:flex;align-items:center;justify-content:center;font-size:24px}
  .logo-text h1{font-size:20px;font-weight:700;color:#f1f5f9}
  .logo-text p{font-size:13px;color:#64748b;margin-top:2px}
  label{display:block;font-size:13px;font-weight:500;color:#94a3b8;margin-bottom:6px}
  input{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;
        padding:10px 14px;color:#f1f5f9;font-size:15px;outline:none;margin-bottom:16px}
  input:focus{border-color:#f38020}
  button{width:100%;background:#f38020;color:#fff;border:none;border-radius:8px;
         padding:12px;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}
  button:hover{background:#d96c10}
  .error{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);
         border-radius:8px;padding:10px 14px;color:#f87171;font-size:13px;margin-bottom:16px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon">🖥</div>
    <div class="logo-text">
      <h1>Hungryroot IT Dashboard</h1>
      <p>Hungryroot · IT Device Management</p>
    </div>
  </div>
  <div class="error" id="err">Invalid username or password.</div>
  <form method="POST" action="/auth/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="username" autofocus required>
    <label>Password</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
</div>
<script>
  const p = new URLSearchParams(location.search);
  if (p.get('error')) document.getElementById('err').style.display = 'block';
</script>
</body>
</html>"""

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hungryroot IT Dashboard</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    background:#0f1117;color:#e2e8f0;min-height:100vh;padding:28px 40px}

  /* ── Header ── */
  .header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
  .logo{display:flex;align-items:center;gap:14px}
  .logo-icon{width:44px;height:44px;background:linear-gradient(135deg,#f38020,#c44f00);
    border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:22px}
  h1{font-size:22px;font-weight:700;letter-spacing:-0.3px}
  .subtitle{color:#64748b;font-size:13px;margin-top:3px}
  .header-right{display:flex;align-items:center;gap:14px}
  .last-updated{color:#64748b;font-size:13px}

  /* ── Buttons ── */
  .btn{display:inline-flex;align-items:center;gap:8px;border:none;border-radius:9px;
    font-size:14px;font-weight:600;cursor:pointer;padding:10px 20px;transition:all .18s}
  .btn-primary{background:#f38020;color:#fff}
  .btn-primary:hover{background:#d96c10}
  .btn-primary:disabled{background:#374151;cursor:not-allowed;color:#6b7280}
  .btn-restart{background:#1e293b;color:#94a3b8;border:1px solid #334155}
  .btn-restart:hover{background:#334155;color:#e2e8f0}
  .btn-restart:disabled{opacity:.5;cursor:not-allowed}
  .btn-secondary{background:#1e2433;color:#94a3b8;border:1px solid #2d3748}
  .btn-secondary:hover{background:#2d3748}
  .spinner{width:14px;height:14px;border:2px solid rgba(255,255,255,.25);
    border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:none}
  .btn.loading .spinner{display:block}
  .btn.loading .btn-text{display:none}
  @keyframes spin{to{transform:rotate(360deg)}}

  /* ── Tabs ── */
  .tab-bar{display:flex;align-items:center;gap:4px;border-bottom:1px solid #2d3748;margin-bottom:28px}
  .tab{padding:10px 20px;font-size:14px;font-weight:500;color:#64748b;cursor:pointer;
    border:none;background:none;border-bottom:2px solid transparent;margin-bottom:-1px;
    transition:color .15s,border-color .15s;white-space:nowrap}
  .tab:hover{color:#cbd5e1}
  .tab.active{color:#f38020;border-bottom-color:#f38020;font-weight:600}
  .tab-panel{display:none}
  .tab-panel.active{display:block}

  /* ── Config panel ── */
  .config-panel{background:#1e2433;border:1px solid #2d3748;border-radius:14px;
    padding:24px;margin-bottom:24px;display:none}
  .config-panel.show{display:block}
  .config-title{font-size:15px;font-weight:600;margin-bottom:18px;color:#e2e8f0}
  .form-row{display:grid;grid-template-columns:1fr 1.5fr auto auto;gap:12px;align-items:end}
  .form-group{display:flex;flex-direction:column;gap:6px}
  label{font-size:12px;color:#94a3b8;font-weight:500;text-transform:uppercase;letter-spacing:.4px}
  input,select{background:#0f1117;border:1px solid #2d3748;border-radius:8px;
    padding:10px 12px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .18s;width:100%}
  input:focus,select:focus{border-color:#f38020}
  select option{background:#1e2433}
  .config-toggle{color:#475569;font-size:12px;cursor:pointer;background:none;border:none;
    padding:0;text-decoration:underline;text-underline-offset:3px}
  .config-toggle:hover{color:#94a3b8}

  /* ── Error / loading ── */
  .error-box{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);
    border-radius:10px;padding:14px 18px;color:#f87171;margin-bottom:20px;display:none}
  .loading-state{text-align:center;padding:80px;color:#64748b;display:none}
  .loading-state.show{display:block}
  .data-area{display:none}
  .data-area.show{display:block}

  /* ── Summary cards ── */
  .cards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:16px;margin-bottom:28px}
  .card{background:#1e2433;border:1px solid #2d3748;border-radius:14px;padding:24px;
    position:relative;overflow:hidden;transition:border-color .2s}
  .card:hover{border-color:#3d4d66}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:14px 14px 0 0}
  .card.total::before{background:#f38020}
  .card.mac::before{background:#3b82f6}
  .card.iphone::before{background:#10b981}
  .card.ipad::before{background:#8b5cf6}
  .card.other::before{background:#f59e0b}
  .card-icon{font-size:26px;margin-bottom:14px}
  .card-label{font-size:11px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
  .card-count{font-size:46px;font-weight:800;line-height:1;letter-spacing:-1px}
  .card.total .card-count{color:#f38020}
  .card.mac .card-count{color:#3b82f6}
  .card.iphone .card-count{color:#10b981}
  .card.ipad .card-count{color:#8b5cf6}
  .card.other .card-count{color:#f59e0b}
  .card-pct{font-size:12px;color:#475569;margin-top:8px}

  /* ── Sections & tables ── */
  .section{margin-bottom:28px}
  .section-title{font-size:14px;font-weight:600;color:#94a3b8;text-transform:uppercase;
    letter-spacing:.5px;margin-bottom:14px}
  .table-wrap{background:#1e2433;border:1px solid #2d3748;border-radius:14px;overflow:hidden}
  table{width:100%;border-collapse:collapse}
  th{text-align:left;padding:11px 18px;font-size:11px;font-weight:600;text-transform:uppercase;
    letter-spacing:.5px;color:#475569;background:#161b27;border-bottom:1px solid #2d3748}
  td{padding:12px 18px;font-size:14px;border-bottom:1px solid #1a2236;color:#cbd5e1}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#232b3e;transition:background .12s}

  /* ── Badges ── */
  .badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
  .badge-mac{background:rgba(59,130,246,.15);color:#3b82f6}
  .badge-iphone{background:rgba(16,185,129,.15);color:#10b981}
  .badge-ipad{background:rgba(139,92,246,.15);color:#8b5cf6}
  .badge-windows{background:rgba(14,165,233,.15);color:#0ea5e9}
  .badge-linux{background:rgba(251,191,36,.15);color:#fbbf24}
  .badge-other{background:rgba(245,158,11,.15);color:#f59e0b}
  .badge-iru{background:rgba(243,128,32,.12);color:#f38020;font-size:10px}
  .badge-jc{background:rgba(14,165,233,.12);color:#0ea5e9;font-size:10px}

  /* ── Progress bar ── */
  .progress-bar{height:5px;background:#1a2236;border-radius:3px;overflow:hidden;margin-top:5px}
  .progress-fill{height:100%;border-radius:3px;transition:width .5s ease}

  /* ── All-devices tab extras ── */
  .toolbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;gap:12px}
  .search-wrap{position:relative;width:340px}
  .search-wrap input{padding-left:36px;background:#1e2433;border-color:#2d3748}
  .search-icon{position:absolute;left:11px;top:50%;transform:translateY(-50%);
    color:#475569;font-size:15px;pointer-events:none}
  .count-label{font-size:13px;color:#64748b}
  th.sortable{cursor:pointer;user-select:none}
  th.sortable:hover{color:#94a3b8}
  th.sort-asc::after{content:' ↑';color:#f38020}
  th.sort-desc::after{content:' ↓';color:#f38020}
  .ci-fresh{color:#10b981}
  .ci-warn{color:#f59e0b}
  .ci-stale{color:#ef4444}
  .ci-unknown{color:#475569}
  .unassigned{color:#475569;font-style:italic}

  /* ── User Lookup tab ── */
  .lookup-layout{display:grid;grid-template-columns:340px 1fr;gap:20px;height:calc(100vh - 220px);min-height:500px}
  .lookup-left{display:flex;flex-direction:column;gap:12px;overflow:hidden}
  .lookup-search{position:relative}
  .lookup-search input{width:100%;padding:12px 14px 12px 40px;background:#1e2433;
    border:1px solid #2d3748;border-radius:10px;color:#e2e8f0;font-size:14px;outline:none;transition:border-color .18s}
  .lookup-search input:focus{border-color:#f38020}
  .lookup-search-icon{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:#475569;font-size:16px}
  .user-list{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:4px;
    scrollbar-width:thin;scrollbar-color:#2d3748 transparent}
  .user-row{padding:12px 14px;border-radius:10px;cursor:pointer;border:1px solid transparent;
    display:flex;align-items:center;gap:12px;transition:all .15s}
  .user-row:hover{background:#1e2433;border-color:#2d3748}
  .user-row.selected{background:#1e2433;border-color:#f38020}
  .avatar{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;color:#fff}
  .user-row-info{flex:1;min-width:0}
  .user-row-name{font-size:14px;font-weight:500;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .user-row-sub{font-size:12px;color:#64748b;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
  .user-row-badge{flex-shrink:0}
  .no-results{text-align:center;padding:40px 20px;color:#475569;font-size:14px}

  /* ── Profile panel ── */
  .lookup-right{overflow-y:auto;scrollbar-width:thin;scrollbar-color:#2d3748 transparent}
  .profile-empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
    height:100%;color:#475569;text-align:center;gap:12px}
  .profile-empty-icon{font-size:48px}
  .profile-card{background:#1e2433;border:1px solid #2d3748;border-radius:14px;overflow:hidden}
  .profile-header{padding:24px;display:flex;align-items:center;gap:18px;
    border-bottom:1px solid #2d3748;background:#161b27}
  .profile-avatar{width:60px;height:60px;border-radius:50%;display:flex;align-items:center;
    justify-content:center;font-size:22px;font-weight:700;color:#fff;flex-shrink:0}
  .profile-name{font-size:20px;font-weight:700;color:#e2e8f0;margin-bottom:4px}
  .profile-title{font-size:13px;color:#94a3b8;margin-bottom:8px}
  .profile-body{padding:24px;display:grid;grid-template-columns:1fr 1fr;gap:0}
  .attr-group{padding:16px 20px;border-bottom:1px solid #1a2236}
  .attr-group:nth-child(odd){border-right:1px solid #1a2236}
  .attr-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
    color:#475569;margin-bottom:5px}
  .attr-value{font-size:14px;color:#cbd5e1;word-break:break-all}
  .attr-value.muted{color:#475569;font-style:italic}
  .attr-value.highlight{color:#f38020}
  .attr-value.danger{color:#ef4444}
  .profile-devices{padding:20px 24px}
  .profile-devices-title{font-size:12px;font-weight:600;text-transform:uppercase;
    letter-spacing:.5px;color:#475569;margin-bottom:14px}
  .device-card{background:#161b27;border:1px solid #2d3748;border-radius:10px;
    padding:14px 16px;display:flex;align-items:center;gap:14px;margin-bottom:10px}
  .device-card:last-child{margin-bottom:0}
  .device-card-icon{font-size:22px;flex-shrink:0}
  .device-card-info{flex:1;min-width:0}
  .device-card-name{font-size:14px;font-weight:600;color:#e2e8f0}
  .device-card-model{font-size:12px;color:#64748b;margin-top:2px}
  .device-card-meta{display:flex;gap:16px;margin-top:6px;font-size:12px}
  .no-device-card{background:#161b27;border:1px dashed #2d3748;border-radius:10px;
    padding:20px;text-align:center;color:#475569;font-size:13px}

  /* ── Okta status badges ── */
  .status-active{background:rgba(16,185,129,.15);color:#10b981}
  .status-suspended{background:rgba(245,158,11,.15);color:#f59e0b}
  .status-deprovisioned{background:rgba(239,68,68,.15);color:#ef4444}
  .status-locked{background:rgba(139,92,246,.15);color:#8b5cf6}
  .status-other{background:rgba(100,116,139,.15);color:#94a3b8}

  /* ── Orphaned alert banner ── */
  .alert-banner{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.25);
    border-radius:12px;padding:16px 20px;margin-bottom:20px;display:flex;align-items:center;gap:12px}
  .alert-banner-icon{font-size:22px}
  .alert-banner-text{font-size:14px;color:#fca5a5}
  .alert-banner-count{font-size:28px;font-weight:800;color:#ef4444;margin-left:auto;white-space:nowrap}

  /* ── Department bar chart ── */
  .dept-bar{height:8px;background:#1a2236;border-radius:4px;overflow:hidden;margin-top:5px;min-width:80px}
  .dept-bar-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#f38020,#e05a00)}

  /* ── Pie-chart modal ── */
  .pie-modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;
    opacity:0;pointer-events:none;transition:opacity .2s}
  .pie-modal-overlay.open{opacity:1;pointer-events:all}
  .pie-modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-52%) scale(.97);
    width:540px;max-height:72vh;background:#161b27;border:1px solid #2d3748;border-radius:16px;
    overflow:hidden;display:flex;flex-direction:column;z-index:1001;
    opacity:0;transition:opacity .2s,transform .2s;pointer-events:none}
  .pie-modal-overlay.open .pie-modal{opacity:1;transform:translate(-50%,-50%) scale(1);pointer-events:all}
  .pie-modal-hdr{padding:18px 22px;border-bottom:1px solid #2d3748;display:flex;align-items:center;gap:12px;flex-shrink:0}
  .pie-modal-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
  .pie-modal-title{font-size:16px;font-weight:700;color:#e2e8f0;flex:1}
  .pie-modal-count{font-size:13px;color:#64748b}
  .pie-modal-close{background:none;border:none;color:#475569;font-size:18px;cursor:pointer;
    padding:4px 8px;border-radius:6px;line-height:1;flex-shrink:0}
  .pie-modal-close:hover{background:#2d3748;color:#e2e8f0}
  .pie-modal-body{overflow-y:auto;flex:1;scrollbar-width:thin;scrollbar-color:#2d3748 transparent}
  .pie-modal-row{display:flex;align-items:center;gap:12px;padding:11px 20px;
    border-bottom:1px solid #1a2236;cursor:pointer;transition:background .12s}
  .pie-modal-row:last-child{border-bottom:none}
  .pie-modal-row:hover{background:#1e2433}
  .pie-modal-row-info{flex:1;min-width:0}
  .pie-modal-row-name{font-size:14px;font-weight:500;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .pie-modal-row-sub{font-size:12px;color:#64748b;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  /* Pie slice hover */
  .pie-slice{cursor:pointer;transition:opacity .15s,filter .15s}
  .pie-slice:hover{opacity:.82;filter:brightness(1.15)}
  /* Legend items */
  .pie-legend-item{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;
    cursor:pointer;transition:background .12s}
  .pie-legend-item:hover{background:#1e2433}
  .pie-legend-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
  .pie-legend-label{font-size:13px;color:#cbd5e1;flex:1}
  .pie-legend-count{font-size:14px;font-weight:700;color:#e2e8f0}
  .pie-legend-pct{font-size:11px;color:#475569;min-width:36px;text-align:right}

  /* ── Settings sub-section ── */
  .settings-section{margin-top:18px;padding-top:18px;border-top:1px solid #2d3748}
  .settings-section-label{font-size:11px;font-weight:600;color:#475569;text-transform:uppercase;
    letter-spacing:.5px;margin-bottom:12px}

  /* ── Filter row ── */
  .filter-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
  .filter-sel{padding:7px 10px;background:#1e2433;border:1px solid #2d3748;border-radius:8px;
    color:#e2e8f0;font-size:13px;outline:none;cursor:pointer;transition:border-color .18s;
    white-space:nowrap}
  .filter-sel:focus,.filter-sel:hover{border-color:#3d4d66}
  .filter-sel option{background:#1e2433}
  /* ── Multi-select dropdown ── */
  .ms-wrap{position:relative;display:inline-block}
  .ms-trigger{display:flex;align-items:center;gap:6px;cursor:pointer;
    background:#1e2433;border:1px solid #2d3748;border-radius:8px;
    padding:7px 10px;font-size:13px;color:#e2e8f0;white-space:nowrap;
    user-select:none;transition:border-color .18s;min-width:110px}
  .ms-trigger:hover{border-color:#3d4d66}
  .ms-trigger.active{border-color:#f38020;color:#fff}
  .ms-arrow{margin-left:auto;font-size:9px;color:#64748b;transition:transform .15s}
  .ms-trigger.open .ms-arrow{transform:rotate(180deg)}
  .ms-panel{position:absolute;top:calc(100% + 4px);left:0;z-index:200;
    background:#1e293b;border:1px solid #334155;border-radius:10px;
    min-width:170px;box-shadow:0 8px 24px rgba(0,0,0,.5);display:none;padding:4px 0}
  .ms-panel.open{display:block}
  .ms-option{display:flex;align-items:center;gap:9px;padding:8px 14px;
    cursor:pointer;font-size:13px;color:#cbd5e1}
  .ms-option:hover{background:#334155}
  .ms-option input[type=checkbox]{accent-color:#f38020;width:14px;height:14px;cursor:pointer}
  .ms-clear{display:block;width:calc(100% - 28px);margin:4px 14px;padding:5px;
    background:transparent;border:1px solid #334155;border-radius:6px;
    color:#94a3b8;font-size:12px;cursor:pointer;text-align:center}
  .ms-clear:hover{background:#1e293b;color:#e2e8f0}
  .btn-export{display:inline-flex;align-items:center;gap:6px;padding:8px 14px;
    background:#1e2433;border:1px solid #2d3748;border-radius:8px;color:#94a3b8;
    font-size:13px;font-weight:500;cursor:pointer;transition:all .18s;margin-left:auto}
  .btn-export:hover{background:#2d3748;color:#e2e8f0;border-color:#3d4d66}

  /* ── Clickable links ── */
  .link-name{color:#e2e8f0;cursor:pointer;font-weight:500;transition:color .15s;background:none;border:none;padding:0;text-align:left}
  .link-name:hover{color:#f38020;text-decoration:underline}
  .link-device{color:#e2e8f0;cursor:pointer;font-weight:500;transition:color .15s;background:none;border:none;padding:0;text-align:left}
  .link-device:hover{color:#0ea5e9;text-decoration:underline}
  .link-email{color:#64748b;cursor:pointer;font-size:13px;transition:color .15s;background:none;border:none;padding:0;text-align:left}
  .link-email:hover{color:#94a3b8;text-decoration:underline}

  /* ── Device details drawer ── */
  .drawer-overlay{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:900;
    opacity:0;pointer-events:none;transition:opacity .2s}
  .drawer-overlay.open{opacity:1;pointer-events:all}
  .device-drawer{position:fixed;top:0;right:-500px;width:460px;height:100vh;
    background:#161b27;border-left:1px solid #2d3748;z-index:901;
    overflow-y:auto;transition:right .25s cubic-bezier(.4,0,.2,1);
    scrollbar-width:thin;scrollbar-color:#2d3748 transparent}
  .device-drawer.open{right:0}
  .drawer-hdr{padding:18px 20px;border-bottom:1px solid #2d3748;
    display:flex;align-items:center;gap:14px;background:#0f1117;position:sticky;top:0;z-index:1}
  .drawer-hdr-icon{font-size:30px;flex-shrink:0}
  .drawer-hdr-name{font-size:15px;font-weight:700;color:#e2e8f0;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .drawer-hdr-sub{font-size:12px;color:#64748b;margin-top:4px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .drawer-close{margin-left:auto;flex-shrink:0;background:none;border:none;color:#475569;
    font-size:18px;cursor:pointer;width:32px;height:32px;display:flex;align-items:center;
    justify-content:center;border-radius:8px;transition:all .15s}
  .drawer-close:hover{background:#2d3748;color:#e2e8f0}
  .drawer-body{padding:0 20px 28px}
  .drawer-sec{margin-top:18px}
  .drawer-sec-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
    color:#475569;padding-bottom:8px;border-bottom:1px solid #1a2236;margin-bottom:2px}
  .drawer-row{display:flex;justify-content:space-between;align-items:baseline;
    padding:9px 0;border-bottom:1px solid #111827}
  .drawer-row:last-child{border-bottom:none}
  .drawer-lbl{font-size:12px;color:#475569;font-weight:500;flex-shrink:0;margin-right:12px}
  .drawer-val{font-size:13px;color:#cbd5e1;text-align:right;word-break:break-word;max-width:280px}
  .drawer-val.good{color:#10b981;font-weight:600}
  .drawer-val.warn{color:#f59e0b;font-weight:600}
  .drawer-val.danger{color:#ef4444;font-weight:600}
  .drawer-val.mono{font-family:'SF Mono','Fira Code',monospace;font-size:12px}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────── -->
<div class="header">
  <div class="logo">
    <div class="logo-icon">🖥️</div>
    <div>
      <h1>Hungryroot IT Dashboard</h1>
      <div class="subtitle">Hungryroot · IT Device Management</div>
    </div>
  </div>
  <div class="header-right">
    <button class="config-toggle" id="settingsBtn" onclick="toggleConfig()">⚙ Settings</button>
    <span class="last-updated" id="lastUpdated"></span>
    <button class="btn btn-restart" id="restartBtn" onclick="restartServer()" title="Restart server">↺ Restart</button>
    <button class="btn btn-restart" id="stopBtn" onclick="stopServer()" title="Stop server" style="color:#f87171">■ Stop</button>
    <button class="btn btn-primary" id="refreshBtn" onclick="fetchDevices()">
      <div class="spinner"></div>
      <span class="btn-text">↻ Refresh</span>
    </button>
    <a href="/auth/logout" class="btn btn-restart" style="text-decoration:none">Sign out</a>
  </div>
</div>

<!-- ── Settings panel ─────────────────────────────────────── -->
<div class="config-panel" id="configPanel">
  <div class="config-title">API Credentials</div>

  <div class="settings-section-label">Iru (Kandji)</div>
  <div class="form-row">
    <div class="form-group">
      <label>Subdomain</label>
      <input type="text" id="subdomain" placeholder="yourcompany">
    </div>
    <div class="form-group">
      <label>API Token</label>
      <input type="password" id="apiToken" placeholder="••••••••••••">
    </div>
    <div class="form-group">
      <label>Region</label>
      <select id="region">
        <option value="us">US</option>
        <option value="eu">EU</option>
      </select>
    </div>
  </div>

  <div class="settings-section">
    <div class="settings-section-label">Okta</div>
    <div class="form-row" style="grid-template-columns:1fr 1.5fr">
      <div class="form-group">
        <label>Okta Domain</label>
        <input type="text" id="oktaDomain" placeholder="yourcompany.okta.com">
      </div>
      <div class="form-group">
        <label>API Token</label>
        <input type="password" id="oktaToken" placeholder="••••••••••••">
      </div>
    </div>
  </div>

  <div class="settings-section">
    <div class="settings-section-label">JumpCloud (Windows)</div>
    <div class="form-row" style="grid-template-columns:1fr">
      <div class="form-group">
        <label>API Key</label>
        <input type="password" id="jcApiKey" placeholder="Settings → API Settings in JumpCloud Admin Console">
      </div>
    </div>
  </div>

  <div class="settings-section">
    <div class="settings-section-label">FedEx Tracking</div>
    <div class="form-row" style="grid-template-columns:1fr 1fr">
      <div class="form-group">
        <label>Client ID</label>
        <input type="password" id="fedexClientId" placeholder="FedEx Developer Portal → App → Client ID">
      </div>
      <div class="form-group">
        <label>Client Secret</label>
        <input type="password" id="fedexSecret" placeholder="FedEx Developer Portal → App → Client Secret">
      </div>
    </div>
  </div>

  <div class="settings-section">
    <div class="settings-section-label">Dashboard Login</div>
    <div class="form-row" style="grid-template-columns:1fr 1fr auto">
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="dashUser" placeholder="admin">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="dashPass" placeholder="Set a strong password">
      </div>
      <button class="btn btn-secondary" onclick="saveConfig()" style="white-space:nowrap;align-self:flex-end">Save & Reload</button>
    </div>
    <div style="font-size:12px;color:#64748b;margin-top:4px">Leave password blank to keep the current one unchanged.</div>
  </div>
</div>

<div class="error-box" id="errorBox"></div>

<div class="loading-state" id="loadingState">
  <div style="font-size:48px;margin-bottom:16px">📡</div>
  <div style="font-size:15px">Fetching devices from Iru, JumpCloud & Okta…</div>
</div>

<!-- ── Main data area ─────────────────────────────────────── -->
<div class="data-area" id="dataArea">

  <!-- Tab bar -->
  <div class="tab-bar">
    <button class="tab active" onclick="switchTab('overview', this)">📊 Overview</button>
    <button class="tab" onclick="switchTab('devices', this)">🖥️ All Devices</button>
    <button class="tab" onclick="switchTab('users', this)">👥 Users</button>
    <button class="tab" onclick="switchTab('departments', this)">🏢 By Department</button>
    <button class="tab" onclick="switchTab('orphaned', this)">🚨 Pending Returns</button>
    <button class="tab" onclick="switchTab('admin', this)" style="margin-left:auto">🔐 Admin</button>
  </div>

  <!-- ── Tab: Overview ── -->
  <div class="tab-panel active" id="tab-overview">
    <div class="cards-grid">
      <div class="card total">
        <div class="card-icon">📦</div>
        <div class="card-label">Total Devices</div>
        <div class="card-count" id="totalCount">—</div>
      </div>
      <div class="card mac">
        <div class="card-icon">💻</div>
        <div class="card-label">Mac Computers</div>
        <div class="card-count" id="macCount">—</div>
        <div class="card-pct" id="macPct"></div>
      </div>
      <div class="card iphone">
        <div class="card-icon">📱</div>
        <div class="card-label">iPhones</div>
        <div class="card-count" id="iphoneCount">—</div>
        <div class="card-pct" id="iphonePct"></div>
      </div>
      <div class="card ipad">
        <div class="card-icon">📟</div>
        <div class="card-label">iPads</div>
        <div class="card-count" id="ipadCount">—</div>
        <div class="card-pct" id="ipadPct"></div>
      </div>
      <div class="card" id="windowsCard" style="display:none;--accent:#0ea5e9">
        <style>#windowsCard::before{background:#0ea5e9}#windowsCard .card-count{color:#0ea5e9}</style>
        <div class="card-icon">🪟</div>
        <div class="card-label">Windows PCs</div>
        <div class="card-count" id="windowsCount">—</div>
        <div class="card-pct" id="windowsPct"></div>
      </div>
      <div class="card other" id="otherCard" style="display:none">
        <div class="card-icon">📺</div>
        <div class="card-label">Other</div>
        <div class="card-count" id="otherCount">—</div>
        <div class="card-pct" id="otherPct"></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Device Distribution</div>
      <div style="display:flex;gap:48px;align-items:center;padding:12px 0 4px">
        <div style="position:relative;flex-shrink:0">
          <svg id="pieChartSvg" width="260" height="260" viewBox="0 0 260 260"></svg>
          <div id="pieChartCenter" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
            text-align:center;pointer-events:none">
            <div id="pieChartCenterNum" style="font-size:28px;font-weight:800;color:#e2e8f0;line-height:1"></div>
            <div id="pieChartCenterLbl" style="font-size:11px;color:#64748b;margin-top:3px;text-transform:uppercase;letter-spacing:.5px"></div>
          </div>
        </div>
        <div id="pieLegend" style="display:flex;flex-direction:column;gap:2px;flex:1"></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Top Models</div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Model</th>
            <th>Type</th>
            <th>Count</th>
          </tr></thead>
          <tbody id="modelsTable"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Tab: All Devices ── -->
  <div class="tab-panel" id="tab-devices">
    <div class="toolbar">
      <div class="filter-bar" style="margin-bottom:0">
        <div class="ms-wrap" id="deviceTypeFilter">
          <div class="ms-trigger" onclick="msToggle('deviceTypeFilter')">
            <span class="ms-label">All Types</span><span class="ms-arrow">▾</span>
          </div>
          <div class="ms-panel">
            <label class="ms-option"><input type="checkbox" value="Mac" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> Mac</label>
            <label class="ms-option"><input type="checkbox" value="iPhone" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> iPhone</label>
            <label class="ms-option"><input type="checkbox" value="iPad" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> iPad</label>
            <label class="ms-option"><input type="checkbox" value="Windows" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> Windows</label>
            <label class="ms-option"><input type="checkbox" value="Linux" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> Linux</label>
            <label class="ms-option"><input type="checkbox" value="Android" onchange="msChanged('deviceTypeFilter','All Types',filterDevices)"> Android</label>
            <button class="ms-clear" onclick="msClear('deviceTypeFilter','All Types',filterDevices)">Clear</button>
          </div>
        </div>
        <div class="ms-wrap" id="deviceSourceFilter">
          <div class="ms-trigger" onclick="msToggle('deviceSourceFilter')">
            <span class="ms-label">All Sources</span><span class="ms-arrow">▾</span>
          </div>
          <div class="ms-panel">
            <label class="ms-option"><input type="checkbox" value="iru" onchange="msChanged('deviceSourceFilter','All Sources',filterDevices)"> Iru (Kandji)</label>
            <label class="ms-option"><input type="checkbox" value="jumpcloud" onchange="msChanged('deviceSourceFilter','All Sources',filterDevices)"> JumpCloud</label>
            <button class="ms-clear" onclick="msClear('deviceSourceFilter','All Sources',filterDevices)">Clear</button>
          </div>
        </div>
        <div class="ms-wrap" id="deviceAssignFilter">
          <div class="ms-trigger" onclick="msToggle('deviceAssignFilter')">
            <span class="ms-label">All Assignment</span><span class="ms-arrow">▾</span>
          </div>
          <div class="ms-panel">
            <label class="ms-option"><input type="checkbox" value="assigned" onchange="msChanged('deviceAssignFilter','All Assignment',filterDevices)"> Assigned</label>
            <label class="ms-option"><input type="checkbox" value="unassigned" onchange="msChanged('deviceAssignFilter','All Assignment',filterDevices)"> Unassigned</label>
            <button class="ms-clear" onclick="msClear('deviceAssignFilter','All Assignment',filterDevices)">Clear</button>
          </div>
        </div>
        <div class="ms-wrap" id="deviceCheckInFilter">
          <div class="ms-trigger" onclick="msToggle('deviceCheckInFilter')">
            <span class="ms-label">Any Check-in</span><span class="ms-arrow">▾</span>
          </div>
          <div class="ms-panel">
            <label class="ms-option"><input type="checkbox" value="1d" onchange="msChanged('deviceCheckInFilter','Any Check-in',filterDevices)"> Within 24h</label>
            <label class="ms-option"><input type="checkbox" value="7d" onchange="msChanged('deviceCheckInFilter','Any Check-in',filterDevices)"> Within 7 days</label>
            <label class="ms-option"><input type="checkbox" value="30d" onchange="msChanged('deviceCheckInFilter','Any Check-in',filterDevices)"> Within 30 days</label>
            <label class="ms-option"><input type="checkbox" value="stale" onchange="msChanged('deviceCheckInFilter','Any Check-in',filterDevices)"> Stale (&gt;30 days)</label>
            <button class="ms-clear" onclick="msClear('deviceCheckInFilter','Any Check-in',filterDevices)">Clear</button>
          </div>
        </div>
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input type="text" id="deviceSearch" placeholder="Search name, user, model, serial…" oninput="filterDevices()">
        </div>
        <span class="count-label" id="deviceCountLabel"></span>
        <button class="btn-export" onclick="exportDevicesCSV()">⬇ Export CSV</button>
      </div>
    </div>
    <div class="table-wrap" style="overflow-x:auto">
      <table id="allDevicesTable">
        <thead><tr>
          <th class="sortable" onclick="sortBy('device_name')">Device Name</th>
          <th class="sortable" onclick="sortBy('model')">Model</th>
          <th class="sortable" onclick="sortBy('device_family')">Type</th>
          <th>Source</th>
          <th class="sortable" onclick="sortBy('user_name')">Assigned User</th>
          <th>User Email</th>
          <th>Okta Status</th>
          <th class="sortable" onclick="sortBy('last_check_in')">Last Check-in</th>
          <th class="sortable" onclick="sortBy('first_enrollment')">Enrolled</th>
        </tr></thead>
        <tbody id="allDevicesBody"></tbody>
      </table>
    </div>
  </div>

  <!-- ── Tab: Users (merged list + profile) ── -->
  <div class="tab-panel" id="tab-users">
    <div id="usersNoOkta" style="text-align:center;padding:60px;color:#64748b">
      <div style="font-size:40px;margin-bottom:12px">🔑</div>
      <div style="font-size:15px">Add your Okta credentials in <strong>⚙ Settings</strong> to enable this view.</div>
    </div>
    <div id="usersContent" style="display:none">
      <div class="lookup-layout" style="grid-template-columns:400px 1fr">
        <!-- Left: filters + scrollable user list -->
        <div class="lookup-left">
          <div style="display:flex;flex-direction:column;gap:6px">
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <div class="ms-wrap" id="usersStatusFilter" style="flex:1">
                <div class="ms-trigger" onclick="msToggle('usersStatusFilter')" style="width:100%">
                  <span class="ms-label">All Statuses</span><span class="ms-arrow">▾</span>
                </div>
                <div class="ms-panel" id="usersStatusPanel" style="min-width:180px">
                  <button class="ms-clear" onclick="msClear(\'usersStatusFilter\',\'All Statuses\',filterUsers)">Clear</button>
                </div>
              </div>
              <div class="ms-wrap" id="usersDeptFilter" style="flex:1">
                <div class="ms-trigger" onclick="msToggle('usersDeptFilter')" style="width:100%">
                  <span class="ms-label">All Departments</span><span class="ms-arrow">▾</span>
                </div>
                <div class="ms-panel" id="usersDeptPanel" style="min-width:200px;max-height:240px;overflow-y:auto"></div>
              </div>
              <div class="ms-wrap" id="usersDeviceFilter" style="flex:1">
                <div class="ms-trigger" onclick="msToggle('usersDeviceFilter')" style="width:100%">
                  <span class="ms-label">All Users</span><span class="ms-arrow">▾</span>
                </div>
                <div class="ms-panel" style="min-width:150px">
                  <label class="ms-option"><input type="checkbox" value="has_device" onchange="msChanged('usersDeviceFilter','All Users',filterUsers)"> Has Device</label>
                  <label class="ms-option"><input type="checkbox" value="no_device" onchange="msChanged('usersDeviceFilter','All Users',filterUsers)"> No Device</label>
                  <button class="ms-clear" onclick="msClear('usersDeviceFilter','All Users',filterUsers)">Clear</button>
                </div>
              </div>
            </div>
            <div class="lookup-search">
              <span class="lookup-search-icon">🔍</span>
              <input type="text" id="usersSearch" placeholder="Search name, email, dept, title…" oninput="filterUsers()">
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;padding:0 2px">
              <span class="count-label" id="usersCountLabel"></span>
              <button class="btn-export" style="margin-left:0" onclick="exportUsersCSV()">⬇ Export CSV</button>
            </div>
          </div>
          <div class="user-list" id="userList"></div>
        </div>
        <!-- Right: selected user profile -->
        <div class="lookup-right" id="lookupRight">
          <div class="profile-empty">
            <div class="profile-empty-icon">👤</div>
            <div style="font-size:15px;color:#64748b">Select a user to view their profile</div>
            <div style="font-size:13px;color:#475569">Filter or search on the left</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- ── Tab: Pending Returns ── -->
  <div class="tab-panel" id="tab-orphaned">
    <div id="orphanedBanner" style="display:none;align-items:center;gap:16px;background:linear-gradient(135deg,#1e1010,#2d1515);border:1px solid #7f1d1d;border-radius:10px;padding:14px 20px;margin-bottom:16px">
      <span style="font-size:22px">🔄</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:14px;color:#fca5a5">Pending Equipment Returns</div>
        <div style="font-size:12px;color:#94a3b8;margin-top:2px">Offboarded employees with devices not yet returned</div>
      </div>
      <div id="orphanedCount" style="font-size:22px;font-weight:700;color:#f87171">—</div>
    </div>
    <div id="orphanedEmpty" style="display:none;text-align:center;padding:60px;color:#64748b">
      <div style="font-size:40px;margin-bottom:12px">✅</div>
      <div style="font-size:15px">No pending returns — all offboarded employees have returned their equipment.</div>
    </div>
    <div id="orphanedNoOkta" style="text-align:center;padding:60px;color:#64748b">
      <div style="font-size:40px;margin-bottom:12px">🔑</div>
      <div style="font-size:15px">Add your Okta credentials in <strong>⚙ Settings</strong> to enable this view.</div>
    </div>
    <div class="table-wrap" id="orphanedTable" style="display:none;overflow-x:auto">
      <table>
        <thead><tr>
          <th>Employee</th>
          <th>Device</th>
          <th>Term Date</th>
          <th style="text-align:center">Okta</th>
          <th style="text-align:center">Slack</th>
          <th style="text-align:center">Google</th>
          <th>Outbound Box</th>
          <th>Return Status</th>
          <th>Actions</th>
        </tr></thead>
        <tbody id="orphanedBody"></tbody>
      </table>
    </div>
  </div>

  <!-- ── Tab: By Department ── -->
  <div class="tab-panel" id="tab-departments">
    <div id="deptNoOkta" style="text-align:center;padding:60px;color:#64748b">
      <div style="font-size:40px;margin-bottom:12px">🔑</div>
      <div style="font-size:15px">Add your Okta credentials in <strong>⚙ Settings</strong> to enable this view.</div>
    </div>
    <div id="deptContent" style="display:none">
      <div class="cards-grid" id="deptSummaryCards" style="margin-bottom:28px"></div>
      <div class="section">
        <div class="section-title">Devices by Department</div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>Department</th>
              <th>Active Users</th>
              <th>Devices</th>
              <th>💻 Mac</th>
              <th>🪟 Windows</th>
              <th>📱 iPhone</th>
              <th>📟 iPad</th>
              <th style="width:180px">Device Share</th>
            </tr></thead>
            <tbody id="deptTable"></tbody>
          </table>
        </div>
      </div>
      <div class="section">
        <div class="section-title">Users Without a Device</div>
        <div class="table-wrap" style="overflow-x:auto">
          <table>
            <thead><tr>
              <th>Name</th>
              <th>Email</th>
              <th>Department</th>
              <th>Title</th>
              <th>Okta Status</th>
            </tr></thead>
            <tbody id="noDeviceTable"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

</div><!-- /data-area -->

<!-- ── Device Details Drawer ───────────────────────────────── -->
<!-- ── Pie-chart drill-down modal ── -->
<div class="pie-modal-overlay" id="pieModalOverlay" onclick="closePieModal()">
  <div class="pie-modal" onclick="event.stopPropagation()">
    <div class="pie-modal-hdr">
      <div class="pie-modal-dot" id="pieModalDot"></div>
      <div class="pie-modal-title" id="pieModalTitle"></div>
      <span class="pie-modal-count" id="pieModalCount"></span>
      <button class="pie-modal-close" onclick="closePieModal()">✕</button>
    </div>
    <div class="pie-modal-body" id="pieModalBody"></div>
  </div>
</div>

<div class="drawer-overlay" id="drawerOverlay" onclick="closeDeviceDrawer()"></div>
<div class="device-drawer" id="deviceDrawer">
  <div class="drawer-hdr">
    <div class="drawer-hdr-icon" id="drawerIcon"></div>
    <div style="flex:1;min-width:0">
      <div class="drawer-hdr-name" id="drawerTitle"></div>
      <div class="drawer-hdr-sub" id="drawerSub"></div>
    </div>
    <button class="drawer-close" onclick="closeDeviceDrawer()">✕</button>
  </div>
  <div class="drawer-body" id="drawerBody"></div>
</div>

<script>
  // ── Helpers ──────────────────────────────────────────────────────────────
  function badgeClass(fam) {
    const f = (fam||'').toLowerCase();
    if (f==='mac')     return 'badge-mac';
    if (f==='iphone')  return 'badge-iphone';
    if (f==='ipad')    return 'badge-ipad';
    if (f==='windows') return 'badge-windows';
    if (f==='linux')   return 'badge-linux';
    return 'badge-other';
  }
  function barColor(fam) {
    const f = (fam||'').toLowerCase();
    if (f==='mac')     return '#3b82f6';
    if (f==='iphone')  return '#10b981';
    if (f==='ipad')    return '#8b5cf6';
    if (f==='windows') return '#0ea5e9';
    if (f==='linux')   return '#fbbf24';
    return '#f59e0b';
  }
  function sourceBadge(src) {
    if (src === 'jumpcloud') return '<span class="badge badge-jc">JumpCloud</span>';
    return '<span class="badge badge-iru">Iru</span>';
  }
  function pct(n, total) { return total ? Math.round(n/total*100) : 0; }

  function fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleDateString([], {year:'numeric',month:'short',day:'numeric'});
  }

  function checkInClass(iso) {
    if (!iso) return 'ci-unknown';
    const days = (Date.now() - new Date(iso)) / 86400000;
    if (days < 1) return 'ci-fresh';
    if (days < 7) return 'ci-fresh';
    if (days < 30) return 'ci-warn';
    return 'ci-stale';
  }

  function fmtRelative(iso) {
    if (!iso) return '—';
    const mins = Math.round((Date.now() - new Date(iso)) / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return mins + 'm ago';
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    const days = Math.round(hrs / 24);
    if (days < 30) return days + 'd ago';
    return fmtDate(iso);
  }

  function esc(s) {
    return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  function deviceConsoleUrl(d) {
    if (!d) return null;
    if (d.source === 'iru' && d.device_id)
      return { url: `https://${window.iruSubdomain || 'hungryroot'}.iru.com/devices/${d.device_id}`, label: 'Iru' };
    if (d.source === 'jumpcloud' && d.jc_system_id)
      return { url: `https://console.jumpcloud.com/#/devices/${d.jc_system_id}/details/highlights`, label: 'JumpCloud' };
    return null;
  }

  function kandjiLink(d) {
    const info = deviceConsoleUrl(d);
    if (!info) return '';
    return `<a href="${info.url}" target="_blank" title="Open in ${info.label}"
      style="color:#64748b;font-size:11px;margin-left:5px;text-decoration:none;opacity:0.7"
      onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.7">↗ ${info.label}</a>`;
  }

  // Keep old name as alias (used in offboarding modal)
  function kandjiUrl(d) { return deviceConsoleUrl(d)?.url || null; }

  // ── State ─────────────────────────────────────────────────────────────────
  let allDevicesFlat = [];
  let allUsersFlat   = [];   // normalised Okta user rows
  let devicesByEmail = {};   // email → [device, ...]
  let oktaUserMap = {};      // email (lowercase) → okta user object
  let sortCol = 'last_check_in';
  let sortDir = -1;          // -1 = desc, 1 = asc

  // ── Tabs ──────────────────────────────────────────────────────────────────
  function switchTab(name, btn) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => { p.classList.remove('active'); p.style.display='none'; });
    btn.classList.add('active');
    const panel = document.getElementById('tab-' + name);
    panel.classList.add('active');
    panel.style.display = '';
    if (name === 'admin') loadAdminTab();
  }

  // ── Config ────────────────────────────────────────────────────────────────
  function toggleConfig() {
    document.getElementById('configPanel').classList.toggle('show');
  }

  function saveConfig() {
    const subdomain  = document.getElementById('subdomain').value.trim();
    const token      = document.getElementById('apiToken').value.trim();
    const region     = document.getElementById('region').value;
    const oktaDomain = document.getElementById('oktaDomain').value.trim();
    const oktaToken  = document.getElementById('oktaToken').value.trim();
    const jcApiKey   = document.getElementById('jcApiKey').value.trim();
    const dashUser      = document.getElementById('dashUser').value.trim();
    const dashPass      = document.getElementById('dashPass').value.trim();
    const fedexClientId = document.getElementById('fedexClientId').value.trim();
    const fedexSecret   = document.getElementById('fedexSecret').value.trim();
    if (!subdomain || !token) { alert('Please enter Iru subdomain and token.'); return; }
    fetch('/api/save-config', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({subdomain, token, region, okta_domain: oktaDomain, okta_token: oktaToken,
        jumpcloud_api_key: jcApiKey, dashboard_user: dashUser, dashboard_pass: dashPass,
        fedex_client_id: fedexClientId, fedex_client_secret: fedexSecret})
    }).then(r => r.json()).then(d => {
      if (d.ok) { document.getElementById('configPanel').classList.remove('show'); fetchAll(); }
      else alert('Error saving: ' + d.error);
    });
  }

  // ── Multi-select helpers ──────────────────────────────────────────────────
  function msToggle(id) {
    const wrap  = document.getElementById(id);
    const panel = wrap.querySelector('.ms-panel');
    const trig  = wrap.querySelector('.ms-trigger');
    const isOpen = panel.classList.contains('open');
    // Close all others first
    document.querySelectorAll('.ms-panel.open').forEach(p => {
      p.classList.remove('open');
      p.parentElement.querySelector('.ms-trigger')?.classList.remove('open');
    });
    if (!isOpen) {
      panel.classList.add('open');
      trig.classList.add('open');
    }
  }

  function msVals(id) {
    return [...document.getElementById(id).querySelectorAll('input:checked')].map(c => c.value);
  }

  function msChanged(id, allLabel, cb) {
    const vals  = msVals(id);
    const label = document.getElementById(id).querySelector('.ms-label');
    const trig  = document.getElementById(id).querySelector('.ms-trigger');
    if (vals.length === 0) {
      label.textContent = allLabel;
      trig.classList.remove('active');
    } else {
      label.textContent = vals.length === 1 ? vals[0] : vals.length + ' selected';
      trig.classList.add('active');
    }
    if (cb) cb();
  }

  function msClear(id, allLabel, cb) {
    document.getElementById(id).querySelectorAll('input[type=checkbox]').forEach(c => c.checked = false);
    const label = document.getElementById(id).querySelector('.ms-label');
    const trig  = document.getElementById(id).querySelector('.ms-trigger');
    if (label) label.textContent = allLabel;
    if (trig)  trig.classList.remove('active');
    if (cb) cb();
  }

  // Close multi-selects when clicking outside
  document.addEventListener('click', e => {
    if (!e.target.closest('.ms-wrap')) {
      document.querySelectorAll('.ms-panel.open').forEach(p => {
        p.classList.remove('open');
        p.parentElement.querySelector('.ms-trigger')?.classList.remove('open');
      });
    }
  });

  // ── Fetch both APIs in parallel ───────────────────────────────────────────
  async function stopServer() {
    if (!confirm('Stop the dashboard server? The page will close and you will need to relaunch the app to use it again.')) return;
    const btn = document.getElementById('stopBtn');
    btn.disabled = true;
    btn.textContent = '■ Stopping…';
    try { await fetch('/api/stop').catch(() => {}); } catch(e) {}
    // Replace page with a simple stopped message
    setTimeout(() => {
      document.body.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;background:#0f172a;color:#94a3b8;font-family:system-ui;gap:16px"><div style="font-size:48px">&#x1F6D1;</div><div style="font-size:18px;color:#e2e8f0">Server stopped</div><div style="font-size:14px">Relaunch the app to start it again.</div></div>';
    }, 800);
  }

  async function restartServer() {
    const btn = document.getElementById('restartBtn');
    btn.disabled = true;
    btn.textContent = '↺ Restarting…';

    try {
      await fetch('/api/restart').catch(() => {});  // server will drop the connection — that's expected
    } catch(e) {}

    // Poll until the server is back up, then reload
    const poll = async () => {
      try {
        const r = await fetch('/api/devices', {signal: AbortSignal.timeout(1500)});
        if (r.ok || r.status === 503) {
          btn.textContent = '↺ Reloading…';
          location.reload();
          return;
        }
      } catch(e) {}
      setTimeout(poll, 800);
    };

    // Give the server a moment to go down before polling
    setTimeout(poll, 1200);
  }

  // ── Cache status polling ──────────────────────────────────────────────────
  let _cacheStatusInterval = null;

  function fmtAge(secs) {
    if (secs === null || secs === undefined) return 'no data';
    if (secs < 60)  return 'just now';
    if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
    return `${Math.floor(secs/3600)}h ago`;
  }

  async function updateCacheStatus() {
    try {
      const r = await fetch('/api/cache-status');
      if (!r.ok) return;
      const s = await r.json();
      const age = s.ages.devices;
      const el  = document.getElementById('lastUpdated');
      if (s.refreshing) {
        el.textContent = '⟳ Refreshing…';
        el.style.color = '#f59e0b';
      } else {
        el.textContent = 'Updated ' + fmtAge(age);
        el.style.color = '';
      }
    } catch(e) {}
  }

  function startCachePolling() {
    updateCacheStatus();
    if (_cacheStatusInterval) clearInterval(_cacheStatusInterval);
    _cacheStatusInterval = setInterval(updateCacheStatus, 10000);
  }

  async function fetchAll() {
    const btn = document.getElementById('refreshBtn');
    btn.classList.add('loading');
    btn.disabled = true;
    document.getElementById('errorBox').style.display = 'none';
    document.getElementById('loadingState').classList.add('show');
    document.getElementById('dataArea').classList.remove('show');

    try {
      // Fetch Iru devices + Okta users + JumpCloud devices in parallel (all served from cache)
      const [iruResp, oktaBulkResp, jcResp, metaResp] = await Promise.all([
        fetch('/api/devices'),
        fetch('/api/okta-users').catch(() => null),
        fetch('/api/jumpcloud-devices').catch(() => null),
        fetch('/api/meta').catch(() => null),
      ]);
      if (metaResp && metaResp.ok) {
        const meta = await metaResp.json();
        window.iruSubdomain = meta.subdomain || '';
      }
      if (!iruResp.ok) throw new Error(await iruResp.text());
      const iruDevices = await iruResp.json();

      iruDevices.forEach(d => { d.source = d.source || 'iru'; });

      let jcDevices = [];
      if (jcResp && jcResp.ok) jcDevices = await jcResp.json();
      const devices = [...iruDevices, ...jcDevices];

      oktaUserMap = {};
      const addToMap = u => {
        const email = (u.profile?.email || '').toLowerCase().trim();
        const login = (u.profile?.login || '').toLowerCase().trim();
        if (email) oktaUserMap[email] = u;
        if (login && login !== email) oktaUserMap[login] = u;
      };
      if (oktaBulkResp && oktaBulkResp.ok) {
        (await oktaBulkResp.json()).forEach(addToMap);
      }

      // Targeted lookup for any device email missing from the bulk result
      const deviceEmails = [...new Set(
        devices.map(d => (d.user?.email || d.assigned_user?.email || '')).filter(Boolean).map(e => e.toLowerCase())
      )];
      const missingEmails = deviceEmails.filter(e => !oktaUserMap[e]);
      if (missingEmails.length > 0) {
        const targetedResp = await fetch('/api/okta-lookup', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({emails: missingEmails}),
        }).catch(() => null);
        if (targetedResp && targetedResp.ok) {
          (await targetedResp.json()).forEach(addToMap);
        }
      }

      renderDashboard(devices);
      startCachePolling();
    } catch(e) {
      const box = document.getElementById('errorBox');
      box.style.display = 'block';
      box.innerHTML = '<strong>⚠ Could not load devices:</strong> ' + e.message +
        '<br><small style="opacity:.7">Check your credentials in ⚙ Settings or review iru_config.json.</small>';
      document.getElementById('dataArea').classList.remove('show');
    } finally {
      btn.classList.remove('loading');
      btn.disabled = false;
      document.getElementById('loadingState').classList.remove('show');
    }
  }

  // Refresh button: trigger server-side fetch, wait for it, then reload data
  async function fetchDevices() {
    const btn = document.getElementById('refreshBtn');
    btn.classList.add('loading');
    btn.disabled = true;
    document.getElementById('lastUpdated').textContent = '⟳ Refreshing…';
    document.getElementById('lastUpdated').style.color = '#f59e0b';

    try {
      await fetch('/api/force-refresh');

      // Poll until server-side refresh is done (refreshing flag clears)
      await new Promise(resolve => {
        const check = async () => {
          try {
            const r = await fetch('/api/cache-status');
            const s = await r.json();
            if (!s.refreshing) { resolve(); return; }
          } catch(e) {}
          setTimeout(check, 1500);
        };
        setTimeout(check, 1000);
      });

      // Now re-fetch all data from the freshly populated cache
      await fetchAll();
    } catch(e) {
      btn.classList.remove('loading');
      btn.disabled = false;
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  function renderDashboard(devices) {
    document.getElementById('dataArea').classList.add('show');

    const total = devices.length;
    const families = {}, models = {};

    // Normalise each device into a flat row for the all-devices table
    allDevicesFlat = devices.map((d, idx) => {
      const user = d.user || d.assigned_user || {};
      const fam  = d.device_family || d.platform || 'Unknown';
      return {
        _idx:             idx,
        _raw:             d,          // full raw object for details drawer
        device_id:        d.device_id || d.id || '',
        jc_system_id:     d._extra?.jc_system_id || '',
        device_name:      d.device_name || d.name || '—',
        model:            d.model || '—',
        device_family:    fam,
        serial_number:    d.serial_number || '',
        user_name:        user.name || user.full_name || '',
        user_email:       (user.email || '').toLowerCase(),
        last_check_in:    d.last_check_in || d.last_checkin || null,
        first_enrollment: d.first_enrollment || d.enrollment_date || d.enrolled_at || null,
        source:           d.source || 'iru',
      };
    });

    allDevicesFlat.forEach(d => {
      families[d.device_family] = (families[d.device_family] || 0) + 1;
      if (!models[d.model]) models[d.model] = {count:0, family:d.device_family};
      models[d.model].count++;
    });

    // ── Summary cards
    document.getElementById('totalCount').textContent = total.toLocaleString();
    const mac     = families['Mac']     || 0;
    const iphone  = families['iPhone']  || 0;
    const ipad    = families['iPad']    || 0;
    const windows = families['Windows'] || 0;
    const linux   = families['Linux']   || 0;
    const other   = total - mac - iphone - ipad - windows - linux;
    document.getElementById('macCount').textContent    = mac.toLocaleString();
    document.getElementById('iphoneCount').textContent = iphone.toLocaleString();
    document.getElementById('ipadCount').textContent   = ipad.toLocaleString();
    document.getElementById('macPct').textContent    = total ? pct(mac,total)+'% of fleet' : '';
    document.getElementById('iphonePct').textContent = total ? pct(iphone,total)+'% of fleet' : '';
    document.getElementById('ipadPct').textContent   = total ? pct(ipad,total)+'% of fleet' : '';
    if (windows > 0) {
      document.getElementById('windowsCard').style.display = 'block';
      document.getElementById('windowsCount').textContent  = windows.toLocaleString();
      document.getElementById('windowsPct').textContent    = total ? pct(windows,total)+'% of fleet' : '';
    }
    if (other > 0) {
      document.getElementById('otherCard').style.display = 'block';
      document.getElementById('otherCount').textContent = other.toLocaleString();
      document.getElementById('otherPct').textContent   = total ? pct(other,total)+'% of fleet' : '';
    }

    // ── Pie chart
    const noDeviceCount = Object.keys(oktaUserMap).length > 0
      ? Object.values(oktaUserMap).filter(u => {
          const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
          const ACTIVE = new Set(['ACTIVE','RECOVERY','PASSWORD_EXPIRED','LOCKED_OUT']);
          return ACTIVE.has((u.status||'').toUpperCase()) &&
                 !allDevicesFlat.some(d => d.user_email === email);
        }).length
      : 0;
    const pieSegments = [
      {label:'Mac',       count:mac,           color:'#3b82f6', icon:'💻'},
      {label:'Windows',   count:windows,        color:'#0ea5e9', icon:'🪟'},
      {label:'iPhone',    count:iphone,         color:'#10b981', icon:'📱'},
      {label:'iPad',      count:ipad,           color:'#8b5cf6', icon:'📟'},
      {label:'No Device', count:noDeviceCount,  color:'#475569', icon:'📵'},
      {label:'Other',     count:other,          color:'#f59e0b', icon:'🖥️'},
    ].filter(s => s.count > 0);
    drawPieChart(pieSegments, total + noDeviceCount);

    // ── Models table (top 25)
    const sortedModels = Object.entries(models).sort((a,b)=>b[1].count-a[1].count).slice(0,25);
    document.getElementById('modelsTable').innerHTML = sortedModels.map(([model,info]) => `
      <tr>
        <td>${esc(model)}</td>
        <td><span class="badge ${badgeClass(info.family)}">${esc(info.family)}</span></td>
        <td style="font-weight:700">${info.count.toLocaleString()}</td>
      </tr>
    `).join('');

    // ── All-devices table
    document.getElementById('deviceSearch').value = '';
    document.getElementById('deviceTypeFilter').value = '';
    document.getElementById('deviceSourceFilter').value = '';
    document.getElementById('deviceAssignFilter').value = '';
    document.getElementById('deviceCheckInFilter').value = '';
    renderAllDevices(allDevicesFlat);

    // ── Okta-powered tabs
    buildAllUsers();
    renderOrphaned();
    renderDepartments();
  }

  // ── All-Devices table: sort & filter ─────────────────────────────────────
  function sortBy(col) {
    // Update sort state
    if (sortCol === col) { sortDir *= -1; }
    else { sortCol = col; sortDir = -1; }

    // Update header classes
    document.querySelectorAll('#allDevicesTable th').forEach(th => {
      th.classList.remove('sort-asc','sort-desc');
      if (th.getAttribute('onclick') === `sortBy('${col}')`) {
        th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
      }
    });

    filterDevices();
  }

  function filterDevices() {
    const q        = document.getElementById('deviceSearch').value.toLowerCase();
    const typeF    = msVals('deviceTypeFilter');
    const sourceF  = msVals('deviceSourceFilter');
    const assignF  = msVals('deviceAssignFilter');
    const checkInF = msVals('deviceCheckInFilter');
    const now = Date.now();

    const filtered = allDevicesFlat.filter(d => {
      if (typeF.length   && !typeF.includes(d.device_family))  return false;
      if (sourceF.length && !sourceF.includes(d.source))       return false;
      if (assignF.length) {
        const isAssigned = !!d.user_email;
        if (!assignF.some(v => v === 'assigned' ? isAssigned : !isAssigned)) return false;
      }
      if (checkInF.length) {
        const ts  = d.last_check_in ? new Date(d.last_check_in).getTime() : 0;
        const age = now - ts;
        const ok  = checkInF.some(v => {
          if (v === '1d')    return ts && age <= 86400000;
          if (v === '7d')    return ts && age <= 7*86400000;
          if (v === '30d')   return ts && age <= 30*86400000;
          if (v === 'stale') return !ts || age > 30*86400000;
          return false;
        });
        if (!ok) return false;
      }
      if (q && !(d.device_name+d.model+d.user_name+d.user_email+d.serial_number).toLowerCase().includes(q)) return false;
      return true;
    });
    renderAllDevices(filtered);
  }

  function renderAllDevices(rows) {
    // Sort
    const sorted = [...rows].sort((a,b) => {
      let va = a[sortCol] || '', vb = b[sortCol] || '';
      // Date fields: compare as timestamps
      if (sortCol === 'last_check_in' || sortCol === 'first_enrollment') {
        va = va ? new Date(va).getTime() : 0;
        vb = vb ? new Date(vb).getTime() : 0;
        return sortDir * (va - vb);
      }
      return sortDir * va.toString().localeCompare(vb.toString());
    });

    document.getElementById('deviceCountLabel').textContent =
      sorted.length === allDevicesFlat.length
        ? `${sorted.length.toLocaleString()} devices`
        : `${sorted.length.toLocaleString()} of ${allDevicesFlat.length.toLocaleString()} devices`;

    document.getElementById('allDevicesBody').innerHTML = sorted.map(d => {
      const ciClass   = checkInClass(d.last_check_in);
      const userName  = d.user_name
        ? `<button class="link-name" onclick="goToUser('${d.user_email}')">${esc(d.user_name)}</button>`
        : `<span class="unassigned">Unassigned</span>`;
      const userEmail = d.user_email
        ? `<button class="link-email" onclick="goToUser('${d.user_email}')">${esc(d.user_email)}</button>`
        : '—';
      const oktaUser  = d.user_email ? oktaUserMap[d.user_email.toLowerCase()] : null;
      const oktaStatus = oktaUser ? oktaStatusBadge(oktaUser.status) : '<span style="color:#475569;font-size:12px">—</span>';
      return `
        <tr>
          <td>
            <button class="link-device" onclick="openDeviceDrawer(${d._idx})">${esc(d.device_name)}</button>
            ${kandjiLink(d)}
          </td>
          <td style="color:#94a3b8">${esc(d.model)}</td>
          <td><span class="badge ${badgeClass(d.device_family)}">${esc(d.device_family)}</span></td>
          <td>${sourceBadge(d.source)}</td>
          <td>${userName}</td>
          <td>${userEmail}</td>
          <td>${oktaStatus}</td>
          <td class="${ciClass}" title="${d.last_check_in||''}">${fmtRelative(d.last_check_in)}</td>
          <td style="color:#94a3b8">${fmtDate(d.first_enrollment)}</td>
        </tr>`;
    }).join('');
  }

  // ── User Lookup tab ──────────────────────────────────────────────────────
  const AVATAR_COLORS = [
    '#3b82f6','#10b981','#8b5cf6','#f59e0b','#ef4444',
    '#06b6d4','#f97316','#84cc16','#ec4899','#6366f1',
  ];
  function avatarColor(name) {
    let h = 0;
    for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0xfffffff;
    return AVATAR_COLORS[h % AVATAR_COLORS.length];
  }
  function initials(name) {
    const parts = name.trim().split(/\s+/);
    return parts.length >= 2
      ? (parts[0][0] + parts[parts.length-1][0]).toUpperCase()
      : (name[0] || '?').toUpperCase();
  }
  function fmtHireDate(val) {
    if (!val) return null;
    // Okta stores as "MM/DD/YYYY" or ISO
    const d = new Date(val);
    if (!isNaN(d)) return d.toLocaleDateString([], {year:'numeric',month:'long',day:'numeric'});
    return val;
  }

  let lookupSelectedId = null;

  // ── Navigate to Users tab and select a user by email ─────────────────────
  function goToUser(email) {
    const e = (email || '').toLowerCase();
    const u = allUsersFlat.find(u => u.email === e);
    if (!u) return;
    // Switch to Users tab
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelector('.tab[onclick*="users"]').classList.add('active');
    document.getElementById('tab-users').classList.add('active');
    // Clear all filters so user is visible in list
    document.getElementById('usersSearch').value = '';
    document.getElementById('usersStatusFilter').value = '';
    msClear('usersDeptFilter', 'All Departments', null);
    document.getElementById('usersDeviceFilter').value = '';
    lookupSelectedId = u.id;
    filterUsers();
    selectUser(u.id);
    setTimeout(() => {
      const sel = document.querySelector('.user-row.selected');
      if (sel) sel.scrollIntoView({block:'nearest', behavior:'smooth'});
    }, 60);
    closeDeviceDrawer();
  }

  // ── Device details drawer ────────────────────────────────────────────────
  function openDeviceDrawer(idx) {
    const d = allDevicesFlat[idx];
    if (!d) return;

    const f    = d.device_family || '';
    const icon = f==='Mac' ? '💻' : f==='iPhone' ? '📱' : f==='iPad' ? '📟' : f==='Windows' ? '🪟' : '🖥️';
    document.getElementById('drawerIcon').textContent = icon;
    document.getElementById('drawerTitle').textContent = d.device_name;
    document.getElementById('drawerSub').innerHTML =
      `<span class="badge ${badgeClass(f)}">${esc(f)}</span>${sourceBadge(d.source)}` +
      (d.serial_number ? `<span style="font-family:monospace;font-size:11px;color:#475569">${esc(d.serial_number)}</span>` : '');

    const raw   = d._raw || {};
    const extra = raw._extra || {};

    // OS: JumpCloud has extra.os_display (e.g. "Windows 11 Pro (26200.8246)"); Iru has raw.os_version
    const osDisplay = extra.os_display || extra.os_name || extra.os_version || raw.os_version || raw.osVersion || '';

    // ── User section
    const oktaU = d.user_email ? (oktaUserMap[d.user_email] || null) : null;
    const hasUser = d.user_name || d.user_email;
    const userHTML = `
      <div class="drawer-sec">
        <div class="drawer-sec-title">Assigned User</div>
        ${hasUser ? `
          ${d.user_name ? `<div class="drawer-row">
            <span class="drawer-lbl">Name</span>
            <span class="drawer-val">${d.user_email
              ? `<button class="link-name" onclick="goToUser('${d.user_email}')">${esc(d.user_name)}</button>`
              : esc(d.user_name)}</span></div>` : ''}
          ${d.user_email ? `<div class="drawer-row">
            <span class="drawer-lbl">Email</span>
            <span class="drawer-val" style="color:#64748b">${esc(d.user_email)}</span></div>` : ''}
          ${oktaU ? `<div class="drawer-row">
            <span class="drawer-lbl">Okta Status</span>
            <span class="drawer-val">${oktaStatusBadge(oktaU.status)}</span></div>` : ''}
        ` : `<div style="color:#475569;font-style:italic;padding:10px 0;font-size:13px">No user assigned</div>`}
      </div>`;

    // ── System info
    const hwModel  = extra.hw_model  || '';
    const hwVendor = extra.hw_vendor || '';
    const cpuModel = extra.cpu_model || '';
    const memGb    = extra.memory_gb || '';
    // Model row: show hw_model if different from d.model (avoids dupe)
    const modelVal = hwModel || d.model;
    const vendorVal = hwVendor && hwVendor.toLowerCase() !== modelVal.toLowerCase() ? hwVendor : '';
    const sysHTML = `
      <div class="drawer-sec">
        <div class="drawer-sec-title">System Info</div>
        <div class="drawer-row"><span class="drawer-lbl">Model</span><span class="drawer-val">${esc(modelVal)}</span></div>
        ${vendorVal ? `<div class="drawer-row"><span class="drawer-lbl">Manufacturer</span><span class="drawer-val">${esc(vendorVal)}</span></div>` : ''}
        ${osDisplay ? `<div class="drawer-row"><span class="drawer-lbl">OS</span><span class="drawer-val">${esc(osDisplay)}</span></div>` : ''}
        ${cpuModel ? `<div class="drawer-row"><span class="drawer-lbl">CPU</span><span class="drawer-val">${esc(cpuModel)}</span></div>` : ''}
        ${memGb ? `<div class="drawer-row"><span class="drawer-lbl">Memory</span><span class="drawer-val">${esc(memGb)}</span></div>` : ''}
        ${extra.arch ? `<div class="drawer-row"><span class="drawer-lbl">Architecture</span><span class="drawer-val">${esc(extra.arch)}</span></div>` : ''}
        ${d.serial_number ? `<div class="drawer-row"><span class="drawer-lbl">Serial</span><span class="drawer-val mono">${esc(d.serial_number)}</span></div>` : ''}
        <div class="drawer-row"><span class="drawer-lbl">Last Check-in</span>
          <span class="drawer-val ${checkInClass(d.last_check_in)}">${d.last_check_in ? new Date(d.last_check_in).toLocaleString() : '—'}</span></div>
        <div class="drawer-row"><span class="drawer-lbl">Enrolled</span>
          <span class="drawer-val">${d.first_enrollment ? new Date(d.first_enrollment).toLocaleString() : '—'}</span></div>
      </div>`;

    // ── Security (JumpCloud)
    let secHTML = '';
    if (d.source === 'jumpcloud') {
      const fde  = extra.fde_encrypted;
      const mdm  = extra.mdm_enabled;
      const aad  = extra.azure_ad_joined;
      const dom  = extra.domain_info;
      const agv  = extra.agent_version;
      const jcid = extra.jc_system_id || '';
      secHTML = `
        <div class="drawer-sec">
          <div class="drawer-sec-title">Security & Compliance</div>
          ${fde !== undefined && fde !== null ? `<div class="drawer-row">
            <span class="drawer-lbl">Disk Encryption</span>
            <span class="drawer-val ${fde ? 'good' : 'danger'}">${fde ? '✓ Encrypted' : '✗ Not Encrypted'}</span></div>` : ''}
          ${mdm !== undefined && mdm !== null ? `<div class="drawer-row">
            <span class="drawer-lbl">MDM Enrolled</span>
            <span class="drawer-val ${mdm ? 'good' : 'warn'}">${mdm ? '✓ Yes' : '✗ No'}</span></div>` : ''}
          ${aad !== undefined ? `<div class="drawer-row">
            <span class="drawer-lbl">Azure AD</span>
            <span class="drawer-val ${aad ? 'good' : 'warn'}">${aad ? '✓ Joined' : '✗ Not Joined'}</span></div>` : ''}
          ${dom ? `<div class="drawer-row"><span class="drawer-lbl">Domain</span><span class="drawer-val">${esc(dom)}</span></div>` : ''}
          ${agv ? `<div class="drawer-row"><span class="drawer-lbl">JC Agent</span><span class="drawer-val" style="color:#64748b">${esc(agv)}</span></div>` : ''}
          ${jcid ? `<div class="drawer-row"><span class="drawer-lbl">JC System ID</span>
            <span class="drawer-val mono" style="font-size:10px;color:#475569">${esc(jcid)}</span></div>` : ''}
        </div>`;
    }

    // ── Iru / Kandji: static fields (always available)
    let iruHTML = '';
    if (d.source === 'iru') {
      const bp  = raw.blueprint_name || (raw.blueprint || {}).name || '';
      const osV = raw.os_version || '';
      iruHTML = `
        <div class="drawer-sec" id="iruDetailsSection">
          <div class="drawer-sec-title">Iru / Kandji</div>
          ${bp  ? `<div class="drawer-row"><span class="drawer-lbl">Blueprint</span><span class="drawer-val">${esc(bp)}</span></div>` : ''}
          ${osV ? `<div class="drawer-row"><span class="drawer-lbl">OS Version</span><span class="drawer-val">${esc(osV)}</span></div>` : ''}
          <div id="iruHardwareRows"><div style="color:#475569;font-size:12px;padding:8px 0">Loading hardware details…</div></div>
        </div>`;
    }

    document.getElementById('drawerBody').innerHTML = userHTML + sysHTML + secHTML + iruHTML;
    document.getElementById('drawerOverlay').classList.add('open');
    document.getElementById('deviceDrawer').classList.add('open');

    // Lazy-fetch Iru device details
    if (d.source === 'iru') {
      const devId = raw.device_id || raw.id || '';
      if (devId) {
        fetch(`/api/iru-device-details?id=${encodeURIComponent(devId)}`)
          .then(r => r.ok ? r.json() : null)
          .then(det => {
            const hw  = (det && det.hardware_overview)   || {};
            const net = (det && det.network)             || {};
            const agt = (det && det.agent)               || {};
            const rows = [
              hw.model_name          && `<div class="drawer-row"><span class="drawer-lbl">Model Name</span><span class="drawer-val">${esc(hw.model_name)}</span></div>`,
              hw.model_identifier    && `<div class="drawer-row"><span class="drawer-lbl">Model ID</span><span class="drawer-val mono" style="font-size:11px">${esc(hw.model_identifier)}</span></div>`,
              hw.processor_name      && `<div class="drawer-row"><span class="drawer-lbl">CPU</span><span class="drawer-val">${esc(hw.processor_name)}</span></div>`,
              hw.total_number_of_cores && `<div class="drawer-row"><span class="drawer-lbl">Cores</span><span class="drawer-val">${esc(hw.total_number_of_cores)}</span></div>`,
              hw.memory              && `<div class="drawer-row"><span class="drawer-lbl">Memory</span><span class="drawer-val">${esc(hw.memory)}</span></div>`,
              hw.battery_health      && `<div class="drawer-row"><span class="drawer-lbl">Battery</span>
                <span class="drawer-val ${hw.battery_health==='Normal'?'good':'warn'}">${esc(hw.battery_health)}</span></div>`,
              net.ip_address         && `<div class="drawer-row"><span class="drawer-lbl">IP Address</span><span class="drawer-val mono">${esc(net.ip_address)}</span></div>`,
              net.mac_address        && `<div class="drawer-row"><span class="drawer-lbl">MAC Address</span><span class="drawer-val mono" style="font-size:11px">${esc(net.mac_address)}</span></div>`,
              agt.version            && `<div class="drawer-row"><span class="drawer-lbl">Agent Version</span><span class="drawer-val" style="color:#64748b">${esc(agt.version)}</span></div>`,
            ].filter(Boolean).join('');
            const el = document.getElementById('iruHardwareRows');
            if (el) el.innerHTML = rows || '<div style="color:#475569;font-size:12px;padding:8px 0">No hardware details available.</div>';
          })
          .catch(() => {
            const el = document.getElementById('iruHardwareRows');
            if (el) el.innerHTML = '<div style="color:#475569;font-size:12px;padding:8px 0">Could not load hardware details.</div>';
          });
      } else {
        const el = document.getElementById('iruHardwareRows');
        if (el) el.innerHTML = '';
      }
    }
  }

  function closeDeviceDrawer() {
    document.getElementById('drawerOverlay').classList.remove('open');
    document.getElementById('deviceDrawer').classList.remove('open');
  }

  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDeviceDrawer(); });

  function selectUser(id) {
    lookupSelectedId = id;
    // Refresh list highlight
    document.querySelectorAll('.user-row').forEach(r => r.classList.remove('selected'));
    document.querySelectorAll('.user-row').forEach(r => {
      if (r.getAttribute('onclick') === `selectUser('${id}')`) r.classList.add('selected');
    });

    const u = allUsersFlat.find(u => u.id === id);
    if (!u) return;

    // Fetch the raw Okta user for full profile attributes
    const okta = oktaUserMap[u.email] || {};
    const p    = okta.profile || {};

    // Manager name lookup
    const mgr = p.manager ? (oktaUserMap[p.manager.toLowerCase()] || null) : null;
    const mgrName = mgr
      ? `${mgr.profile?.firstName||''} ${mgr.profile?.lastName||''}`.trim()
      : null;
    const mgrDisplay = mgrName
      ? `${esc(mgrName)} <span style="color:#475569;font-size:12px">(${esc(p.manager)})</span>`
      : (p.manager ? esc(p.manager) : null);

    const color = avatarColor(u.name || u.email);
    const ini   = initials(u.name || u.email);

    const attr = (label, value, cls='') => value
      ? `<div class="attr-group"><div class="attr-label">${label}</div>
           <div class="attr-value ${cls}">${value}</div></div>`
      : `<div class="attr-group"><div class="attr-label">${label}</div>
           <div class="attr-value muted">—</div></div>`;

    const termDate = fmtHireDate(p.terminationDate || p.endDate || null);

    const deviceHTML = u.devices.length === 0
      ? `<div class="no-device-card">📵 No devices enrolled in Iru</div>`
      : u.devices.map(d => {
          const f = d.device_family || '';
          const icon = f === 'Mac' ? '💻' : f === 'iPhone' ? '📱' : f === 'iPad' ? '📟' : f === 'Windows' ? '🪟' : '🖥️';
          const ciClass = checkInClass(d.last_check_in);
          return `<div class="device-card" onclick="openDeviceDrawer(${d._idx})"
              style="cursor:pointer;transition:border-color .15s"
              onmouseover="this.style.borderColor='#0ea5e9'" onmouseout="this.style.borderColor='#2d3748'">
            <div class="device-card-icon">${icon}</div>
            <div class="device-card-info">
              <div class="device-card-name">${esc(d.device_name)}</div>
              <div class="device-card-model">${esc(d.model)}</div>
              <div class="device-card-meta">
                <span class="badge ${badgeClass(f)}">${esc(f)}</span>
                ${sourceBadge(d.source)}
                <span class="${ciClass}">Last seen: ${fmtRelative(d.last_check_in)}</span>
                <span style="color:#64748b">Enrolled: ${fmtDate(d.first_enrollment)}</span>
                ${kandjiLink(d)}
              </div>
            </div>
            <div style="color:#475569;font-size:12px;flex-shrink:0">›</div>
          </div>`;
        }).join('');

    document.getElementById('lookupRight').innerHTML = `
      <div class="profile-card">
        <div class="profile-header">
          <div class="profile-avatar" style="background:${color}">${ini}</div>
          <div style="flex:1">
            <div class="profile-name">${esc(u.name || '(no name)')}</div>
            <div class="profile-title">${esc(p.title || '—')}</div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              ${oktaStatusBadge(u.status)}
              ${p.employeeNumber ? `<span style="font-size:12px;color:#475569">ID: ${esc(p.employeeNumber)}</span>` : ''}
            </div>
          </div>
          <div style="text-align:right;font-size:12px;color:#475569">
            <div>Last login</div>
            <div style="color:#94a3b8;margin-top:3px">${fmtDate(okta.lastLogin)}</div>
          </div>
        </div>

        <div class="profile-body">
          ${attr('Email', esc(u.email))}
          ${attr('Department', esc(p.department))}
          ${attr('Sub-Department', esc(p.subDepartment))}
          ${attr('Title', esc(p.title))}
          ${attr('Manager', mgrDisplay)}
          ${attr('Hire Date', fmtHireDate(p.hireDate), 'highlight')}
          ${attr('Termination Date', termDate, 'danger')}
          ${attr('Mobile', esc(p.mobilePhone))}
        </div>

        <div class="profile-devices">
          <div class="profile-devices-title">Enrolled Devices (${u.devices.length})</div>
          ${deviceHTML}
        </div>
      </div>`;
  }

  // ── All-Users tab ────────────────────────────────────────────────────────
  function buildAllUsers() {
    const hasOkta = Object.keys(oktaUserMap).length > 0;
    document.getElementById('usersNoOkta').style.display  = hasOkta ? 'none'  : 'block';
    document.getElementById('usersContent').style.display = hasOkta ? 'block' : 'none';
    if (!hasOkta) return;

    // Build device-by-email lookup
    devicesByEmail = {};
    allDevicesFlat.forEach(d => {
      if (!d.user_email) return;
      const key = d.user_email.toLowerCase();
      if (!devicesByEmail[key]) devicesByEmail[key] = [];
      devicesByEmail[key].push(d);
    });

    // Normalise each Okta user
    const seen = new Set();
    allUsersFlat = [];
    Object.values(oktaUserMap).forEach(u => {
      if (seen.has(u.id)) return;
      seen.add(u.id);
      const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
      const devs  = devicesByEmail[email] || [];
      allUsersFlat.push({
        id:         u.id,
        name:       `${u.profile?.firstName || ''} ${u.profile?.lastName || ''}`.trim(),
        email:      email,
        department: u.profile?.department || '',
        title:      u.profile?.title || '',
        status:     u.status || '',
        lastLogin:  u.lastLogin || null,
        devices:    devs,
      });
    });

    // Populate status multi-select panel dynamically from actual data
    const statusOrder = ['ACTIVE','STAGED','PROVISIONED','RECOVERY','PASSWORD_EXPIRED','LOCKED_OUT','SUSPENDED','DEPROVISIONED'];
    const statusLabel = s => s.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
    const statuses = [...new Set(allUsersFlat.map(u => u.status).filter(Boolean))].sort(
      (a, b) => { const ai = statusOrder.indexOf(a), bi = statusOrder.indexOf(b); return (ai<0?99:ai) - (bi<0?99:bi); }
    );
    document.getElementById('usersStatusPanel').innerHTML =
      statuses.map(s => `<label class="ms-option"><input type="checkbox" value="${s}"
        onchange="msChanged('usersStatusFilter','All Statuses',filterUsers)"> ${statusLabel(s)}</label>`).join('') +
      `<button class="ms-clear" onclick="msClear('usersStatusFilter','All Statuses',filterUsers)">Clear</button>`;

    // Populate department multi-select panel
    const depts = [...new Set(allUsersFlat.map(u => u.department).filter(Boolean))].sort();
    document.getElementById('usersDeptPanel').innerHTML =
      depts.map(d => `<label class="ms-option"><input type="checkbox" value="${esc(d)}"
        onchange="msChanged('usersDeptFilter','All Departments',filterUsers)"> ${esc(d)}</label>`).join('') +
      `<button class="ms-clear" onclick="msClear('usersDeptFilter','All Departments',filterUsers)">Clear</button>`;

    document.getElementById('usersSearch').value = '';
    msClear('usersStatusFilter', 'All Statuses', null);
    msClear('usersDeviceFilter', 'All Users', null);
    msClear('usersDeptFilter', 'All Departments', null);
    lookupSelectedId = null;
    filterUsers();
  }

  function filterUsers() {
    const q        = document.getElementById('usersSearch').value.toLowerCase();
    const statusF  = msVals('usersStatusFilter');
    const devFilt  = msVals('usersDeviceFilter');
    const deptFilt = msVals('usersDeptFilter');

    const filtered = allUsersFlat.filter(u => {
      if (statusF.length  && !statusF.includes(u.status))       return false;
      if (deptFilt.length && !deptFilt.includes(u.department))  return false;
      if (devFilt.length) {
        const hasDevice = u.devices.length > 0;
        if (!devFilt.some(v => v === 'has_device' ? hasDevice : !hasDevice)) return false;
      }
      if (q && !(u.name+u.email+u.department+u.title).toLowerCase().includes(q)) return false;
      return true;
    }).sort((a,b) => a.name.localeCompare(b.name));

    const total = allUsersFlat.length;
    document.getElementById('usersCountLabel').textContent =
      filtered.length === total
        ? `${total.toLocaleString()} users`
        : `${filtered.length.toLocaleString()} of ${total.toLocaleString()} users`;

    const list = document.getElementById('userList');
    if (filtered.length === 0) {
      list.innerHTML = '<div class="no-results">No users found</div>';
      return;
    }
    list.innerHTML = filtered.map(u => {
      const color = avatarColor(u.name || u.email);
      const ini   = initials(u.name || u.email);
      const sel   = u.id === lookupSelectedId ? ' selected' : '';
      const devLine = u.devices.length > 0
        ? `<span style="font-size:11px;color:#64748b;margin-top:2px;display:block">${u.devices.length} device${u.devices.length !== 1 ? 's' : ''}</span>`
        : '';
      return `<div class="user-row${sel}" onclick="selectUser('${u.id}')">
        <div class="avatar" style="background:${color};width:36px;height:36px;font-size:13px;flex-shrink:0">${ini}</div>
        <div class="user-row-info">
          <div class="user-row-name">${esc(u.name || '(no name)')}</div>
          <div class="user-row-sub">${esc(u.email)}${u.department ? ' · '+esc(u.department) : ''}</div>
          ${devLine}
        </div>
        <div class="user-row-badge" style="flex-shrink:0">${oktaStatusBadge(u.status)}</div>
      </div>`;
    }).join('');
  }

  // ── CSV export helpers ───────────────────────────────────────────────────
  function csvEscape(v) {
    if (v == null) return '';
    const s = String(v);
    return s.includes(',') || s.includes('"') || s.includes('\\n')
      ? '"' + s.replace(/"/g, '""') + '"'
      : s;
  }

  function downloadCSV(filename, rows) {
    const blob = new Blob([rows.join('\\n')], {type:'text/csv;charset=utf-8;'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
  }

  function exportDevicesCSV() {
    // Get currently-filtered list by re-running filter logic
    const q        = document.getElementById('deviceSearch').value.toLowerCase();
    const typeF    = msVals('deviceTypeFilter');
    const sourceF  = msVals('deviceSourceFilter');
    const assignF  = msVals('deviceAssignFilter');
    const checkInF = msVals('deviceCheckInFilter');
    const now = Date.now();
    const rows = allDevicesFlat.filter(d => {
      if (typeF.length   && !typeF.includes(d.device_family))  return false;
      if (sourceF.length && !sourceF.includes(d.source))       return false;
      if (assignF.length) {
        const isAssigned = !!d.user_email;
        if (!assignF.some(v => v === 'assigned' ? isAssigned : !isAssigned)) return false;
      }
      if (checkInF.length) {
        const ts  = d.last_check_in ? new Date(d.last_check_in).getTime() : 0;
        const age = now - ts;
        const ok  = checkInF.some(v => {
          if (v === '1d')    return ts && age <= 86400000;
          if (v === '7d')    return ts && age <= 7*86400000;
          if (v === '30d')   return ts && age <= 30*86400000;
          if (v === 'stale') return !ts || age > 30*86400000;
          return false;
        });
        if (!ok) return false;
      }
      if (q && !(d.device_name+d.model+d.user_name+d.user_email+d.serial_number).toLowerCase().includes(q)) return false;
      return true;
    });
    const header = ['Device Name','Model','Type','Source','Serial Number','Assigned User','User Email','Last Check-in','Enrolled'];
    const lines  = [header.map(csvEscape).join(',')];
    rows.forEach(d => {
      lines.push([
        d.device_name, d.model, d.device_family, d.source,
        d.serial_number, d.user_name, d.user_email,
        d.last_check_in || '', d.first_enrollment || ''
      ].map(csvEscape).join(','));
    });
    downloadCSV('devices_export.csv', lines);
  }

  function exportUsersCSV() {
    // Re-use the same filter logic as filterUsers() to export the current view
    const q        = document.getElementById('usersSearch').value.toLowerCase();
    const statusF  = msVals('usersStatusFilter');
    const devFilt  = msVals('usersDeviceFilter');
    const deptFilt = msVals('usersDeptFilter');
    const rows = allUsersFlat.filter(u => {
      if (statusF.length  && !statusF.includes(u.status))       return false;
      if (deptFilt.length && !deptFilt.includes(u.department))  return false;
      if (devFilt.length) {
        const hasDevice = u.devices.length > 0;
        if (!devFilt.some(v => v === 'has_device' ? hasDevice : !hasDevice)) return false;
      }
      if (q && !(u.name+u.email+u.department+u.title).toLowerCase().includes(q)) return false;
      return true;
    }).sort((a,b) => a.name.localeCompare(b.name));
    const header = ['Name','Email','Department','Title','Okta Status','Last Login','Device Count','Primary Device','Primary Device Model','Primary Last Check-in'];
    const lines  = [header.map(csvEscape).join(',')];
    rows.forEach(u => {
      const dev = u.devices[0] || null;
      lines.push([
        u.name, u.email, u.department, u.title, u.status,
        u.lastLogin || '',
        u.devices.length,
        dev ? dev.device_name : '',
        dev ? dev.model : '',
        dev ? (dev.last_check_in || '') : ''
      ].map(csvEscape).join(','));
    });
    downloadCSV('users_export.csv', lines);
  }

  // ── Okta status helper ───────────────────────────────────────────────────
  function oktaStatusBadge(status) {
    const s = (status || '').toUpperCase();
    const cls = s === 'ACTIVE' ? 'status-active'
      : s === 'SUSPENDED' ? 'status-suspended'
      : s === 'DEPROVISIONED' ? 'status-deprovisioned'
      : (s === 'LOCKED_OUT' || s === 'PASSWORD_EXPIRED') ? 'status-locked'
      : 'status-other';
    return `<span class="badge ${cls}">${s || 'UNKNOWN'}</span>`;
  }

  // ── Render: Pending Returns tab ─────────────────────────────────────────
  async function renderOrphaned() {
    const hasOkta = Object.keys(oktaUserMap).length > 0;

    document.getElementById('orphanedNoOkta').style.display  = hasOkta ? 'none' : 'block';
    document.getElementById('orphanedBanner').style.display  = 'none';
    document.getElementById('orphanedEmpty').style.display   = 'none';
    document.getElementById('orphanedTable').style.display   = 'none';

    if (!hasOkta) return;

    const BAD = new Set(['SUSPENDED','DEPROVISIONED']);
    const orphaned = allDevicesFlat.filter(d => {
      if (!d.user_email) return false;
      const ou = oktaUserMap[d.user_email.toLowerCase()];
      return ou && BAD.has((ou.status || '').toUpperCase());
    });

    if (orphaned.length === 0) {
      document.getElementById('orphanedEmpty').style.display = 'block';
      return;
    }

    // Group devices by user
    const byUser = {};
    orphaned.forEach(d => {
      const email = d.user_email.toLowerCase();
      if (!byUser[email]) byUser[email] = { ou: oktaUserMap[email], devices: [] };
      byUser[email].devices.push(d);
    });

    const emails = Object.keys(byUser);

    // Count unique employees for banner
    document.getElementById('orphanedBanner').style.display = 'flex';
    document.getElementById('orphanedCount').textContent = emails.length + ' employee' + (emails.length !== 1 ? 's' : '');
    document.getElementById('orphanedTable').style.display = 'block';
    document.getElementById('orphanedBody').innerHTML = '<tr><td colspan="9" style="color:#64748b;padding:20px;text-align:center">Loading offboarding status…</td></tr>';

    // Fetch all offboarding records in parallel
    const records = await Promise.all(
      emails.map(e => fetch('/api/offboarding?email=' + encodeURIComponent(e)).then(r => r.json()).catch(() => ({})))
    );
    const obMap = {};
    emails.forEach((e, i) => obMap[e] = records[i] || {});

    // Status pill helpers
    function pill(done, doneLabel, undoneLabel, doneColors, undoneColors) {
      const [bg, fg] = done ? doneColors : undoneColors;
      return `<span style="display:inline-block;font-size:11px;font-weight:600;padding:3px 9px;border-radius:10px;background:${bg};color:${fg};white-space:nowrap">${done ? doneLabel : undoneLabel}</span>`;
    }
    const GREEN  = ['#14532d','#86efac'];
    const ORANGE = ['#431a1a','#fca5a5'];
    const AMBER  = ['#422006','#fcd34d'];

    document.getElementById('orphanedBody').innerHTML = emails.map(email => {
      const { ou, devices } = byUser[email];
      const rec  = obMap[email] || {};
      const name = ou ? `${ou.profile?.firstName || ''} ${ou.profile?.lastName || ''}`.trim() : email;
      const termDate = ou?.profile?.terminationDate || ou?.statusChanged;

      // Device cell — one line per device
      const deviceCell = devices.map(d => {
        const devRec  = rec?.devices?.[d.device_id] || {};
        const received = devRec.received || false;
        const badge = received
          ? `<span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:8px;background:#14532d;color:#86efac">✓ Received</span>`
          : `<span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:8px;background:#431a1a;color:#fca5a5">⏳ Pending</span>`;
        return `<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">
          <button class="link-device" style="font-size:12px" onclick="openDeviceDrawer(${d._idx})">${esc(d.device_name)}</button>
          ${kandjiLink(d)}
          ${badge}
        </div>
        <div style="font-size:11px;color:#64748b">${esc(d.model)} · S/N: ${esc(d.serial_number||'—')}</div>`;
      }).join('<div style="margin:6px 0;border-top:1px solid #1e293b"></div>');

      // Outbound box column
      let outboundCell;
      if (rec.outbound_tracking) {
        outboundCell = `${pill(true,'📦 Shipped','',GREEN,AMBER)}
          <div style="font-size:10px;color:#64748b;margin-top:3px;font-family:monospace">${esc(rec.outbound_tracking)}</div>`;
      } else if (rec.box_shipped) {
        outboundCell = pill(true,'📦 Shipped','',GREEN,AMBER);
      } else {
        outboundCell = pill(false,'','📭 Not Shipped',GREEN,ORANGE);
      }

      // Return status column
      let returnCell;
      const allReceived = devices.every(d => rec?.devices?.[d.device_id]?.received);
      if (rec.equipment_returned || allReceived) {
        returnCell = pill(true,'✓ Returned','',GREEN,AMBER);
      } else if (rec.return_tracking) {
        returnCell = `${pill(false,'','📬 In Transit',GREEN,AMBER)}
          <div style="font-size:10px;color:#64748b;margin-top:3px;font-family:monospace">${esc(rec.return_tracking)}</div>`;
      } else {
        returnCell = pill(false,'','⏳ Awaiting',GREEN,ORANGE);
      }

      return `<tr>
        <td>
          <div style="font-weight:500;font-size:13px">${esc(name)}</div>
          <div style="font-size:11px;color:#64748b;margin-top:2px">${esc(email)}</div>
        </td>
        <td>${deviceCell}</td>
        <td style="color:#f87171;font-size:13px;white-space:nowrap">${fmtDate(termDate)}</td>
        <td style="text-align:center">${oktaStatusBadge(ou?.status)}</td>
        <td style="text-align:center">${pill(rec.slack_deactivated,'✓','✗',GREEN,ORANGE)}</td>
        <td style="text-align:center">${pill(rec.google_deactivated,'✓','✗',GREEN,ORANGE)}</td>
        <td>${outboundCell}</td>
        <td>${returnCell}</td>
        <td><button class="btn btn-secondary" style="font-size:12px;padding:5px 12px;white-space:nowrap"
          onclick="openOffboardModal('${email}')">📋 Checklist</button></td>
      </tr>`;
    }).join('');
  }

  // ── Render: By Department tab ────────────────────────────────────────────
  function renderDepartments() {
    const hasOkta = Object.keys(oktaUserMap).length > 0;
    document.getElementById('deptNoOkta').style.display  = hasOkta ? 'none' : 'block';
    document.getElementById('deptContent').style.display = hasOkta ? 'block' : 'none';
    if (!hasOkta) return;

    // Build a device-lookup by email
    const devicesByEmail = {};
    allDevicesFlat.forEach(d => {
      if (!d.user_email) return;
      const key = d.user_email.toLowerCase();
      if (!devicesByEmail[key]) devicesByEmail[key] = [];
      devicesByEmail[key].push(d);
    });

    // Aggregate by department
    const depts = {};   // dept name → {users, activeUsers, devices, mac, windows, iphone, ipad, linux}
    const ACTIVE_STATUSES = new Set(['ACTIVE','RECOVERY','PASSWORD_EXPIRED','LOCKED_OUT']);

    Object.values(oktaUserMap).forEach(u => {
      const dept = u.profile?.department || 'No Department';
      if (!depts[dept]) depts[dept] = {users:0, activeUsers:0, devices:0, mac:0, windows:0, iphone:0, ipad:0, linux:0};
      depts[dept].users++;
      if (ACTIVE_STATUSES.has((u.status||'').toUpperCase())) depts[dept].activeUsers++;
      const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
      const devs = devicesByEmail[email] || [];
      depts[dept].devices += devs.length;
      devs.forEach(d => {
        const f = (d.device_family||'').toLowerCase();
        if (f==='mac')          depts[dept].mac++;
        else if (f==='windows') depts[dept].windows++;
        else if (f==='iphone')  depts[dept].iphone++;
        else if (f==='ipad')    depts[dept].ipad++;
        else if (f==='linux')   depts[dept].linux++;
      });
    });

    // Also count unassigned JumpCloud devices toward their source department (best-effort via device data)
    allDevicesFlat.forEach(d => {
      if (d.user_email) return; // already counted above
      if (d.source !== 'jumpcloud') return;
      // unassigned windows devices — add to a synthetic bucket so total device counts are accurate
    });

    const totalDevices = allDevicesFlat.length;
    const sorted = Object.entries(depts).sort((a,b) => b[1].devices - a[1].devices);
    const maxDevices = sorted[0]?.[1].devices || 1;

    // Summary cards
    const totalDepts = sorted.length;
    const deptWithDevices = sorted.filter(([,d]) => d.devices > 0).length;
    const usersNoDevice = Object.values(oktaUserMap).filter(u => {
      const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
      return ACTIVE_STATUSES.has((u.status||'').toUpperCase()) && !(devicesByEmail[email]?.length);
    });

    document.getElementById('deptSummaryCards').innerHTML = `
      <div class="card total"><div class="card-icon">🏢</div>
        <div class="card-label">Departments</div>
        <div class="card-count" style="color:#f38020">${totalDepts.toLocaleString()}</div></div>
      <div class="card mac"><div class="card-icon">👤</div>
        <div class="card-label">Active Users</div>
        <div class="card-count" style="color:#3b82f6">${Object.values(depts).reduce((s,d)=>s+d.activeUsers,0).toLocaleString()}</div></div>
      <div class="card iphone"><div class="card-icon">📵</div>
        <div class="card-label">Users w/o Device</div>
        <div class="card-count" style="color:#10b981">${usersNoDevice.length.toLocaleString()}</div></div>
      <div class="card ipad"><div class="card-icon">📊</div>
        <div class="card-label">Depts with Devices</div>
        <div class="card-count" style="color:#8b5cf6">${deptWithDevices.toLocaleString()}</div></div>
    `;

    // Department table
    document.getElementById('deptTable').innerHTML = sorted.map(([dept, d]) => `
      <tr>
        <td style="font-weight:500">${esc(dept)}</td>
        <td>${d.activeUsers.toLocaleString()}</td>
        <td style="font-weight:700">${d.devices.toLocaleString()}</td>
        <td style="color:#3b82f6">${d.mac || '—'}</td>
        <td style="color:#0ea5e9">${d.windows || '—'}</td>
        <td style="color:#10b981">${d.iphone || '—'}</td>
        <td style="color:#8b5cf6">${d.ipad || '—'}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div class="dept-bar" style="flex:1">
              <div class="dept-bar-fill" style="width:${Math.round(d.devices/maxDevices*100)}%"></div>
            </div>
            <span style="font-size:12px;color:#64748b;min-width:30px;text-align:right">
              ${totalDevices ? pct(d.devices,totalDevices) : 0}%
            </span>
          </div>
        </td>
      </tr>
    `).join('');

    // Users without device table
    document.getElementById('noDeviceTable').innerHTML = usersNoDevice
      .sort((a,b) => (a.profile?.department||'').localeCompare(b.profile?.department||''))
      .slice(0, 50)
      .map(u => `
        <tr>
          <td style="font-weight:500">${esc((u.profile?.firstName||'')+' '+(u.profile?.lastName||''))}</td>
          <td style="color:#64748b;font-size:13px">${esc(u.profile?.email || u.profile?.login || '—')}</td>
          <td>${esc(u.profile?.department || '—')}</td>
          <td style="color:#94a3b8">${esc(u.profile?.title || '—')}</td>
          <td>${oktaStatusBadge(u.status)}</td>
        </tr>
      `).join('') || '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:24px">All active users have at least one device enrolled.</td></tr>';
  }

  // ── Pie chart ────────────────────────────────────────────────────────────
  function drawPieChart(segments, grandTotal) {
    const cx = 130, cy = 130, r = 115, innerR = 68;
    const tau = 2 * Math.PI;
    let startAngle = -Math.PI / 2;
    const total = segments.reduce((s, seg) => s + seg.count, 0);

    const paths = segments.map(seg => {
      const fraction = seg.count / total;
      const sweep    = fraction * tau;
      const endAngle = startAngle + sweep;
      const large    = sweep > Math.PI ? 1 : 0;

      const cos1 = Math.cos(startAngle), sin1 = Math.sin(startAngle);
      const cos2 = Math.cos(endAngle),   sin2 = Math.sin(endAngle);

      const x1 = cx + r * cos1,       y1 = cy + r * sin1;
      const x2 = cx + r * cos2,       y2 = cy + r * sin2;
      const ix1 = cx + innerR * cos1, iy1 = cy + innerR * sin1;
      const ix2 = cx + innerR * cos2, iy2 = cy + innerR * sin2;

      const d = `M ${ix1.toFixed(2)} ${iy1.toFixed(2)} L ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)} L ${ix2.toFixed(2)} ${iy2.toFixed(2)} A ${innerR} ${innerR} 0 ${large} 0 ${ix1.toFixed(2)} ${iy1.toFixed(2)} Z`;

      startAngle = endAngle;
      return `<path class="pie-slice" d="${d}" fill="${seg.color}"
        onclick="openPieModal('${seg.label}')"
        onmouseover="document.getElementById('pieChartCenterNum').textContent='${seg.count.toLocaleString()}';document.getElementById('pieChartCenterLbl').textContent='${seg.label}'"
        onmouseout="document.getElementById('pieChartCenterNum').textContent='${grandTotal.toLocaleString()}';document.getElementById('pieChartCenterLbl').textContent='Total'"/>`;
    });

    document.getElementById('pieChartSvg').innerHTML = paths.join('');
    document.getElementById('pieChartCenterNum').textContent = grandTotal.toLocaleString();
    document.getElementById('pieChartCenterLbl').textContent = 'Total';

    // Legend
    document.getElementById('pieLegend').innerHTML = segments.map(seg => {
      const p = total ? Math.round(seg.count / total * 100) : 0;
      return `<div class="pie-legend-item" onclick="openPieModal('${seg.label}')">
        <div class="pie-legend-dot" style="background:${seg.color}"></div>
        <span style="font-size:16px;flex-shrink:0">${seg.icon}</span>
        <span class="pie-legend-label">${seg.label}</span>
        <span class="pie-legend-count">${seg.count.toLocaleString()}</span>
        <span class="pie-legend-pct">${p}%</span>
      </div>`;
    }).join('');
  }

  function openPieModal(label) {
    const ACTIVE = new Set(['ACTIVE','RECOVERY','PASSWORD_EXPIRED','LOCKED_OUT']);
    const colors = {Mac:'#3b82f6',Windows:'#0ea5e9',iPhone:'#10b981',iPad:'#8b5cf6','No Device':'#475569',Other:'#f59e0b'};
    const color  = colors[label] || '#64748b';
    let rows = [];

    if (label === 'No Device') {
      // Active Okta users with no device
      rows = Object.values(oktaUserMap)
        .filter(u => {
          const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
          return ACTIVE.has((u.status||'').toUpperCase()) &&
                 !allDevicesFlat.some(d => d.user_email === email);
        })
        .map(u => {
          const email = (u.profile?.email || u.profile?.login || '').toLowerCase();
          const name  = `${u.profile?.firstName||''} ${u.profile?.lastName||''}`.trim();
          const dept  = u.profile?.department || '';
          return {id:u.id, email, name, dept, status:u.status, deviceSub:'No devices enrolled'};
        })
        .sort((a,b) => a.name.localeCompare(b.name));
    } else {
      // Users who have at least one device of this type
      const seen = new Set();
      allUsersFlat.forEach(u => {
        const hasType = u.devices.some(d => d.device_family === label);
        if (!hasType) return;
        if (seen.has(u.id)) return;
        seen.add(u.id);
        const devNames = u.devices.filter(d => d.device_family === label).map(d => d.device_name).join(', ');
        rows.push({id:u.id, email:u.email, name:u.name||'(no name)', dept:u.department, status:u.status,
          deviceSub:devNames || label});
      });
      // Also include unassigned devices (no user) in the count display but no user rows
      rows.sort((a,b) => a.name.localeCompare(b.name));
    }

    const unassigned = label !== 'No Device'
      ? allDevicesFlat.filter(d => d.device_family === label && !d.user_email).length : 0;

    document.getElementById('pieModalDot').style.background = color;
    document.getElementById('pieModalTitle').textContent = label + ' Users';
    document.getElementById('pieModalCount').textContent =
      rows.length.toLocaleString() + ' user' + (rows.length !== 1 ? 's' : '') +
      (unassigned ? ` · ${unassigned} unassigned device${unassigned!==1?'s':''}` : '');

    const hasOkta = Object.keys(oktaUserMap).length > 0;
    document.getElementById('pieModalBody').innerHTML = rows.length === 0
      ? `<div style="text-align:center;padding:40px;color:#64748b">
           ${hasOkta ? 'No users found in this category.' : 'Connect Okta to see users per category.'}</div>`
      : rows.map(u => {
          const c   = avatarColor(u.name || u.email);
          const ini = initials(u.name || u.email);
          const deptStr = u.dept ? ` · ${esc(u.dept)}` : '';
          return `<div class="pie-modal-row" onclick="closePieModal();goToUser('${u.email}')">
            <div class="avatar" style="background:${c};width:36px;height:36px;font-size:13px;flex-shrink:0">${ini}</div>
            <div class="pie-modal-row-info">
              <div class="pie-modal-row-name">${esc(u.name)}</div>
              <div class="pie-modal-row-sub">${esc(u.email)}${deptStr}</div>
            </div>
            ${oktaStatusBadge(u.status)}
          </div>`;
        }).join('');

    document.getElementById('pieModalOverlay').classList.add('open');
  }

  function closePieModal() {
    document.getElementById('pieModalOverlay').classList.remove('open');
  }

  // ── Offboarding Checklist ─────────────────────────────────────────────────
  function obCheck(icon, label, checked, id, email, field) {
    const bg = checked ? '#14532d' : '#1e293b';
    const ic = checked ? '✅' : '⬜';
    return `<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:${bg};border-radius:8px;cursor:pointer"
      onclick="document.getElementById('${id}').click()">
      <input type="checkbox" id="${id}" ${checked ? 'checked' : ''}
        onchange="saveOffboardField('${email}','${field}',this.checked);this.closest('div').style.background=this.checked?'#14532d':'#1e293b'"
        style="width:16px;height:16px;cursor:pointer;accent-color:#22c55e">
      <span style="font-size:15px">${icon}</span>
      <span style="font-size:13px;font-weight:500">${label}</span>
    </div>`;
  }

  async function openOffboardModal(email) {
    const modal   = document.getElementById('offboardModal');
    const content = document.getElementById('offboardContent');
    modal.style.display = 'flex';
    content.innerHTML = '<div style="color:#64748b;padding:20px">Loading...</div>';

    const ou          = oktaUserMap[email.toLowerCase()];
    const userDevices = allDevicesFlat.filter(d => d.user_email === email.toLowerCase());
    const rec         = await fetch(`/api/offboarding?email=${encodeURIComponent(email)}`).then(r => r.json()).catch(() => ({}));

    const name       = ou ? `${ou.profile?.firstName || ''} ${ou.profile?.lastName || ''}`.trim() : email;
    const oktaStatus = ou?.status || 'UNKNOWN';
    const oktaOk     = oktaStatus === 'DEPROVISIONED';
    const termDate   = ou?.profile?.terminationDate || ou?.statusChanged || null;

    const sectionHead = label => `<div style="font-size:11px;font-weight:600;color:#475569;text-transform:uppercase;letter-spacing:.07em;margin:20px 0 8px">${label}</div>`;

    content.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:4px">
        <div>
          <div style="font-size:18px;font-weight:600">${esc(name)}</div>
          <div style="color:#64748b;font-size:13px">${esc(email)}</div>
          ${termDate ? `<div style="color:#94a3b8;font-size:12px;margin-top:2px">Term date: ${fmtDate(termDate)}</div>` : ''}
        </div>
        <button onclick="closeOffboardModal()" style="background:none;border:none;color:#64748b;font-size:20px;cursor:pointer;padding:0">✕</button>
      </div>

      ${sectionHead('Account Deactivations')}
      <div style="display:flex;flex-direction:column;gap:6px">
        <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:${oktaOk ? '#14532d' : '#431a1a'};border-radius:8px">
          <span style="font-size:18px">${oktaOk ? '✅' : '⚠️'}</span>
          <span style="font-size:15px">🔑</span>
          <div>
            <div style="font-size:13px;font-weight:500">Okta deprovisioned</div>
            <div style="font-size:11px;color:#94a3b8">Status: ${oktaStatus}</div>
          </div>
        </div>
        ${obCheck('💬', 'Slack deactivated',           rec.slack_deactivated   || false, 'ob_slack',   email, 'slack_deactivated')}
        ${obCheck('📧', 'Google Workspace deactivated', rec.google_deactivated  || false, 'ob_google',  email, 'google_deactivated')}
      </div>

      ${sectionHead('Device Return')}
      <div style="display:flex;flex-direction:column;gap:6px">
        ${userDevices.length === 0
          ? `<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:#14532d;border-radius:8px">
               <span style="font-size:18px">✅</span><span style="font-size:13px">No devices enrolled in MDM</span></div>`
          : userDevices.map(d => {
              const devRec   = rec?.devices?.[d.device_id] || {};
              const received = devRec.received || false;
              return `<div style="padding:10px 12px;background:${received ? '#14532d' : '#1e293b'};border-radius:8px;cursor:pointer"
                onclick="document.getElementById('recv_${d.device_id}').click()">
                <div style="display:flex;align-items:center;gap:10px">
                  <input type="checkbox" id="recv_${d.device_id}" ${received ? 'checked' : ''}
                    onchange="saveDeviceReceived('${email}','${d.device_id}',this.checked);this.closest('div[style]').style.background=this.checked?'#14532d':'#1e293b'"
                    style="width:16px;height:16px;cursor:pointer;accent-color:#22c55e">
                  <span style="font-size:15px">💻</span>
                  <div style="flex:1">
                    <div style="font-size:13px;font-weight:500">${esc(d.device_name)} ${kandjiLink(d)}</div>
                    <div style="font-size:12px;color:#94a3b8">${esc(d.model)} · S/N: ${esc(d.serial_number||'—')}</div>
                  </div>
                  <span id="recvBadge_${d.device_id}" style="font-size:11px;font-weight:600;padding:3px 10px;border-radius:12px;white-space:nowrap;${received ? 'background:#14532d;color:#86efac' : 'background:#431a1a;color:#fca5a5'}">${received ? '✓ Received' : '⏳ Pending'}</span>
                </div>
                ${received && devRec.received_at ? `<div style="font-size:11px;color:#64748b;margin-top:4px;padding-left:26px">Received: ${devRec.received_at.slice(0,10)}</div>` : ''}
              </div>`;
            }).join('')}
      </div>

      ${sectionHead('Shipping')}
      <div style="display:flex;flex-direction:column;gap:10px">
        <div style="background:#1e293b;border-radius:8px;padding:12px">
          ${obCheck('📦', 'Empty return box shipped to employee', rec.box_shipped || false, 'ob_box', email, 'box_shipped')}
          <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
            <input type="text" id="outboundTracking" value="${esc(rec.outbound_tracking||'')}"
              placeholder="Outbound FedEx tracking #"
              onblur="saveOffboardField('${email}','outbound_tracking',this.value)"
              style="flex:1;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#f1f5f9;font-size:13px">
            <button class="btn btn-secondary" style="font-size:12px;padding:6px 12px;white-space:nowrap"
              onclick="saveOffboardField('${email}','outbound_tracking',document.getElementById('outboundTracking').value);trackFedEx('outboundTracking','outboundStatus')">Track</button>
          </div>
          <div id="outboundStatus" style="font-size:12px;color:#94a3b8;margin-top:6px;min-height:16px"></div>
        </div>

        <div style="background:#1e293b;border-radius:8px;padding:12px">
          ${obCheck('📬', 'Equipment returned by employee', rec.equipment_returned || false, 'ob_return', email, 'equipment_returned')}
          <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
            <input type="text" id="returnTracking" value="${esc(rec.return_tracking||'')}"
              placeholder="Return FedEx tracking #"
              onblur="saveOffboardField('${email}','return_tracking',this.value)"
              style="flex:1;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:7px 10px;color:#f1f5f9;font-size:13px">
            <button class="btn btn-secondary" style="font-size:12px;padding:6px 12px;white-space:nowrap"
              onclick="saveOffboardField('${email}','return_tracking',document.getElementById('returnTracking').value);trackFedEx('returnTracking','returnStatus')">Track</button>
          </div>
          <div id="returnStatus" style="font-size:12px;color:#94a3b8;margin-top:6px;min-height:16px"></div>
        </div>
      </div>

      ${sectionHead('Notes')}
      <textarea id="offboardNotes" rows="3" placeholder="e.g. Contacted employee on 5/10, device shipped via FedEx..."
        style="width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:10px;color:#f1f5f9;font-size:13px;resize:vertical"
      >${esc(rec?.notes || '')}</textarea>
      <div style="display:flex;align-items:center;gap:10px;margin-top:10px">
        <button class="btn" onclick="saveOffboardAll('${email}')"
          style="background:#3b82f6;color:#fff;padding:8px 18px;font-size:13px">Save</button>
        <span id="offboardSaveMsg" style="font-size:13px;color:#22c55e"></span>
      </div>`;

    // Auto-fetch FedEx status if tracking numbers are already saved
    if (rec.outbound_tracking) trackFedEx('outboundTracking', 'outboundStatus');
    if (rec.return_tracking)   trackFedEx('returnTracking',   'returnStatus');
  }

  function closeOffboardModal() {
    document.getElementById('offboardModal').style.display = 'none';
  }

  async function saveDeviceReceived(email, deviceId, received) {
    await fetch('/api/offboarding/update', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({email, device_id: deviceId, device_received: received})
    });
    // Refresh the badge
    const badge = document.getElementById(`recvBadge_${deviceId}`);
    if (badge) {
      badge.textContent = received ? '✓ Received' : '⏳ Pending';
      badge.style.background = received ? '#14532d' : '#431a1a';
      badge.style.color = received ? '#86efac' : '#fca5a5';
    }
  }

  async function saveOffboardAll(email) {
    const btn = document.querySelector('#offboardContent .btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      // Collect all current field values in one payload
      const payload = {
        email,
        notes:             (document.getElementById('offboardNotes')    || {}).value || '',
        outbound_tracking: (document.getElementById('outboundTracking') || {}).value?.trim() || '',
        return_tracking:   (document.getElementById('returnTracking')   || {}).value?.trim() || '',
      };
      const res  = await fetch('/api/offboarding/update', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.ok) {
        if (btn) { btn.textContent = '✓ Saved'; btn.style.background = '#22c55e'; }
        setTimeout(() => closeOffboardModal(), 800);
      } else {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; btn.style.background = ''; }
        alert(data.error || 'Error saving.');
      }
    } catch(e) {
      if (btn) { btn.disabled = false; btn.textContent = 'Save'; btn.style.background = ''; }
      alert('Network error: ' + e.message);
    }
  }

  async function saveOffboardField(email, field, value) {
    try {
      await fetch('/api/offboarding/update', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({email, [field]: value})
      });
    } catch(e) {
      console.warn('saveOffboardField error:', e);
    }
  }

  async function trackFedEx(inputId, statusId) {
    const tracking = document.getElementById(inputId).value.trim();
    const statusEl = document.getElementById(statusId);
    if (!tracking) { statusEl.textContent = 'Enter a tracking number first.'; return; }
    statusEl.style.color = '#94a3b8';
    statusEl.textContent = 'Looking up…';
    try {
      const res  = await fetch('/api/fedex-track?tracking=' + encodeURIComponent(tracking));
      const data = await res.json();
      if (data.ok) {
        statusEl.style.color = '#22c55e';
        statusEl.textContent = data.statusByLocale || data.status || 'Status unknown';
      } else {
        statusEl.style.color = '#f87171';
        statusEl.textContent = data.error || 'Error fetching status';
      }
    } catch(e) {
      statusEl.style.color = '#f87171';
      statusEl.textContent = 'Network error: ' + e.message;
    }
  }

  // Boot
  fetchAll();
  startCachePolling();

  // ── Admin Tab ─────────────────────────────────────────────────────────────
  async function loadAdminTab() {
    const wrap = document.getElementById('adminUsersWrap');
    wrap.innerHTML = '<div style="color:#64748b;padding:20px">Loading...</div>';
    try {
      const res  = await fetch('/api/admin/users');
      const users = await res.json();
      if (!users.length) {
        wrap.innerHTML = '<div style="color:#64748b;padding:20px">No users found.</div>';
        return;
      }
      wrap.innerHTML = `
        <table class="data-table" style="width:100%;max-width:600px">
          <thead><tr>
            <th>Username</th>
            <th>Created</th>
            <th style="width:220px">Actions</th>
          </tr></thead>
          <tbody>
          ${users.map(u => `
            <tr>
              <td style="font-weight:500">${esc(u.username)}${u.is_me ? ' <span style="font-size:11px;color:#64748b">(you)</span>' : ''}</td>
              <td style="color:#64748b;font-size:13px">${u.created_at ? u.created_at.slice(0,10) : '—'}</td>
              <td style="display:flex;gap:6px">
                <button class="btn btn-secondary" style="font-size:12px;padding:4px 10px"
                  onclick="adminChangePass('${esc(u.username)}')">Change Password</button>
                ${u.is_me ? '' : `<button class="btn" style="font-size:12px;padding:4px 10px;background:#ef4444;color:#fff"
                  onclick="adminDeleteUser('${esc(u.username)}')">Remove</button>`}
              </td>
            </tr>`).join('')}
          </tbody>
        </table>`;
    } catch(e) {
      wrap.innerHTML = `<div style="color:#f87171">Error: ${e.message}</div>`;
    }
  }

  async function adminAddUser() {
    const username = document.getElementById('adminNewUser').value.trim();
    const password = document.getElementById('adminNewPass').value.trim();
    const msg = document.getElementById('adminMsg');
    msg.textContent = '';
    if (!username || !password) { msg.style.color='#f87171'; msg.textContent='Username and password are required.'; return; }
    if (password.length < 8)    { msg.style.color='#f87171'; msg.textContent='Password must be at least 8 characters.'; return; }
    const res  = await fetch('/api/admin/users/add', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, password})});
    const data = await res.json();
    if (data.ok) {
      msg.style.color='#22c55e'; msg.textContent=`User '${username}' added.`;
      document.getElementById('adminNewUser').value = '';
      document.getElementById('adminNewPass').value = '';
      loadAdminTab();
    } else {
      msg.style.color='#f87171'; msg.textContent = data.error || 'Error adding user.';
    }
  }

  async function adminDeleteUser(username) {
    if (!confirm(`Remove user '${username}'? They will no longer be able to log in.`)) return;
    const res  = await fetch('/api/admin/users/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username})});
    const data = await res.json();
    if (data.ok) { loadAdminTab(); }
    else { alert(data.error || 'Error removing user.'); }
  }

  async function adminChangePass(username) {
    const newPass = prompt(`New password for '${username}' (min 8 characters):`);
    if (!newPass) return;
    if (newPass.length < 8) { alert('Password must be at least 8 characters.'); return; }
    const res  = await fetch('/api/admin/users/password', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, password: newPass})});
    const data = await res.json();
    if (data.ok) { alert(`Password updated for '${username}'.`); }
    else { alert(data.error || 'Error updating password.'); }
  }
</script>

<!-- ── Offboarding Checklist Modal ── -->
<div id="offboardModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;align-items:center;justify-content:center;padding:20px">
  <div style="background:#1e293b;border-radius:12px;padding:28px;width:100%;max-width:580px;max-height:85vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.5)">
    <div id="offboardContent"></div>
  </div>
</div>

<!-- ── Admin Tab Panel ── -->
<div class="tab-panel" id="tab-admin" style="display:none;padding:32px 24px;max-width:800px;margin:0 auto">
  <h2 style="font-size:18px;font-weight:600;margin:0 0 6px">Dashboard Users</h2>
  <p style="color:#64748b;font-size:13px;margin:0 0 24px">Manage who can log in to this dashboard.</p>

  <div id="adminUsersWrap" style="margin-bottom:32px"></div>

  <div style="background:#1e293b;border-radius:10px;padding:20px;max-width:500px">
    <div style="font-size:14px;font-weight:600;margin-bottom:14px">Add New User</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
      <div>
        <label style="font-size:12px;color:#94a3b8;display:block;margin-bottom:4px">Username</label>
        <input type="text" id="adminNewUser" placeholder="e.g. jane"
          style="width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 10px;color:#f1f5f9;font-size:14px">
      </div>
      <div>
        <label style="font-size:12px;color:#94a3b8;display:block;margin-bottom:4px">Password</label>
        <input type="password" id="adminNewPass" placeholder="Min 8 characters"
          style="width:100%;box-sizing:border-box;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 10px;color:#f1f5f9;font-size:14px">
      </div>
    </div>
    <button class="btn" onclick="adminAddUser()" style="background:#3b82f6;color:#fff;padding:8px 18px;font-size:13px">Add User</button>
    <div id="adminMsg" style="margin-top:8px;font-size:13px;min-height:18px"></div>
  </div>
</div>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class DashboardHandler(BaseHTTPRequestHandler):
    config = None

    def log_message(self, fmt, *args):
        pass  # suppress default noise

    # ── Auth helpers ──────────────────────────────────────────────────────────
    def _get_cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == name:
                return v.strip()
        return None

    def _redirect(self, location, clear_session=False):
        self.send_response(302)
        self.send_header("Location", location)
        if clear_session:
            self.send_header("Set-Cookie", "session=; Path=/; HttpOnly; Max-Age=0")
        self.end_headers()

    def _set_session_cookie(self, token):
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
        )
        self.end_headers()

    def _require_auth(self):
        """Return True (and send redirect) if request is NOT authenticated."""
        token = self._get_cookie("session")
        if not _valid_session(token):
            self._redirect("/login")
            return True
        return False

    def do_GET(self):
        # ── Public routes (no auth needed) ───────────────────────────────────
        if self.path in ("/login", "/login.html"):
            self._html_response(LOGIN_HTML)
            return

        if self.path == "/auth/logout":
            token = self._get_cookie("session")
            if token:
                with _sessions_lock:
                    _sessions.pop(token, None)
            self._redirect("/login", clear_session=True)
            return

        # ── All other routes require auth ─────────────────────────────────────
        if self._require_auth():
            return

        if self.path in ("/", "/index.html"):
            page = HTML
            if CLOUD_MODE:
                # Hide local-only controls in cloud deployment
                for btn_id in ("settingsBtn", "restartBtn", "stopBtn"):
                    page = page.replace(f'id="{btn_id}"', f'id="{btn_id}" style="display:none"')
            self._html_response(page)

        elif self.path == "/api/devices":
            cfg = DashboardHandler.config
            if not cfg:
                self._text_error(503, "No config found. Open ⚙ Settings in the dashboard.")
                return
            data, _ = _cache_get("devices")
            if data is None:
                # First load — fetch synchronously so the page has something to show
                try:
                    data = fetch_all_devices(cfg["subdomain"], cfg["token"], cfg.get("region", "us"))
                    _cache_set("devices", data)
                except urllib.error.HTTPError as e:
                    body = e.read().decode(errors="replace")
                    self._text_error(e.code, f"Iru API returned {e.code} {e.reason}: {body[:300]}")
                    return
                except Exception as e:
                    self._text_error(500, str(e))
                    return
            self._json_response(data)

        elif self.path.startswith("/api/okta-debug"):
            # e.g. /api/okta-debug?email=ni.chin@hungryroot.com
            cfg = DashboardHandler.config
            if not cfg or not cfg.get("okta_domain") or not cfg.get("okta_token"):
                self._text_error(503, "Okta not configured.")
                return
            import urllib.parse as _uparse
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            email = qs.get("email", [""])[0]
            try:
                search = _uparse.quote(f'profile.email eq "{email}" OR profile.login eq "{email}"')
                url = f"https://{cfg['okta_domain']}/api/v1/users?search={search}&limit=5"
                req = urllib.request.Request(url, headers={
                    "Authorization": f"SSWS {cfg['okta_token']}", "Accept": "application/json"
                })
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                self._json_response(data)
            except Exception as e:
                self._text_error(500, str(e))

        elif self.path == "/api/okta-users":
            cfg = DashboardHandler.config
            if not cfg or not cfg.get("okta_domain") or not cfg.get("okta_token"):
                self._json_response([])
                return
            data, _ = _cache_get("okta_users")
            if data is None:
                try:
                    data = fetch_all_okta_users(cfg["okta_domain"], cfg["okta_token"])
                    _cache_set("okta_users", data)
                except Exception as e:
                    self._text_error(500, str(e))
                    return
            self._json_response(data)

        elif self.path == "/api/jumpcloud-devices":
            cfg = DashboardHandler.config
            if not cfg or not cfg.get("jumpcloud_api_key"):
                self._json_response([])
                return
            data, _ = _cache_get("jc_devices")
            if data is None:
                try:
                    data = fetch_jumpcloud_devices(cfg["jumpcloud_api_key"])
                    _cache_set("jc_devices", data)
                except Exception as e:
                    print(f"[JumpCloud ERROR] {e}")
                    self._text_error(500, str(e))
                    return
            self._json_response(data)

        elif self.path == "/api/cache-status":
            now = time.time()
            def age_secs(key):
                _, ts = _cache_get(key)
                return int(now - ts) if ts else None
            self._json_response({
                "refreshing": _refresh_busy.is_set(),
                "ages": {
                    "devices":    age_secs("devices"),
                    "okta_users": age_secs("okta_users"),
                    "jc_devices": age_secs("jc_devices"),
                },
                "ttl": CACHE_TTL,
            })

        elif self.path == "/api/force-refresh":
            # Kick off an immediate background refresh and return straight away
            _refresh_flag.set()
            self._json_response({"ok": True, "refreshing": True})

        elif self.path.startswith("/api/iru-device-details"):
            cfg = DashboardHandler.config
            if not cfg:
                self._text_error(503, "No config.")
                return
            import urllib.parse as _uparse
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            device_id = qs.get("id", [""])[0]
            if not device_id:
                self._text_error(400, "Missing id")
                return
            try:
                details = fetch_iru_device_details(
                    cfg["subdomain"], cfg["token"], cfg.get("region", "us"), device_id
                )
                self._json_response(details)
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                self._text_error(e.code, f"Iru API {e.code}: {body[:300]}")
            except Exception as e:
                self._text_error(500, str(e))

        elif self.path == "/api/meta":
            cfg = DashboardHandler.config
            self._json_response({
                "subdomain": cfg.get("subdomain", "") if cfg else "",
                "region":    cfg.get("region", "us") if cfg else "us",
            })

        elif self.path.startswith("/api/fedex-track"):
            from urllib.parse import urlparse, parse_qs
            qs       = parse_qs(urlparse(self.path).query)
            tracking = qs.get("tracking", [""])[0].strip()
            if not tracking:
                self._json_response({"ok": False, "error": "tracking number required"})
                return
            cfg = DashboardHandler.config or {}
            cid  = os.environ.get("FEDEX_CLIENT_ID",     cfg.get("fedex_client_id",     ""))
            csec = os.environ.get("FEDEX_CLIENT_SECRET",  cfg.get("fedex_client_secret",  ""))
            if not cid or not csec:
                self._json_response({"ok": False, "error": "FedEx credentials not configured. Add FEDEX_CLIENT_ID and FEDEX_CLIENT_SECRET in Settings."})
                return
            try:
                result = _track_fedex(tracking, cid, csec)
                track_results = result.get("output", {}).get("completeTrackResults", [])
                if not track_results:
                    self._json_response({"ok": False, "error": "No results found for that tracking number."})
                    return
                info   = track_results[0].get("trackResults", [{}])[0]
                status = info.get("latestStatusDetail", {})
                self._json_response({
                    "ok":             True,
                    "status":         status.get("description", ""),
                    "statusByLocale": status.get("statusByLocale", ""),
                    "code":           status.get("code", ""),
                })
            except urllib.error.HTTPError as e:
                body = e.read().decode(errors="replace")
                self._json_response({"ok": False, "error": f"FedEx API error {e.code}: {body[:200]}"})
            except Exception as e:
                self._json_response({"ok": False, "error": str(e)})

        elif self.path.startswith("/api/offboarding"):
            from urllib.parse import urlparse, parse_qs
            qs  = parse_qs(urlparse(self.path).query)
            email = qs.get("email", [""])[0].lower().strip()
            data = _load_offboarding()
            self._json_response(data.get(email, {}))

        elif self.path == "/api/admin/users":
            token = self._get_cookie("session")
            me = _get_session_username(token)
            users = _load_users()
            self._json_response([
                {"username": u["username"], "created_at": u.get("created_at",""), "is_me": u["username"] == me}
                for u in users
            ])

        else:
            self.send_error(404)

    def do_POST(self):
        # ── Login form submission ─────────────────────────────────────────────
        if self.path == "/auth/login":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode()
            params = {}
            for part in body.split("&"):
                k, _, v = part.partition("=")
                params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
            username = params.get("username", "")
            password = params.get("password", "")
            if _check_credentials(username, password):
                token = _create_session(username)
                # Kick off a background refresh so the dashboard shows fresh data
                _refresh_flag.set()
                self._set_session_cookie(token)
            else:
                self._redirect("/login?error=1")
            return

        # All other POST routes require auth
        if self._require_auth():
            return

        if self.path == "/api/okta-lookup":
            cfg = DashboardHandler.config
            if not cfg or not cfg.get("okta_domain") or not cfg.get("okta_token"):
                self._json_response([])
                return
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            emails = [e.lower().strip() for e in body.get("emails", []) if e]
            try:
                users = fetch_okta_users_by_emails(cfg["okta_domain"], cfg["okta_token"], emails)
                self._json_response(users)
            except urllib.error.HTTPError as e:
                self._text_error(e.code, e.read().decode(errors="replace")[:300])
            except Exception as e:
                self._text_error(500, str(e))

        elif self.path == "/api/save-config":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            try:
                cfg = save_config(
                    body["subdomain"], body["token"], body.get("region", "us"),
                    body.get("okta_domain", ""), body.get("okta_token", ""),
                    body.get("jumpcloud_api_key", ""),
                    body.get("dashboard_user", ""), body.get("dashboard_pass", ""),
                    body.get("fedex_client_id", ""), body.get("fedex_client_secret", ""),
                )
                DashboardHandler.config = cfg
                self._json_response({"ok": True})
            except Exception as e:
                self._json_response({"ok": False, "error": str(e)})
        elif self.path == "/api/restart":
            # Send response first, then restart the process after a short delay
            self._json_response({"ok": True, "msg": "Restarting..."})
            def _do_restart():
                import time, os
                time.sleep(0.4)
                os.execv(sys.executable, [sys.executable] + sys.argv)
            Timer(0.1, _do_restart).start()

        elif self.path == "/api/stop":
            self._json_response({"ok": True, "msg": "Stopping..."})
            def _do_stop():
                import time, os
                time.sleep(0.4)
                print("\n🛑 Server stopped via dashboard button.")
                os._exit(0)
            Timer(0.1, _do_stop).start()

        elif self.path == "/api/offboarding/update":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            email  = body.get("email", "").lower().strip()
            if not email:
                self._json_response({"ok": False, "error": "email required"})
                return
            data = _load_offboarding()
            if email not in data:
                data[email] = {
                    "initiated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "notes": "", "devices": {}
                }
            rec = data[email]
            # Simple boolean / string fields
            for field in ("notes", "slack_deactivated", "google_deactivated",
                          "box_shipped", "outbound_tracking", "return_tracking"):
                if field in body:
                    rec[field] = body[field]
            # Per-device received flag
            if "device_received" in body:
                dev_id = body.get("device_id", "")
                if dev_id:
                    rec.setdefault("devices", {})[dev_id] = {
                        "received":    body["device_received"],
                        "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                                       if body["device_received"] else None,
                    }
            _save_offboarding(data)
            _sheets_sync_bg(email, data[email], DashboardHandler.config or {})
            self._json_response({"ok": True})

        elif self.path == "/api/admin/users/add":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            new_user = body.get("username", "").strip()
            new_pass = body.get("password", "").strip()
            if not new_user or not new_pass:
                self._json_response({"ok": False, "error": "Username and password are required."})
                return
            if len(new_pass) < 8:
                self._json_response({"ok": False, "error": "Password must be at least 8 characters."})
                return
            users = _load_users()
            if any(u["username"] == new_user for u in users):
                self._json_response({"ok": False, "error": f"User '{new_user}' already exists."})
                return
            users.append({
                "username":     new_user,
                "password_hash": _hash_password(new_pass),
                "created_at":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            _save_users(users)
            self._json_response({"ok": True})

        elif self.path == "/api/admin/users/delete":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            target = body.get("username", "").strip()
            token  = self._get_cookie("session")
            me     = _get_session_username(token)
            if target == me:
                self._json_response({"ok": False, "error": "You cannot delete your own account."})
                return
            users = _load_users()
            updated = [u for u in users if u["username"] != target]
            if len(updated) == len(users):
                self._json_response({"ok": False, "error": "User not found."})
                return
            if len(updated) == 0:
                self._json_response({"ok": False, "error": "Cannot delete the last user."})
                return
            _save_users(updated)
            self._json_response({"ok": True})

        elif self.path == "/api/admin/users/password":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            target   = body.get("username", "").strip()
            new_pass = body.get("password", "").strip()
            if len(new_pass) < 8:
                self._json_response({"ok": False, "error": "Password must be at least 8 characters."})
                return
            users = _load_users()
            found = False
            for u in users:
                if u["username"] == target:
                    u["password_hash"] = _hash_password(new_pass)
                    found = True
                    break
            if not found:
                self._json_response({"ok": False, "error": "User not found."})
                return
            _save_users(users)
            self._json_response({"ok": True})

        else:
            self.send_error(404)

    # Helpers
    def _html_response(self, html):
        encoded = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(encoded))
        self.end_headers()
        self.wfile.write(encoded)

    def _json_response(self, data):
        encoded = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(encoded))
        self.end_headers()
        self.wfile.write(encoded)

    def _text_error(self, code, msg):
        encoded = msg.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(encoded))
        self.end_headers()
        self.wfile.write(encoded)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _gui_prompt(prompt_text, hidden=False):
    """Show a native macOS dialog for input — used when there is no terminal (e.g. launched from Dock)."""
    hidden_clause = " with hidden answer" if hidden else ""
    script = (
        f'tell application "System Events" to display dialog '
        f'"{prompt_text}" with title "Hungryroot IT Dashboard Setup" '
        f'default answer ""{hidden_clause} buttons {{"Cancel","OK"}} default button "OK"'
    )
    try:
        result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
        if result.returncode != 0:
            return ""          # user clicked Cancel
        for part in result.stdout.strip().split(", "):
            if part.startswith("text returned:"):
                return part[len("text returned:"):].strip()
    except Exception:
        pass
    return ""


def _ask(prompt_text, hidden=False):
    """Read from terminal if available, otherwise show a macOS GUI dialog."""
    has_tty = sys.stdin and sys.stdin.isatty()
    if has_tty:
        if hidden:
            import getpass
            return getpass.getpass(prompt_text).strip()
        return input(prompt_text).strip()
    return _gui_prompt(prompt_text, hidden=hidden)


def main():
    # Cloud mode: load config from environment variables
    cfg = _config_from_env()
    if cfg:
        print(f"✅ Cloud mode — config from environment variables")
        if not DASHBOARD_PASS:
            print("⚠️  WARNING: DASHBOARD_PASS is not set. Login will be disabled.")
        _sheets_restore(cfg)  # restore offboarding data from Sheet if local file is missing
    else:
        # Local mode: load from JSON or run first-time setup
        cfg = load_config()
        if not cfg:
            has_tty = sys.stdin and sys.stdin.isatty()
            if has_tty:
                print("\n━━━ Hungryroot IT Dashboard First-Time Setup ━━━")
            else:
                subprocess.run([
                    "osascript", "-e",
                    'display alert "Iru Dashboard — First-Time Setup" '
                    'message "Enter your Iru/Kandji credentials in the next prompts." '
                    'buttons {"OK"} default button "OK"'
                ])
            subdomain = _ask("Subdomain (e.g. 'yourcompany'): ")
            token     = _ask("API Token: ", hidden=True)
            region    = (_ask("Region [us/eu] (default: us): ") or "us").lower()
            cfg = save_config(subdomain, token, region)
            print(f"✅ Config saved to iru_config.json\n")
        else:
            print(f"✅ Loaded config  →  subdomain: {cfg['subdomain']}  region: {cfg.get('region','us')}")

    DashboardHandler.config = cfg

    # Migrate single-user config to multi-user users file (no-op if already done)
    _init_users()

    # Load cached data from disk so first page load is instant
    _load_cache_from_disk()

    # Start background refresh thread
    bg = threading.Thread(target=_background_refresh_loop, daemon=True, name="cache-refresh")
    bg.start()

    # Warm up cache immediately if empty (non-blocking)
    if _cache_get("devices")[0] is None:
        print("[Cache] No cache found — warming up in background…")
        threading.Thread(target=_refresh_all, args=(cfg, True), daemon=True, name="cache-warmup").start()
    else:
        # Stale data is fine to serve; schedule a background refresh
        _refresh_flag.set()

    server = HTTPServer(("0.0.0.0", PORT), DashboardHandler)
    url = f"http://localhost:{PORT}"
    print(f"🚀 Dashboard running at {url}")
    print("   Press Ctrl+C to stop.\n")

    # Only auto-open browser if launched from terminal (app launcher opens it separately)
    if sys.stdin and sys.stdin.isatty():
        Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
