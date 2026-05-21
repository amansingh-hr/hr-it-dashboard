#!/usr/bin/env python3
"""
Okta user deactivation test script.
Finds a user by email and deactivates their account.
"""

import urllib.request
import urllib.parse
import json
import sys

# ── Credentials ──────────────────────────────────────────────────────────────
OKTA_DOMAIN    = "hungryroot.okta.com"
OKTA_API_TOKEN = "00706ik3wQB0sf_Y9fgqIdjKCpinvEDrpEOATrsMGk"

TEST_EMAIL = "test.user2@hungryroot.com"


def okta_request(method, path, body=None):
    url  = f"https://{OKTA_DOMAIN}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"SSWS {OKTA_API_TOKEN}")
    req.add_header("Content-Type",  "application/json")
    req.add_header("Accept",        "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return None, {"error": str(e)}


def find_user(email):
    print(f"\n🔍 Searching for Okta user: {email}")
    encoded = urllib.parse.quote(f'profile.email eq "{email}"')
    status, data = okta_request("GET", f"/api/v1/users?search={encoded}")
    print(f"  → GET /api/v1/users?search=... → {status}")

    if status != 200:
        print(f"  ❌ API error: {data}")
        return None

    if not data:
        print(f"  ⚠️  User not found.")
        return None

    user = data[0]
    profile = user.get("profile", {})
    print(f"  ✅ Found user:")
    print(f"     ID     : {user.get('id')}")
    print(f"     Email  : {profile.get('email')}")
    print(f"     Name   : {profile.get('firstName')} {profile.get('lastName')}")
    print(f"     Status : {user.get('status')}")
    return user


def deactivate_user(user):
    uid    = user.get("id")
    status = user.get("status", "")
    email  = user.get("profile", {}).get("email", uid)

    if not uid:
        print("  ❌ No user ID — cannot deactivate.")
        return False

    if status in ("DEPROVISIONED", "DEACTIVATED"):
        print(f"\n  ℹ️  User '{email}' is already {status}. No action needed.")
        return True

    print(f"\n⚠️  About to DEACTIVATE Okta user '{email}'.")
    confirm = input("   Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("   Cancelled.")
        return False

    print(f"\n🔄 Deactivating {uid}...")
    s, d = okta_request("POST", f"/api/v1/users/{uid}/lifecycle/deactivate")
    print(f"  → POST /api/v1/users/{uid}/lifecycle/deactivate → {s}")

    if s in (200, 204):
        print(f"  ✅ Successfully deactivated '{email}' in Okta.")
        return True
    else:
        print(f"  ❌ Failed. Status {s}: {d}")
        return False


def main():
    if not OKTA_API_TOKEN:
        print("❌ Set OKTA_API_TOKEN before running.")
        sys.exit(1)

    print("=" * 55)
    print("  Okta User Deactivation Test")
    print("=" * 55)

    user = find_user(TEST_EMAIL)
    if not user:
        print("\nNo action taken — user not found.")
        sys.exit(0)

    deactivate_user(user)
    print("\nDone.")


if __name__ == "__main__":
    main()
