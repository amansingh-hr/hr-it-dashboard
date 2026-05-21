#!/usr/bin/env python3
"""
Braze company user (dashboard access) removal via SCIM API.
Finds and removes an employee's Braze dashboard access.
"""

import urllib.request
import urllib.parse
import json
import sys

# ── Credentials ──────────────────────────────────────────────────────────────
BRAZE_SCIM_TOKEN = "df8f2e890663f4727f976258ed817f842b5bad19fa479396ea3be140a2459289"
BRAZE_SCIM_URL   = "https://rest.iad-06.braze.com"

TEST_EMAIL = "test.user2@hungryroot.com"


def braze_request(method, path, body=None):
    url  = f"{BRAZE_SCIM_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {BRAZE_SCIM_TOKEN}")
    req.add_header("Content-Type",  "application/json")
    req.add_header("X-Request-Origin", "https://hungryroot.okta.com")
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


def find_company_user(email):
    print(f"\n🔍 Searching for company user: {email}")

    # Try SCIM search
    encoded = urllib.parse.quote(f'userName eq "{email}"')
    status, data = braze_request("GET", f"/scim/v2/Users?filter={encoded}")
    print(f"  → GET /scim/v2/Users?filter=... → {status}")

    if status == 200:
        resources = data.get("Resources", [])
        if resources:
            user = resources[0]
            print(f"  ✅ Found via SCIM:")
            print(f"     ID    : {user.get('id')}")
            print(f"     Email : {user.get('userName')}")
            print(f"     Name  : {user.get('displayName', '—')}")
            return user, "scim"
        else:
            print(f"  ⚠️  Not found via SCIM filter.")

    # Try listing all SCIM users
    print(f"\n  🔄 Trying full SCIM user list...")
    status2, data2 = braze_request("GET", "/scim/v2/Users")
    print(f"  → GET /scim/v2/Users → {status2}")
    if status2 == 200:
        resources = data2.get("Resources", [])
        print(f"  ℹ️  Total company users: {len(resources)}")
        match = next((u for u in resources if u.get("userName", "").lower() == email.lower()), None)
        if match:
            print(f"  ✅ Found in full list:")
            print(f"     ID    : {match.get('id')}")
            print(f"     Email : {match.get('userName')}")
            return match, "scim"
        else:
            print(f"  ⚠️  {email} not in company user list.")

    print(f"  ❌ Could not find company user. Last status: {status2 if status2 else status}")
    print(f"  Response: {str(data2 if status2 else data)[:300]}")
    return None, None


def remove_company_user(user, method):
    uid   = user.get("id")
    email = user.get("userName", uid)

    if not uid:
        print("  ❌ No user ID — cannot remove.")
        return False

    print(f"\n⚠️  About to REMOVE company user '{email}' from Braze.")
    confirm = input("   Type 'yes' to confirm: ").strip().lower()
    if confirm != "yes":
        print("   Cancelled.")
        return False

    print(f"\n🔄 Removing user {uid}...")
    status, data = braze_request("DELETE", f"/scim/v2/Users/{uid}")
    print(f"  → DELETE /scim/v2/Users/{uid} → {status}")

    if status in (200, 204):
        print(f"  ✅ Successfully removed '{email}' from Braze.")
        return True
    else:
        print(f"  ❌ Failed. Status {status}: {data}")
        return False


def main():
    print("=" * 55)
    print("  Braze Company User Removal Test")
    print("=" * 55)

    user, method = find_company_user(TEST_EMAIL)
    if not user:
        print("\nNo action taken — user not found.")
        sys.exit(0)

    remove_company_user(user, method)
    print("\nDone.")


if __name__ == "__main__":
    main()
