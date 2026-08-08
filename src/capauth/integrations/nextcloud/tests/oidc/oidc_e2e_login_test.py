import json
import sys
import urllib.parse

import requests

S = requests.Session()
S.headers.update({"User-Agent": "oidc-e2e"})
NC = "https://nextcloud-skstack41.skworld.io"
SSO = "https://sksso-skstack41.skworld.io"
PW = "Sk-OujvA_orlifIdrJh"
# 1. start at nextcloud's own login init (builds correct authorize + sets NC session/state)
r = S.get(NC + "/index.php/apps/user_oidc/login/1", allow_redirects=False, timeout=15)
authz = r.headers.get("location", "")
print(
    "1. nc login init ->",
    r.status_code,
    "authorize" if "/application/o/authorize" in authz else authz[:80],
)
# 2. hit sksso authorize (verbatim)
r = S.get(authz, allow_redirects=False, timeout=15)
loc = r.headers.get("location", "")
print(
    "2. authorize ->",
    r.status_code,
    ("FLOW " + loc.split("?")[0][-40:]) if "/if/flow/" in loc else loc[:90],
)
if "/if/flow/" not in loc:
    print("   STILL malformed — provider issue, not url-building")
    sys.exit(1)
slug = loc.split("/if/flow/")[1].split("/")[0]
flowq = urllib.parse.urlparse(loc).query
ex = f"{SSO}/api/v3/flows/executor/{slug}/"
params = {"query": flowq}
c = S.get(ex, params=params, headers={"Accept": "application/json"}, timeout=15).json()
for i in range(8):
    comp = c.get("component")
    print(f"3.{i}", comp)
    if comp == "ak-stage-identification":
        d = {"uid_field": "akadmin"}
        if c.get("password_fields"):
            d["password"] = PW
        c = S.post(ex, params=params, json=d, timeout=15).json()
    elif comp == "ak-stage-password":
        c = S.post(ex, params=params, json={"password": PW}, timeout=15).json()
    elif comp == "ak-stage-consent":
        c = S.post(ex, params=params, json={}, timeout=15).json()
    elif comp == "xak-flow-redirect":
        break
    else:
        print("   unexpected:", json.dumps(c)[:200])
        break
to = c.get("to")
print("4. flow done ->", (to or "")[:50])
# 3. follow continuation -> nc callback (auto-follow cross-domain, keep cookies)
r = S.get(to if to.startswith("http") else SSO + to, allow_redirects=True, timeout=15)
print("5. final url:", r.url[:70], "status", r.status_code)
# 4. verify logged in via OCS whoami
who = S.get(
    NC + "/ocs/v1.php/cloud/user?format=json", headers={"OCS-APIRequest": "true"}, timeout=15
)
try:
    j = who.json()
    uid = j["ocs"]["data"].get("id")
    dn = j["ocs"]["data"].get("display-name")
    print("6. WHOAMI: id=%s display=%s" % (uid, dn))
    print(
        "\n=== OIDC LOGIN E2E: PASS — provisioned & logged in as %s ===" % uid
        if uid
        else "=== FAIL (no session) ==="
    )
except Exception:
    print("6. whoami not json (status %s) — checking session cookie" % who.status_code)
    print(
        "   nc cookies:", [k for k in S.cookies.get_dict(domain="nextcloud-skstack41.skworld.io")]
    )
