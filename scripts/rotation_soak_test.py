"""Soak test for automatic STS rotation (no manual "rotate" calls).

Deploy with a short TTL first so rotation happens within minutes:
  CRED_TTL_SECONDS=900 bash scripts/deploy.sh      # STS minimum
  python3 scripts/rotation_soak_test.py [minutes=28]

With minutes >= 65 (default TTL 3600 is fine) it also reads the efs-utils TLS
client certificate as root (InvokeAgentRuntimeCommand) after the watchdog's
60-minute renewal and checks the AccessKeyId embedded in it is a ROTATED key.

Keeps one e2e-soak session alive (status every 4 min, under the 15 min idle
timeout), and checks the background loop rotated on its own and that the
mount still works after the FIRST credentials have expired.
"""

import os
import sys
import time
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))
import manage_users  # noqa: E402
import e2e_test  # noqa: E402
from e2e_test import check, invoke, login, sh  # noqa: E402
from root_attack_test import run_as_root  # noqa: E402

# The cert's efs_client_auth extension (OID 1.3.6.1.4.1.4843.7.2) carries the
# AccessKeyId that signed it; print it (masked) with the cert's notBefore.
USER = "e2e-soak"  # dedicated user: other tests reset e2e-alice's password
CERT_CMD = ("for c in /var/run/efs/*/certificate.pem; do openssl x509 -in $c -noout -startdate; "
            "openssl x509 -in $c -noout -text | grep -o 'ASIA[A-Z0-9]*' | sed -E 's/^(.{4}).*(.{4})$/\\1…\\2/'; done")


def main() -> int:
    minutes = float(sys.argv[1]) if len(sys.argv) > 1 else 28
    password = manage_users.add(USER, None)["password"]
    token, token_at = login(USER, password), time.time()
    sid = "soak-" + str(uuid.uuid4())
    _, st = invoke(token, sid, {"action": "status"})
    first_key = st["credentials"]["accessKeyId"]
    first_exp = datetime.fromisoformat(st["credentials"]["expiration"])
    print(f"session {sid}\n首份凭证 {first_key} 过期于 {first_exp.isoformat()}", flush=True)
    print("TLS 证书:", run_as_root(token, sid, CERT_CMD)[1].strip(), flush=True)

    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        time.sleep(240)
        if time.time() - token_at > 45 * 60:  # like the browser: refresh the token before it expires
            token, token_at = login(USER, password), time.time()
        _, st = invoke(token, sid, {"action": "status"})
        c = st["credentials"]
        r = sh(token, sid, f"date -u +%T >> soak.log && tail -1 soak.log")
        print(f"{datetime.now(timezone.utc):%H:%M:%S}  key={c['accessKeyId']} rotations={c['rotations']} "
              f"exp={c['expiration'][11:19]} lastError={c['lastError']} write={'ok' if r['exitCode'] == 0 else r}",
              flush=True)

    past_first = datetime.now(timezone.utc) > first_exp
    check("后台循环自动轮换（≥ 1 次，无人工 rotate）", st["credentials"]["rotations"] >= 1, str(st["credentials"]))
    check("首份凭证已过期", past_first, first_exp.isoformat())
    check("首份凭证过期后挂载仍可写", r["exitCode"] == 0, r["stdout"].strip())
    check("最后一次轮换无错误", st["credentials"]["lastError"] is None)
    if minutes >= 65:
        _, cert = run_as_root(token, sid, CERT_CMD)
        print("TLS 证书:", cert.strip())
        check("watchdog 已续签 TLS 证书，且证书里嵌的是轮换后的 AccessKeyId",
              first_key[-4:] not in cert and st["credentials"]["accessKeyId"][-4:] in cert, cert.strip()[-200:])
    print(f"\n{e2e_test.failures} 项失败")
    return e2e_test.failures


if __name__ == "__main__":
    sys.exit(main())
