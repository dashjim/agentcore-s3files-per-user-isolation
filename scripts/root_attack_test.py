"""Worst case: an attacker is ROOT inside alice's microVM and holds alice's
mount credentials. Can they reach bob's data?

Uses InvokeAgentRuntimeCommand (runs a shell command in the session as the
container's root) with alice's bearer token, then tries, with alice's
user-mount profile:
  1. mount alice's own access point      -> control, must succeed
  2. mount bob's access point            -> must be denied (STS session policy)
  3. mount the file system root (no AP)  -> must be denied (file system policy)

  python3 scripts/e2e_test.py        # first: onboards e2e-alice / e2e-bob
  python3 scripts/root_attack_test.py
"""

import os
import secrets
import shlex
import sys
import uuid

import boto3
from botocore import UNSIGNED
from botocore.config import Config

sys.path.insert(0, os.path.dirname(__file__))
import manage_users  # noqa: E402
from e2e_test import RUNTIME_ARN, REGION, check, invoke, login  # noqa: E402
import e2e_test  # noqa: E402


def run_as_root(token: str, session_id: str, command: str) -> tuple[int, str]:
    client = boto3.client("bedrock-agentcore", region_name=REGION, config=Config(signature_version=UNSIGNED))
    client.meta.events.register(
        "before-sign.bedrock-agentcore.InvokeAgentRuntimeCommand",
        lambda request, **_: request.headers.__setitem__("Authorization", f"Bearer {token}"))
    resp = client.invoke_agent_runtime_command(agentRuntimeArn=RUNTIME_ARN, runtimeSessionId=session_id,
                                               body={"command": f"bash -c {shlex.quote(command)}", "timeout": 120})
    out, code = "", None
    for ev in resp["stream"]:
        chunk = ev.get("chunk", {})
        if "contentDelta" in chunk:
            out += chunk["contentDelta"].get("stdout", "") + chunk["contentDelta"].get("stderr", "")
        elif "contentStop" in chunk:
            code = chunk["contentStop"].get("exitCode")
    return code, out


def main() -> int:
    pw = {u: manage_users.add(u, None)["password"] for u in ("e2e-alice", "e2e-bob")}
    alice = login("e2e-alice", pw["e2e-alice"])
    rec_a, rec_b = manage_users._record("e2e-alice"), manage_users._record("e2e-bob")
    fs = rec_a["fileSystemId"]
    sid = "atk-" + str(uuid.uuid4())

    _, st = invoke(alice, sid, {"action": "status"})
    check("alice 的 session 已挂载", st.get("mounted") is True, st.get("accessPointId", str(st)))

    code, out = run_as_root(alice, sid, "id -u")
    if not check("InvokeAgentRuntimeCommand 以 root 执行", code == 0 and out.strip() == "0", out.strip()[:200]):
        return e2e_test.failures

    def try_mount(label: str, ap: str | None) -> tuple[int, str]:
        target = f"/mnt/atk-{secrets.token_hex(3)}"
        opt = (f"accesspoint={ap}," if ap else "") + "awsprofile=user-mount,nodirects3read"
        cmd = (f"mkdir -p {target} && timeout 90 mount -t s3files -o {opt} {fs}:/ {target} && "
               f"echo MOUNTED && ls -la {target} | head -5; umount {target} 2>/dev/null; true")
        code, out = run_as_root(alice, sid, cmd)
        print(f"  [{label}] {out.strip()[-300:]}")
        return code, out

    denied = ("access denied", "accessdenied", "permission denied", "not authorized", "failed")
    _, out = try_mount("alice 自己的 AP", rec_a["accessPointId"])
    if not check("对照组：alice 的凭证能挂 alice 的 AP", "MOUNTED" in out):
        return e2e_test.failures  # without a working control the denials prove nothing
    _, out = try_mount("bob 的 AP", rec_b["accessPointId"])
    check("alice 的凭证挂 bob 的 AP → 被拒绝（会话策略）",
          "MOUNTED" not in out and any(d in out.lower() for d in denied))
    _, out = try_mount("文件系统根目录（不经 AP）", None)
    check("alice 的凭证挂根目录 → 被拒绝（文件系统策略）",
          "MOUNTED" not in out and any(d in out.lower() for d in denied))

    print(f"\n{e2e_test.failures} 项失败")
    return e2e_test.failures


if __name__ == "__main__":
    sys.exit(main())
