"""End-to-end test against the deployed stack (run from an admin workstation).

  python3 scripts/e2e_test.py            # STACK_NAME / REGION env optional

Creates two throw-away Cognito users (e2e-alice, e2e-bob), logs in as each,
and drives the runtime over HTTPS exactly like the browser does. Each check
prints PASS/FAIL; exit code is the number of failures.
"""

import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import boto3

sys.path.insert(0, os.path.dirname(__file__))
import manage_users  # noqa: E402  (onboarding control plane)

STACK = os.environ.get("STACK_NAME", "s3files-user")
REGION = os.environ.get("REGION", "us-west-2")
cfn = boto3.client("cloudformation", region_name=REGION)
OUT = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=STACK)["Stacks"][0]["Outputs"]}
POOL, CLIENT, RUNTIME_ARN = OUT["UserPoolId"], OUT["UserPoolClientId"], OUT["AgentRuntimeArn"]
BUCKET = OUT["DataBucketName"]
idp = boto3.client("cognito-idp", region_name=REGION)
lam = boto3.client("lambda", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)

failures = 0


def check(name: str, ok: bool, detail="") -> bool:
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""), flush=True)
    return ok


def login(username: str, password: str) -> str:
    r = idp.initiate_auth(ClientId=CLIENT, AuthFlow="USER_PASSWORD_AUTH",
                          AuthParameters={"USERNAME": username, "PASSWORD": password})
    return r["AuthenticationResult"]["AccessToken"]


def ensure_user(username: str) -> str:
    """Onboard via the control plane (Cognito user + AP + mapping), then log in."""
    return login(username, manage_users.add(username, None)["password"])


def new_session() -> str:
    return "e2e-" + str(uuid.uuid4())


def invoke(token, session_id, payload, timeout=300):
    """Return (status, parsed body). SSE bodies are returned as a list of events."""
    url = (f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
           f"{urllib.parse.quote(RUNTIME_ARN, safe='')}/invocations?qualifier=DEFAULT")
    headers = {"Content-Type": "application/json",
               "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status, ctype = r.read().decode(), r.status, r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        raw, status, ctype = e.read().decode(), e.code, e.headers.get("Content-Type", "")
    if "text/event-stream" in ctype:
        return status, [json.loads(line[6:]) for line in raw.splitlines() if line.startswith("data: ")]
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def sh(token, sid, command):
    status, body = invoke(token, sid, {"action": "exec", "command": command})
    ok = status == 200 and isinstance(body, dict) and "exitCode" in body
    return body if ok else {"exitCode": -1, "stdout": "", "stderr": str(body)}


def main() -> int:
    alice, bob = ensure_user("e2e-alice"), ensure_user("e2e-bob")
    a1, a2, a3, b1 = new_session(), new_session(), new_session(), new_session()
    marker = f"hello from alice {secrets.token_hex(4)}"

    print("== 用户 ↔ AP 映射（开户时由控制面写入）")
    rec_a, rec_b = manage_users._record("e2e-alice"), manage_users._record("e2e-bob")
    check("映射表里 alice / bob 各有一个 active 的 AP", rec_a["status"] == rec_b["status"] == "active"
          and rec_a["accessPointId"] != rec_b["accessPointId"], f"{rec_a['accessPointId']} / {rec_b['accessPointId']}")
    pw = "Aa1#" + secrets.token_urlsafe(12)
    try:
        idp.admin_create_user(UserPoolId=POOL, Username="e2e-nostorage", MessageAction="SUPPRESS")
    except idp.exceptions.UsernameExistsException:
        pass
    idp.admin_set_user_password(UserPoolId=POOL, Username="e2e-nostorage", Password=pw, Permanent=True)
    status, body = invoke(login("e2e-nostorage", pw), new_session(), {"action": "status"})
    check("登录了但未开通存储的用户 → 拒绝挂载", body.get("status") == 503 and "no storage provisioned" in body.get("error", ""),
          str(body)[:120])
    idp.admin_delete_user(UserPoolId=POOL, Username="e2e-nostorage")

    print("== 入口认证")
    status, _ = invoke(None, a1, {"action": "status"})
    check("无 token 调用被 AgentCore 拒绝", status in (401, 403), f"HTTP {status}")
    status, _ = invoke(alice[:-4] + "AAAA", a1, {"action": "status"})
    check("篡改 token 被 AgentCore 拒绝", status in (401, 403), f"HTTP {status}")

    print("== alice 首次请求：申请 STS 凭证 + 挂载")
    t0 = time.time()
    status, st_a = invoke(alice, a1, {"action": "status"})
    check("alice 冷启动挂载成功", status == 200 and st_a.get("mounted") is True,
          f"{time.time() - t0:.1f}s ap={st_a.get('accessPointId') if isinstance(st_a, dict) else st_a}")
    check("AP 根目录 = /users/<sha256(sub)>", str(st_a.get("rootPath", "")).startswith("/users/")
          and len(st_a.get("userKey", "")) == 64)

    print("== 非 root agent")
    r = sh(alice, a1, "id -u; id -g; grep NoNewPrivs /proc/self/status | awk '{print $2}'")
    check("agent 以 uid/gid 1000 运行且 NoNewPrivs=1", r["stdout"].split() == ["1000", "1000", "1"], r["stdout"].strip())
    r = sh(alice, a1, "cat /root/.aws/credentials")
    check("agent 读不到 root 的 STS 凭证文件", r["exitCode"] != 0 and "Permission denied" in r["stderr"], r["stderr"].strip())
    r = sh(alice, a1, "mkdir -p /tmp/m && mount -t tmpfs none /tmp/m")
    check("agent 无法 mount", r["exitCode"] != 0, r["stderr"].strip()[-80:])
    r = sh(alice, a1, "cat /proc/1/environ")
    check("agent 读不到 gateway(root) 进程的环境", r["exitCode"] != 0, r["stderr"].strip()[-80:])

    print("== 读写持久化")
    r = sh(alice, a1, f"mkdir -p notes && echo '{marker}' > notes/alice.txt && cat notes/alice.txt")
    check("alice 写入 /mnt/user/notes/alice.txt", r["exitCode"] == 0 and marker in r["stdout"])
    status, files = invoke(alice, a1, {"action": "list_files"})
    check("list_files 能看到该文件", any(f["path"] == "notes/alice.txt" for f in files.get("files", [])))

    print("== bob：另一个用户")
    status, st_b = invoke(bob, b1, {"action": "status"})
    check("bob 挂载成功且 AP 与 alice 不同", status == 200 and st_b.get("accessPointId") not in (None, st_a.get("accessPointId")),
          f"bob ap={st_b.get('accessPointId')}")
    status, files_b = invoke(bob, b1, {"action": "list_files"})
    check("bob 看不到 alice 的文件", not any("alice" in f["path"] for f in files_b.get("files", [])))
    r = sh(bob, b1, f"grep -rl '{marker}' / 2>/dev/null | head -3")
    check("bob 全盘搜索也找不到 alice 的内容", r["stdout"].strip() == "", r["stdout"].strip())

    print("== 会话与用户绑定")
    status, body = invoke(bob, a1, {"action": "list_files"})
    check("bob 的 token 打到 alice 的 session 被 gateway 拒绝", body.get("status") == 403, str(body))

    race_sid = new_session()
    from concurrent.futures import ThreadPoolExecutor

    def first_request(t):  # AgentCore answers 409 while the session is being created: retry like a client would
        for _ in range(5):
            status, body = invoke(t, race_sid, {"action": "status"})
            if status != 409:
                return body
            time.sleep(3)
        return body
    with ThreadPoolExecutor(2) as pool:
        ra, rb = pool.map(first_request, [alice, bob])
    outcomes = sorted(["ok" if r.get("mounted") else r.get("status") for r in (ra, rb)], key=str)
    check("两个用户并发抢同一个新 session → 一个成功、另一个被 gateway 403", outcomes == [403, "ok"], str(outcomes))

    print("== 执行角色（MMDS，VM 内任何代码都拿得到）不能碰用户数据")
    probe = (
        "import boto3,json\n"
        f"lam=boto3.client('lambda',region_name='{REGION}')\n"
        "out={}\n"
        "for name,payload in [('no_token',{}),('bogus_token',{'token':'a.b.c'})]:\n"
        f"  r=lam.invoke(FunctionName='{STACK}-broker',Payload=json.dumps(payload))\n"
        "  out[name]=json.loads(r['Payload'].read()).get('error','MINTED!')\n"
        "try:\n"
        f"  boto3.client('s3',region_name='{REGION}').list_objects_v2(Bucket='{BUCKET}',MaxKeys=1); out['s3']='ALLOWED!'\n"
        "except Exception as e: out['s3']=type(e).__name__+':'+str(e)[:60]\n"
        "try:\n"
        f"  boto3.client('s3files',region_name='{REGION}').list_access_points(fileSystemId='{st_a.get('fileSystemId')}'); out['s3files']='ALLOWED!'\n"
        "except Exception as e: out['s3files']=getattr(e,'response',{}).get('Error',{}).get('Code',type(e).__name__)\n"
        "print(json.dumps(out))\n"
    )
    r = sh(alice, a1, f"python3.11 - <<'EOF'\n{probe}EOF")
    try:
        res = json.loads(r["stdout"].strip().splitlines()[-1])
    except Exception:
        res = {"raw": r}
    check("执行角色 + 无 token 调 broker → 拒绝", "unauthorized" in str(res.get("no_token")), str(res.get("no_token")))
    check("执行角色 + 伪造 token 调 broker → 拒绝", "unauthorized" in str(res.get("bogus_token")), str(res.get("bogus_token")))
    check("执行角色直接读数据桶 → AccessDenied", "AccessDenied" in str(res.get("s3")), str(res.get("s3")))
    check("执行角色调 S3 Files 控制面 → AccessDenied", "AccessDenied" in str(res.get("s3files")) or "Forbidden" in str(res.get("s3files")),
          str(res.get("s3files")))

    print("== broker 直接调用（管理员身份，验证幂等与 token 校验）")
    r1 = json.loads(lam.invoke(FunctionName=f"{STACK}-broker", Payload=json.dumps({"token": alice}))["Payload"].read())
    check("broker 按映射表返回 alice 的 AP", r1.get("accessPointId") == st_a.get("accessPointId") == rec_a["accessPointId"])
    from datetime import datetime, timezone
    ttl = (datetime.fromisoformat(r1["credentials"]["Expiration"]) - datetime.now(timezone.utc)).total_seconds()
    check("凭证有效期 ≤ 1h（role chaining 上限）", 0 < ttl <= 3600, f"{ttl:.0f}s")

    print("== STS 凭证轮换")
    before = st_a["credentials"]["accessKeyId"]
    status, st_r = invoke(alice, a1, {"action": "rotate"})
    check("rotate 后 AccessKeyId 变化、轮换次数 +1",
          status == 200 and st_r["credentials"]["accessKeyId"] != before and st_r["credentials"]["rotations"] >= 1,
          f"{before} -> {st_r.get('credentials', {}).get('accessKeyId')}")
    r = sh(alice, a1, "echo after-rotate >> notes/alice.txt && tail -1 notes/alice.txt")
    check("轮换后挂载照常可写（无需重新挂载）", "after-rotate" in r["stdout"])

    print("== 停用用户（控制面吊销）")
    manage_users.set_status("e2e-alice", "disabled")
    status, body = invoke(alice, a1, {"action": "rotate"})
    check("停用后凭证轮换被 broker 拒绝", body.get("status") == 502 and "disabled" in body.get("error", ""), str(body)[:120])
    status, body = invoke(alice, a3, {"action": "status"})
    check("停用后新会话无法挂载", body.get("status") == 503 and "disabled" in body.get("error", ""), str(body)[:120])
    manage_users.set_status("e2e-alice", "active")
    status, body = invoke(alice, a1, {"action": "rotate"})
    check("恢复后轮换成功", status == 200 and body["credentials"]["lastError"] is None)

    print("== 新会话（新 microVM）数据仍在")
    t0 = time.time()
    status, files2 = invoke(alice, a2, {"action": "list_files"})
    check("alice 新会话看到之前写的文件", any(f["path"] == "notes/alice.txt" for f in files2.get("files", [])),
          f"{time.time() - t0:.1f}s")
    status, content = invoke(alice, a2, {"action": "read_file", "path": "notes/alice.txt"})
    check("内容一致", marker in content.get("content", ""))

    print("== 数据落在自有 S3 桶")
    key = f"users/{st_a['userKey']}/notes/alice.txt"
    seen = False
    for _ in range(24):
        try:
            seen = marker in s3.get_object(Bucket=BUCKET, Key=key)["Body"].read().decode()
            if seen:
                break
        except s3.exceptions.NoSuchKey:
            pass
        time.sleep(5)
    check(f"s3://{BUCKET}/{key} 可见", seen)

    print("== 大模型对话（agent 使用工具写文件）")
    status, events = invoke(alice, a2, {"action": "chat",
                                         "prompt": "在工作区写一个 hello.md，内容是一句中文问候，然后告诉我写好了。"})
    tools = [e["name"] for e in events if isinstance(e, dict) and e.get("type") == "tool"] if isinstance(events, list) else []
    check("chat 流式返回并调用 write_file", status == 200 and "write_file" in tools and events[-1].get("type") == "done",
          f"tools={tools}")
    status, files3 = invoke(alice, a2, {"action": "list_files"})
    check("hello.md 已出现在工作区", any(f["path"] == "hello.md" for f in files3.get("files", [])))

    print(f"\n{failures} 项失败")
    return failures


if __name__ == "__main__":
    sys.exit(main())
