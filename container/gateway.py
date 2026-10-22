"""Root gateway: the only process that ever touches mount credentials.

Listens on :8080 (the AgentCore contract port). On the first invocation:

  1. Read the user's Cognito access token from the Authorization header
     (AgentCore already validated it; the header is allow-listed).
  2. Ask the broker Lambda for per-user STS credentials. The broker re-verifies
     the token and returns credentials that can mount ONLY this user's access
     point. No credentials -> no mount -> no service. Never falls back to the
     execution role.
  3. Write them to a root-only profile and `mount -t s3files` the user's
     access point at /mnt/user.
  4. Bind this microVM to that user; later requests from anyone else -> 403.
  5. Proxy requests to the agent (uid 1000, 127.0.0.1:8081) with the
     Authorization header stripped.

A background loop rotates the STS credentials before they expire (role
chaining caps them at 1 h): it re-calls the broker with the user's latest
token and rewrites the profile in place. The efs-utils watchdog re-reads the
profile when it renews the TLS certificate, so the mount is never remounted.
"""

import asyncio
import base64
import json
import os
import subprocess
import time
from datetime import datetime, timezone

import aiohttp
import boto3
from aiohttp import web

REGION = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION", "us-west-2")
BROKER_FUNCTION = os.environ["BROKER_FUNCTION"]
DATA_BUCKET = os.environ.get("DATA_BUCKET", "")
AGENT_UID = int(os.environ.get("AGENT_UID", "1000"))
AGENT_URL = "http://127.0.0.1:8081"
MOUNT_POINT = "/mnt/user"
PROFILE = "user-mount"
CREDENTIALS_FILE = "/root/.aws/credentials"
REFRESH_BUFFER_S = int(os.environ.get("REFRESH_BUFFER_SECONDS", "900"))
RETRY_S = 60


def log(event: str, **fields) -> None:
    print(json.dumps({"component": "gateway", "event": event, **fields}), flush=True)


def jwt_claims(token: str) -> dict:
    # Signature already checked by the AgentCore JWT authorizer (and again by
    # the broker); here we only need `sub` to bind the microVM to one user.
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class OtherUser(Exception):
    pass


class MountController:
    def __init__(self) -> None:
        self.lambda_client = boto3.client("lambda", region_name=REGION)
        self.lock = asyncio.Lock()
        self.bound_sub: str | None = None
        self.latest_token: str | None = None
        self.target: dict | None = None  # broker result minus credentials
        self.access_key_id = ""
        self.expiration: datetime | None = None
        self.rotations = 0
        self.last_rotation: str | None = None
        self.last_error: str | None = None
        self.wake = asyncio.Event()

    # ---- credentials -------------------------------------------------
    def _call_broker(self, token: str) -> dict:
        resp = self.lambda_client.invoke(
            FunctionName=BROKER_FUNCTION,
            Payload=json.dumps({"token": token}).encode(),
        )
        result = json.loads(resp["Payload"].read())
        if "error" in result or "credentials" not in result:
            raise RuntimeError(f"broker refused: {result.get('error', result)}")
        return result

    def _write_profile(self, creds: dict) -> None:
        # Root-only file: the agent (uid 1000) cannot read it. Write-then-rename
        # so the watchdog never sees a half-written profile.
        os.makedirs(os.path.dirname(CREDENTIALS_FILE), mode=0o700, exist_ok=True)
        tmp = CREDENTIALS_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(
                f"[{PROFILE}]\n"
                f"aws_access_key_id = {creds['AccessKeyId']}\n"
                f"aws_secret_access_key = {creds['SecretAccessKey']}\n"
                f"aws_session_token = {creds['SessionToken']}\n"
            )
        os.replace(tmp, CREDENTIALS_FILE)

    async def _mint(self, token: str) -> dict:
        result = await asyncio.get_running_loop().run_in_executor(None, self._call_broker, token)
        creds = result.pop("credentials")
        self._write_profile(creds)
        self.access_key_id = creds["AccessKeyId"]
        self.expiration = datetime.fromisoformat(creds["Expiration"])
        return result

    # ---- mount -------------------------------------------------------
    def _mount(self, fs_id: str, ap_id: str) -> None:
        os.makedirs(MOUNT_POINT, exist_ok=True)
        if os.path.ismount(MOUNT_POINT):
            return
        cmd = ["mount", "-t", "s3files",
               "-o", f"accesspoint={ap_id},awsprofile={PROFILE},nodirects3read",
               f"{fs_id}:/", MOUNT_POINT]
        for attempt in range(1, 7):
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                               env={**os.environ, "HOME": "/root"})
            if r.returncode == 0 and os.path.ismount(MOUNT_POINT):
                return
            log("mount_retry", attempt=attempt, stderr=r.stderr.strip()[-500:])
            time.sleep(2 * attempt)
        raise RuntimeError(f"mount failed: {r.stderr.strip()[-300:]}")

    async def _wait_agent(self, timeout_s: float = 90) -> None:
        deadline = time.monotonic() + timeout_s
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2)) as s:
            while time.monotonic() < deadline:
                try:
                    async with s.get(f"{AGENT_URL}/ping") as r:
                        if r.status == 200:
                            return
                except aiohttp.ClientError:
                    pass
                await asyncio.sleep(0.2)
        raise RuntimeError("agent process not healthy")

    async def ensure_ready(self, token: str, sub: str) -> None:
        async with self.lock:
            if self.bound_sub:
                # Re-check under the lock: two users' first requests may race
                # into an unbound microVM; only the winner is served.
                if self.bound_sub != sub:
                    raise OtherUser()
                return
            t0 = time.monotonic()
            target = await self._mint(token)
            t1 = time.monotonic()
            await asyncio.get_running_loop().run_in_executor(
                None, self._mount, target["fileSystemId"], target["accessPointId"])
            t2 = time.monotonic()
            await self._wait_agent()
            self.target = target
            self.bound_sub = sub
            self.last_rotation = datetime.now(timezone.utc).isoformat()
            log("mounted", userKey=target["userKey"], accessPointId=target["accessPointId"],
                mint_ms=int((t1 - t0) * 1000), mount_ms=int((t2 - t1) * 1000),
                expiration=self.expiration.isoformat())
            asyncio.create_task(self._refresh_loop())

    # ---- rotation ----------------------------------------------------
    def _seconds_until_refresh(self) -> float:
        remaining = (self.expiration - datetime.now(timezone.utc)).total_seconds()
        buffer = min(REFRESH_BUFFER_S, remaining / 4)
        return max(0.0, remaining - buffer)

    async def rotate(self) -> None:
        await self._mint(self.latest_token)
        self.rotations += 1
        self.last_rotation = datetime.now(timezone.utc).isoformat()
        self.last_error = None
        log("rotated", rotations=self.rotations, expiration=self.expiration.isoformat())

    async def _refresh_loop(self) -> None:
        delay = self._seconds_until_refresh()
        while True:
            try:
                await asyncio.wait_for(self.wake.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()
            try:
                await self.rotate()
                delay = self._seconds_until_refresh()
            except Exception as e:
                # Keep serving: the mount survives until the TLS cert expires.
                # A fresh token on the next request wakes us up early.
                self.last_error = str(e)
                log("rotate_failed", error=str(e))
                delay = RETRY_S

    def note_token(self, token: str) -> None:
        self.latest_token = token
        if self.last_error and self.bound_sub:
            self.wake.set()  # last rotation failed (e.g. stale token): retry now

    def status(self) -> dict:
        t = self.target or {}
        return {
            "username": t.get("username"),
            "storageStatus": t.get("status"),
            "mounted": os.path.ismount(MOUNT_POINT),
            "mountPoint": MOUNT_POINT,
            "fileSystemId": t.get("fileSystemId"),
            "accessPointId": t.get("accessPointId"),
            "rootPath": t.get("rootPath"),
            "userKey": t.get("userKey"),
            "s3Prefix": f"s3://{DATA_BUCKET}{t['rootPath']}/" if t else None,
            "agentUid": AGENT_UID,
            "credentials": {
                "accessKeyId": ("…" + self.access_key_id[-4:]) if self.access_key_id else None,
                "expiration": self.expiration.isoformat() if self.expiration else None,
                "rotations": self.rotations,
                "lastRotation": self.last_rotation,
                "lastError": self.last_error,
            },
        }


ctl: MountController


def fail(message: str, status: int) -> web.Response:
    # AgentCore turns any non-2xx from the container into "424 Received error
    # (<code>) from runtime" and drops the body, so business errors go back
    # as 200 + {"error", "status"} for the client to see the reason.
    log("request_failed", status=status, error=message)
    return web.json_response({"error": message, "status": status})


async def ping(_request: web.Request) -> web.Response:
    return web.json_response({"status": "Healthy", "time_of_last_update": int(time.time())})


async def invocations(request: web.Request) -> web.StreamResponse:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return fail("missing bearer token", 401)
    token = auth[len("Bearer "):]
    try:
        sub = jwt_claims(token)["sub"]
    except Exception:
        return fail("malformed token", 401)

    # One microVM serves one user for its whole life.
    if ctl.bound_sub and sub != ctl.bound_sub:
        return fail("this session belongs to another user", 403)

    body = await request.read()
    try:
        payload = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return fail("invalid JSON body", 400)

    try:
        await ctl.ensure_ready(token, sub)
    except OtherUser:
        return fail("this session belongs to another user", 403)
    except Exception as e:
        return fail(f"存储未就绪，拒绝服务：{e}", 503)
    ctl.note_token(token)

    action = payload.get("action")
    if action == "status":
        return web.json_response(ctl.status())
    if action == "rotate":
        try:
            await ctl.rotate()
        except Exception as e:
            return fail(f"凭证轮换失败：{e}", 502)
        return web.json_response(ctl.status())

    # Forward to the non-root agent. Only the body travels: no Authorization.
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=900)) as s:
        async with s.post(f"{AGENT_URL}/invocations", data=body,
                          headers={"Content-Type": "application/json"}) as upstream:
            resp = web.StreamResponse(status=upstream.status, headers={
                "Content-Type": upstream.headers.get("Content-Type", "application/json")})
            await resp.prepare(request)
            async for chunk in upstream.content.iter_any():
                await resp.write(chunk)
            await resp.write_eof()
            return resp


async def on_startup(_app: web.Application) -> None:
    global ctl
    ctl = MountController()


def main() -> None:
    assert os.getuid() == 0, "gateway must run as root (mount + credential file)"
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.on_startup.append(on_startup)
    app.router.add_get("/ping", ping)
    app.router.add_post("/invocations", invocations)
    web.run_app(app, host="0.0.0.0", port=8080, access_log=None)


if __name__ == "__main__":
    main()
