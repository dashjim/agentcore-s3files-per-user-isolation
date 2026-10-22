"""Non-root agent: a Strands agent whose workspace is the user's S3 Files mount.

Started as root by entrypoint.sh, it drops to AGENT_UID (the uid every user
access point enforces) before importing anything else, and sets
no_new_privs so setuid binaries (mount, su, ...) cannot regain root. From
here on neither this process nor any code it runs (LLM-chosen shell commands
included) can read /root/.aws, mount file systems, or ptrace the gateway.

Only the gateway can reach it (127.0.0.1:8081), and the gateway forwards a
request only after the user's access point is mounted at /mnt/user.
"""

import ctypes
import os
import sys

AGENT_UID = int(os.environ.get("AGENT_UID", "1000"))
WORKSPACE = "/mnt/user"
PR_SET_NO_NEW_PRIVS = 38


def drop_privileges() -> None:
    if os.getuid() == 0:
        os.setgroups([])
        os.setresgid(AGENT_UID, AGENT_UID, AGENT_UID)  # gid first: after setuid we could not
        os.setresuid(AGENT_UID, AGENT_UID, AGENT_UID)
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit("[agent] prctl(NO_NEW_PRIVS) failed")
    if os.getuid() == 0 or os.geteuid() == 0:
        sys.exit("[agent] refusing to run as root")
    os.environ["HOME"] = "/home/agent"
    os.chdir("/home/agent")


drop_privileges()

import asyncio  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

from aiohttp import web  # noqa: E402
from strands import Agent, tool  # noqa: E402
from strands.models import BedrockModel  # noqa: E402

MODEL_ID = os.environ.get("MODEL_ID", "us.anthropic.claude-sonnet-4-6")
MAX_READ = 200_000


def _path(rel: str) -> str:
    path = os.path.realpath(os.path.join(WORKSPACE, rel.lstrip("/")))
    if path != WORKSPACE and not path.startswith(WORKSPACE + os.sep):
        raise ValueError(f"路径越界：{rel}")
    return path


def list_workspace() -> list[dict]:
    files = []
    for root, dirs, names in os.walk(WORKSPACE):
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(root, n)
            st = os.stat(p)
            files.append({
                "path": os.path.relpath(p, WORKSPACE),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            })
    return files


def run_shell_command(command: str) -> dict:
    r = subprocess.run(["bash", "-c", command], cwd=WORKSPACE, capture_output=True,
                       text=True, timeout=60)
    return {"exitCode": r.returncode, "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:]}


@tool
def list_files() -> str:
    """列出用户工作区（/mnt/user，即该用户在 S3 上的持久化目录）中的所有文件。"""
    return json.dumps(list_workspace(), ensure_ascii=False)


@tool
def read_file(path: str) -> str:
    """读取工作区中的文本文件。path 为相对于工作区的路径。"""
    with open(_path(path), encoding="utf-8", errors="replace") as f:
        return f.read(MAX_READ)


@tool
def write_file(path: str, content: str) -> str:
    """在工作区中创建或覆盖文本文件，需要时自动创建父目录。path 为相对路径。"""
    p = _path(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return f"已写入 {path}（{len(content)} 字符）"


@tool
def run_shell(command: str) -> str:
    """在工作区目录下执行 bash 命令（以非 root 用户运行，60 秒超时），返回退出码和输出。"""
    return json.dumps(run_shell_command(command), ensure_ascii=False)


SYSTEM_PROMPT = f"""你是一个个人文件助手，运行在 Amazon Bedrock AgentCore Runtime 中。
用户的工作区是 {WORKSPACE}，它是该用户专属的 S3 Files 挂载目录：写入的文件会持久化到 S3，
下次会话（即使换了一台 microVM）依然可见，其他用户看不到。
你可以用 list_files / read_file / write_file / run_shell 工具操作工作区。
你以普通用户（uid {AGENT_UID}）身份运行，没有 root 权限。用中文简洁回答；可以用代码块，不要用表格。"""

agent = Agent(model=BedrockModel(model_id=MODEL_ID), tools=[list_files, read_file, write_file, run_shell],
              system_prompt=SYSTEM_PROMPT, callback_handler=None)
agent_lock = asyncio.Lock()


def sse(obj: dict) -> bytes:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode()


async def chat(request: web.Request, prompt: str) -> web.StreamResponse:
    resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
    await resp.prepare(request)
    seen_tools = set()
    async with agent_lock:  # one conversation per microVM
        try:
            async for event in agent.stream_async(prompt):
                if "data" in event:
                    await resp.write(sse({"type": "text", "text": event["data"]}))
                elif "current_tool_use" in event:
                    t = event["current_tool_use"]
                    if t.get("toolUseId") not in seen_tools and t.get("name"):
                        seen_tools.add(t.get("toolUseId"))
                        await resp.write(sse({"type": "tool", "name": t["name"]}))
        except Exception as e:
            await resp.write(sse({"type": "error", "message": str(e)}))
    await resp.write(sse({"type": "done"}))
    await resp.write_eof()
    return resp


async def invocations(request: web.Request) -> web.StreamResponse:
    payload = await request.json()
    action = payload.get("action", "chat")
    loop = asyncio.get_running_loop()
    try:
        if action == "chat":
            return await chat(request, payload.get("prompt", ""))
        if action == "list_files":
            return web.json_response({"files": await loop.run_in_executor(None, list_workspace)})
        if action == "read_file":
            with open(_path(payload["path"]), encoding="utf-8", errors="replace") as f:
                return web.json_response({"path": payload["path"], "content": f.read(MAX_READ)})
        if action == "exec":
            # Demo / test hook: simulates untrusted code. Same privileges as
            # the agent's run_shell tool (uid AGENT_UID, no root).
            return web.json_response(await loop.run_in_executor(None, run_shell_command, payload["command"]))
        return web.json_response({"error": f"unknown action {action}"}, status=400)
    except (OSError, ValueError, KeyError) as e:
        return web.json_response({"error": str(e)}, status=400)


async def ping(_request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "uid": os.getuid()})


def main() -> None:
    app = web.Application(client_max_size=10 * 1024 * 1024)
    app.router.add_get("/ping", ping)
    app.router.add_post("/invocations", invocations)
    print(json.dumps({"component": "agent", "event": "started", "uid": os.getuid()}), flush=True)
    web.run_app(app, host="127.0.0.1", port=8081, access_log=None)


if __name__ == "__main__":
    main()
