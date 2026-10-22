"use strict";
// Frontend for "per-user S3 Files storage on AgentCore Runtime". Vanilla JS, no build step.
// Flow: Cognito USER_PASSWORD_AUTH -> access token as Bearer -> AgentCore Runtime /invocations.

const cfg = window.APP_CONFIG || {};
const $ = (id) => document.getElementById(id);
const STORE = { auth: "demo.auth", session: "demo.sessionId" };
const REFRESH_MARGIN_MS = 5 * 60 * 1000;
const EXPIRED_MSG = "登录已过期，请重新登录";

const SUGGESTIONS = [
  "在工作区写一个 hello.md，内容是今天的日期和一句问候",
  "列出我工作区里的所有文件",
  "执行 whoami 和 id，再试试读取 /root/.aws/credentials",
  "看看 /mnt/user 的挂载信息（mount | grep /mnt/user）",
];

const state = {
  gen: 0,          // bumped on every new session; async results from older sessions are dropped
  status: null,    // last status/rotate response
  busy: false,     // a chat stream is in flight
  abort: null,     // AbortController of the in-flight chat
  progressTimer: null,
};

class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// ---------------------------------------------------------------- Cognito auth (no SDK)

const COGNITO_ERRORS = {
  NotAuthorizedException: "用户名或密码错误",
  UserNotFoundException: "用户名或密码错误",
  UserNotConfirmedException: "用户尚未确认",
  PasswordResetRequiredException: "该用户需要重置密码",
  TooManyRequestsException: "请求过于频繁，请稍后再试",
  InvalidParameterException: "参数错误（App Client 是否启用了 USER_PASSWORD_AUTH？）",
};

async function cognito(authFlow, authParameters) {
  const res = await fetch(`https://cognito-idp.${cfg.region}.amazonaws.com/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    },
    body: JSON.stringify({ AuthFlow: authFlow, ClientId: cfg.userPoolClientId, AuthParameters: authParameters }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const type = (data.__type || "").split("#").pop();
    throw new ApiError(COGNITO_ERRORS[type] || data.message || `Cognito 错误（HTTP ${res.status}）`, res.status);
  }
  if (data.ChallengeName) throw new ApiError("该用户需要先设置永久密码（请用 scripts/add_user.sh 创建用户）");
  return data.AuthenticationResult;
}

function decodeJwt(token) {
  const b64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

function saveAuth(result, previousRefreshToken) {
  const claims = decodeJwt(result.AccessToken);
  const auth = {
    accessToken: result.AccessToken,  // AccessToken (not IdToken) is what the Runtime JWT authorizer validates
    refreshToken: result.RefreshToken || previousRefreshToken,  // REFRESH_TOKEN_AUTH returns no new one
    expiresAt: claims.exp * 1000,
    username: claims.username,
  };
  sessionStorage.setItem(STORE.auth, JSON.stringify(auth));
  return auth;
}

const getAuth = () => JSON.parse(sessionStorage.getItem(STORE.auth) || "null");

async function refreshTokens() {
  const auth = getAuth();
  if (!auth) throw new ApiError(EXPIRED_MSG, 401);
  try {
    return saveAuth(await cognito("REFRESH_TOKEN_AUTH", { REFRESH_TOKEN: auth.refreshToken }), auth.refreshToken);
  } catch {
    throw new ApiError(EXPIRED_MSG, 401);
  }
}

async function getAccessToken() {
  const auth = getAuth();
  if (!auth) throw new ApiError(EXPIRED_MSG, 401);
  if (auth.expiresAt - Date.now() < REFRESH_MARGIN_MS) return (await refreshTokens()).accessToken;
  return auth.accessToken;
}

// ---------------------------------------------------------------- Runtime session + invoke

const getSessionId = () => sessionStorage.getItem(STORE.session);

function newSessionId() {
  // AgentCore requires session ids of >= 33 chars; a new id means a new microVM.
  const id = "s-" + crypto.randomUUID();
  sessionStorage.setItem(STORE.session, id);
  return id;
}

async function invoke(payload, signal, retried = false) {
  const url = `https://bedrock-agentcore.${cfg.region}.amazonaws.com/runtimes/` +
    `${encodeURIComponent(cfg.runtimeArn)}/invocations?qualifier=DEFAULT`;
  const res = await fetch(url, {
    method: "POST",
    signal,
    headers: {
      Authorization: `Bearer ${await getAccessToken()}`,
      "Content-Type": "application/json",
      "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": getSessionId(),
    },
    body: JSON.stringify(payload),
  });
  if (res.ok) return res;

  // Gateway errors are {"error": ...}; AgentCore's own errors are {"message": ...}.
  const text = await res.text();
  let msg = text;
  try { const j = JSON.parse(text); msg = j.error || j.message || j.Message || text; } catch { /* plain text */ }

  if (res.status === 403 && /another user/i.test(msg)) throw new ApiError("该会话属于其他用户（gateway 拒绝）", 403);
  if (res.status === 401 || res.status === 403) {
    if (!retried) { await refreshTokens(); return invoke(payload, signal, true); }
    throw new ApiError(`鉴权失败（HTTP ${res.status}）：${msg}。请重新登录后再试`, res.status);
  }
  throw new ApiError(msg || `HTTP ${res.status}`, res.status);
}

// AgentCore hides non-2xx bodies from the container (it answers 424), so the
// gateway reports business errors as HTTP 200 + {"error", "status"}.
function gatewayError(j) {
  if (/another user/i.test(j.error)) return new ApiError("该会话属于其他用户（gateway 拒绝）", 403);
  return new ApiError(j.error, j.status);
}

async function invokeJson(payload) {
  const j = await (await invoke(payload)).json();
  if (j && j.error) throw gatewayError(j);
  return j;
}

// Parse a text/event-stream body: events separated by "\n\n", payload lines start with "data: ".
async function readSSE(res, onEvent) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  const flush = (chunk) => {
    for (const line of chunk.split("\n")) {
      if (!line.startsWith("data: ")) continue;
      try { onEvent(JSON.parse(line.slice(6))); } catch (e) { console.warn("bad SSE line", line, e); }
    }
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
    const parts = buf.split("\n\n");
    buf = parts.pop();
    parts.forEach(flush);
  }
  if (buf.trim()) flush(buf);
}

// ---------------------------------------------------------------- Small helpers

function el(tag, cls, children) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  for (const c of [].concat(children ?? [])) e.append(c);  // strings become text nodes (safe)
  return e;
}

const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (iso) => new Date(iso).toLocaleString("zh-CN", { hour12: false });

function humanSize(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${units[i]}`;
}

const rtf = new Intl.RelativeTimeFormat("zh-CN", { numeric: "auto" });
function relTime(iso) {
  const s = (new Date(iso) - Date.now()) / 1000;
  const a = Math.abs(s);
  if (a < 60) return rtf.format(Math.round(s), "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}

function flash(node) {
  node.classList.remove("flash");
  void node.offsetWidth;  // restart the CSS animation
  node.classList.add("flash");
}

function showError(id, msg) {
  $(id).textContent = msg || "";
  $(id).hidden = !msg;
}

// ---------------------------------------------------------------- Status panel

function resetPanel() {
  state.status = null;
  for (const id of ["st-mount", "st-s3prefix", "st-ap", "st-fs", "st-uid", "st-akid", "st-exp", "st-rotations", "st-last-rotation"]) {
    $(id).textContent = "—";
  }
  $("st-countdown").textContent = "";
  $("mount-done").hidden = true;
  showError("st-error", "");
  $("file-list").replaceChildren();
  $("files-empty").hidden = true;
}

function renderStatus(s) {
  state.status = s;
  const c = s.credentials || {};
  $("st-mount").textContent = s.mounted ? `${s.mountPoint} ✅ 已挂载` : "❌ 未挂载";
  $("st-s3prefix").textContent = s.s3Prefix || "—";
  $("st-s3prefix").title = s.s3Prefix || "";
  $("st-mapping").textContent = s.username
    ? `${s.username} → ${s.rootPath ? "/users/" + s.userKey.slice(0, 8) + "…" : "?"}（${s.storageStatus === "active" ? "已开通" : s.storageStatus}）`
    : "—";
  $("st-mapping").title = "DynamoDB 映射表：开户时由控制面写入，broker 只读";
  $("st-ap").textContent = s.accessPointId || "—";
  $("st-ap").title = s.rootPath ? `根目录 ${s.rootPath}` : "";
  $("st-fs").textContent = s.fileSystemId || "—";
  $("st-uid").textContent = s.agentUid === 0 ? "uid 0（root！）" : `uid ${s.agentUid}（非 root）`;
  $("st-akid").textContent = c.accessKeyId || "—";
  $("st-exp").textContent = c.expiration ? fmtTime(c.expiration) : "—";
  $("st-rotations").textContent = c.rotations ?? "—";
  $("st-last-rotation").textContent = c.lastRotation ? fmtTime(c.lastRotation) : "—";
  showError("st-error", c.lastError ? `上次轮换失败：${c.lastError}` : "");
  tickCountdown();
}

function tickCountdown() {
  const exp = state.status?.credentials?.expiration;
  const node = $("st-countdown");
  if (!exp) { node.textContent = ""; return; }
  const left = Math.floor((new Date(exp) - Date.now()) / 1000);
  node.textContent = left > 0 ? `还剩 ${pad(Math.floor(left / 60))}:${pad(left % 60)}` : "已过期";
  node.classList.toggle("warn", left < 300);
}

async function loadStatus() {
  const gen = state.gen;
  const t0 = Date.now();
  const secs = () => Math.round((Date.now() - t0) / 1000);
  const tick = () => {
    $("mount-progress-text").textContent = `正在唤醒 microVM，申请 STS 凭证并挂载你的 S3 存储… ${secs()} 秒`;
  };
  clearInterval(state.progressTimer);
  tick();
  state.progressTimer = setInterval(tick, 1000);
  $("mount-progress").hidden = false;
  $("mount-done").hidden = true;
  try {
    const s = await invokeJson({ action: "status" });
    if (gen !== state.gen) return;
    renderStatus(s);
    $("mount-done").textContent = s.mounted ? `已挂载，用时 ${secs()} 秒` : `未挂载（用时 ${secs()} 秒）`;
    $("mount-done").hidden = false;
  } catch (e) {
    if (gen === state.gen) showError("st-error", `获取状态失败：${e.message}`);
  } finally {
    if (gen === state.gen) {
      clearInterval(state.progressTimer);
      $("mount-progress").hidden = true;
    }
  }
}

async function rotate() {
  const btn = $("rotate-btn");
  const prevKey = state.status?.credentials?.accessKeyId;
  btn.disabled = true;
  btn.textContent = "轮换中…";
  try {
    const s = await invokeJson({ action: "rotate" });
    renderStatus(s);
    if (s.credentials?.accessKeyId !== prevKey) flash($("st-akid"));
  } catch (e) {
    showError("st-error", `轮换失败：${e.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "立即轮换 STS 凭证";
  }
}

// ---------------------------------------------------------------- Files

async function loadFiles() {
  const gen = state.gen;
  const btn = $("refresh-files-btn");
  btn.disabled = true;
  try {
    const { files = [] } = await invokeJson({ action: "list_files" });
    if (gen === state.gen) renderFiles(files);
  } catch (e) {
    if (gen === state.gen) $("file-list").replaceChildren(el("li", "error-text", `加载文件失败：${e.message}`));
  } finally {
    btn.disabled = false;
  }
}

function renderFiles(files) {
  const prefix = state.status?.s3Prefix || "";
  $("files-empty").hidden = files.length > 0;
  $("file-list").replaceChildren(...[...files].sort((a, b) => a.path.localeCompare(b.path)).map((f) => {
    const li = el("li", "file", [
      el("div", "file-main", [
        el("span", "file-path", `📄 ${f.path}`),
        el("span", "file-meta", `${humanSize(f.size)} · ${relTime(f.mtime)}`),
      ]),
      el("div", "file-key", prefix + f.path),
    ]);
    li.title = "点击预览";
    li.onclick = () => openPreview(f.path);
    return li;
  }));
}

async function openPreview(path) {
  $("preview-path").textContent = path;
  $("preview-content").textContent = "加载中…";
  $("preview-modal").hidden = false;
  try {
    const r = await invokeJson({ action: "read_file", path });
    $("preview-content").textContent = r.content;
  } catch (e) {
    $("preview-content").textContent = `读取失败：${e.message}`;
  }
}

// ---------------------------------------------------------------- Chat

function addBubble(role, content) {
  const b = el("div", `bubble ${role}`, content);
  $("messages").append(b);
  b.scrollIntoView({ block: "end" });
  return b;
}

// Minimal safe Markdown via DOM nodes, never innerHTML: ``` blocks, # headings,
// --- rules, **bold** and `code`.
function renderInline(text) {
  return text.split(/(\*\*[^*\n]+\*\*|`[^`\n]+`)/).map((part, i) => {
    if (i % 2 === 0) return part;
    return part.startsWith("**") ? el("strong", null, part.slice(2, -2)) : el("code", null, part.slice(1, -1));
  });
}

function renderRich(text) {
  return text.split(/```[^\n]*\n?/).flatMap((chunk, i) => {
    if (i % 2 === 1) return [el("pre", "codeblock", chunk.replace(/\n$/, ""))];
    return chunk.split(/(^#{1,6} .*$|^-{3,}$)/m).flatMap((part, j) => {
      if (j % 2 === 0) return renderInline(part);
      if (part.startsWith("#")) return [el("div", "md-heading", renderInline(part.replace(/^#+ /, "")))];
      return [el("hr")];
    });
  });
}

function renderAssistant(bubble, segs) {
  if (!segs.length) { bubble.replaceChildren(el("span", "typing", "思考中")); return; }
  bubble.replaceChildren(...segs.flatMap((s) =>
    s.tool ? [el("span", "chip", `🔧 ${s.tool}`)]
      : s.error ? [el("div", "inline-error", `⚠️ ${s.error}`)]
      : renderRich(s.text)));
  bubble.scrollIntoView({ block: "end" });
}

function setBusy(busy) {
  state.busy = busy;
  $("send-btn").disabled = busy;
  $("send-btn").textContent = busy ? "生成中…" : "发送";
}

async function sendPrompt(text) {
  if (state.busy || !text.trim()) return;
  const gen = state.gen;
  $("suggestions").hidden = true;
  $("chat-input").value = "";
  addBubble("user", text);
  const bubble = addBubble("assistant");
  const segs = [];
  renderAssistant(bubble, segs);
  setBusy(true);
  state.abort = new AbortController();
  try {
    const res = await invoke({ action: "chat", prompt: text }, state.abort.signal);
    if (!(res.headers.get("content-type") || "").includes("text/event-stream")) {
      const j = await res.json().catch(() => ({}));
      throw j.error ? gatewayError(j) : new ApiError(j.message || "意外的响应格式");
    }
    await readSSE(res, (ev) => {
      if (gen !== state.gen) return;
      const last = segs[segs.length - 1];
      if (ev.type === "text") {
        if (last && last.text !== undefined) last.text += ev.text;
        else segs.push({ text: ev.text });
      } else if (ev.type === "tool") segs.push({ tool: ev.name });
      else if (ev.type === "error") segs.push({ error: ev.message });
      else return;  // "done" and unknown types: nothing to draw
      renderAssistant(bubble, segs);
    });
    if (!segs.length) segs.push({ text: "（无输出）" });
  } catch (e) {
    if (gen !== state.gen) return;  // aborted by "new session"
    if (!segs.length) bubble.classList.add("error");
    segs.push({ error: e.message });
  } finally {
    if (gen === state.gen) {
      renderAssistant(bubble, segs);
      setBusy(false);
      loadFiles();  // the agent may have written files
    }
  }
}

function renderSuggestions() {
  $("suggestions").replaceChildren(...SUGGESTIONS.map((s) => {
    const chip = el("button", "suggestion", s);
    chip.type = "button";
    chip.onclick = () => sendPrompt(s);
    return chip;
  }));
  $("suggestions").hidden = false;
}

// ---------------------------------------------------------------- Views

function showSessionId() {
  const id = getSessionId();
  $("session-id").textContent = `${id.slice(0, 10)}…${id.slice(-4)}`;
  $("session-id").title = id;
}

async function startSession(note) {
  state.gen++;
  state.abort?.abort();
  setBusy(false);
  showSessionId();
  $("messages").replaceChildren();
  if (note) $("messages").append(el("div", "note", note));
  renderSuggestions();
  resetPanel();
  await loadStatus();  // first call wakes the microVM and mounts storage; run it before list_files
  await loadFiles();
}

function showApp() {
  $("login-view").hidden = true;
  $("app-view").hidden = false;
  $("user-name").textContent = getAuth().username;
  startSession();
}

function showLogin(error) {
  $("app-view").hidden = true;
  $("login-view").hidden = false;
  showError("login-error", error);
}

function setSidebar(open) {
  document.body.classList.toggle("sidebar-open", open);
}

function init() {
  if (!cfg.region || !cfg.userPoolClientId || !cfg.runtimeArn) {
    showLogin("缺少 config.js（参考 config.example.js，部署脚本会自动生成）");
    $("login-btn").disabled = true;
    return;
  }

  $("login-form").onsubmit = async (e) => {
    e.preventDefault();
    const btn = $("login-btn");
    btn.disabled = true;
    btn.textContent = "登录中…";
    showError("login-error", "");
    try {
      saveAuth(await cognito("USER_PASSWORD_AUTH", {
        USERNAME: $("login-username").value.trim(),
        PASSWORD: $("login-password").value,
      }));
      newSessionId();
      $("login-password").value = "";
      showApp();
    } catch (err) {
      showError("login-error", err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = "登录";
    }
  };

  $("logout-btn").onclick = () => { sessionStorage.clear(); location.reload(); };
  $("new-session-btn").onclick = () => {
    newSessionId();
    startSession("已切换到新会话 = 新的 microVM。之前写入的文件仍在 S3 中，看看右侧文件列表。");
  };

  $("chat-form").onsubmit = (e) => { e.preventDefault(); sendPrompt($("chat-input").value); };
  $("chat-input").onkeydown = (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); sendPrompt(e.target.value); }
  };

  $("sidebar-toggle").onclick = () => setSidebar(!document.body.classList.contains("sidebar-open"));
  $("sidebar-close").onclick = () => setSidebar(false);
  setSidebar(window.matchMedia("(min-width: 1100px)").matches);

  $("rotate-btn").onclick = rotate;
  $("refresh-files-btn").onclick = loadFiles;
  $("copy-s3-btn").onclick = async () => {
    if (!state.status?.s3Prefix) return;
    await navigator.clipboard.writeText(state.status.s3Prefix);
    flash($("st-s3prefix"));
  };

  const closePreview = () => { $("preview-modal").hidden = true; };
  $("preview-close").onclick = closePreview;
  $("preview-modal").onclick = (e) => { if (e.target.id === "preview-modal") closePreview(); };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePreview(); });

  setInterval(tickCountdown, 1000);

  if (getAuth() && getSessionId()) showApp();
  else showLogin();
}

init();
