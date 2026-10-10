#!/usr/bin/env python3
"""
OpenAI 账号降级探测工具

原理（逆向自 help.openai.com 客服 ChatKit 组件）:
  1. POST /api/v1/chatkit  threads.create        —— 首条消息发送邮箱
  2. 机器人返回 email_collection 组件要求再次提交邮箱
  3. POST /api/v1/chatkit  threads.custom_action —— register-logged-out-email 二次提交
  4. 读取机器人回复 SSE 流, 命中 "limited" + "Terms of Use" 关键字 → 账号被降级

x-session-id 是 help.openai.com 服务端签发的签名令牌 (v1.<uuid>.<sig>),
嵌入在页面 HTML 的 React hydration 数据里 (sessionIdToken 字段)。
获取它需要真实浏览器过 Cloudflare —— 用持久化 Chrome profile,
之后令牌可缓存复用直到过期。

用法:
  ./check_degrade.py someone@example.com
  ./check_degrade.py --file emails.txt
  ./check_degrade.py --session-id 'v1.xxxx.yyyy' someone@example.com
  cat emails.txt | ./check_degrade.py --stdin
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import uuid

API = "https://support.api.openai.com/api/v1/chatkit"
PAGE_URL = "https://help.openai.com/en"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSION_FILE = os.path.join(BASE_DIR, "session.json")
PROFILE_DIR = os.path.join(BASE_DIR, ".chrome-profile")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36")

EMAIL_RE = re.compile(r"[^\s@:,;|\"'<>]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_email(line):
    """Extract the email from a line; supports 'email----password' / 'email:password'."""
    cand = re.split(r"-{2,}|\t", line.strip(), maxsplit=1)[0]
    m = EMAIL_RE.search(cand)
    return m.group(0) if m else None


SIG_RE = re.compile(r'"sessionIdToken"\s*,\s*"(v1\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+)"')
SIG_RE2 = re.compile(r'v1\.[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]{20,}')
DEGRADED_RE = re.compile(r"limited", re.I)
TOS_RE = re.compile(r"terms of use|policies/terms", re.I)
BANNED_RE = re.compile(
    r"deactivat|suspend|unable to take further action|case is now closed"
    r"|appeal process|will not respond|permanently (closed|disabled|banned)"
    r"|account.{0,30}(disabled|closed|terminated)", re.I)

GREEN, RED, YELLOW, GRAY, BOLD, NC = ("\033[32m", "\033[31m", "\033[33m",
                                      "\033[90m", "\033[1m", "\033[0m")
if not sys.stdout.isatty():
    GREEN = RED = YELLOW = GRAY = BOLD = NC = ""


def log(msg):
    print(f"{GRAY}[*]{NC} {msg}", file=sys.stderr)


# ---------------------------------------------------------------- session --

def load_cached_session():
    try:
        with open(SESSION_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def save_session(sess):
    with open(SESSION_FILE, "w") as f:
        json.dump(sess, f, indent=2)


def extract_token(html):
    m = SIG_RE.search(html) or SIG_RE2.search(html)
    if not m:
        return None
    tok = m.group(1) if m.lastindex else m.group(0)
    return tok


def bootstrap_via_cookies(cookies):
    """Fast path: reuse cf_clearance cookie from a previous browser run."""
    log("尝试用缓存的 cf cookie 直接取 sessionIdToken ...")
    req = urllib.request.Request(PAGE_URL)
    req.add_header("user-agent", UA)
    req.add_header("cookie", cookies)
    try:
        html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
    except Exception as e:
        log(f"cookie 路径失败: {e}")
        return None
    tok = extract_token(html)
    if tok:
        log("cookie 路径成功拿到 sessionIdToken")
    return tok


def bootstrap_via_browser(headless=False):
    """Real Chrome + persistent profile -> pass CF -> scrape sessionIdToken."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("缺少 playwright: uv pip install playwright (本目录 .venv 已装)")

    log(f"启动 Chrome ({'headless' if headless else 'headed'}) 过 Cloudflare ...")
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            PROFILE_DIR, channel="chrome", headless=headless,
            viewport={"width": 1280, "height": 900},
            args=["--disable-blink-features=AutomationControlled",
                  "--window-position=40,40"],
        )
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(PAGE_URL, wait_until="domcontentloaded", timeout=60000)
            passed = False
            for _ in range(90):
                t = page.title() or ""
                if t and "moment" not in t.lower() and "请稍候" not in t \
                        and "challenge" not in t.lower():
                    passed = True
                    break
                # CF turnstile iframe: click the checkbox area
                for f in page.frames:
                    if "challenges.cloudflare.com" in f.url or "turnstile" in f.url:
                        try:
                            f.locator("body").click(
                                position={"x": 25, "y": 25},
                                force=True, timeout=800)
                        except Exception:
                            pass
                page.wait_for_timeout(1000)
            if not passed:
                log("Cloudflare 90 秒内未放行 (可重试或人工点一下窗口里的验证框)")
            page.wait_for_timeout(3000)
            html = page.content()
            tok = extract_token(html)
            cookies = ctx.cookies(PAGE_URL)
            ctx.close()
        except Exception:
            ctx.close()
            raise
    if not tok:
        return None
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return {"token": tok, "cookies": cookie_str}


def session_uuid(tok):
    m = re.match(r"v1\.([0-9a-fA-F-]{36})\.", tok)
    return m.group(1) if m else str(uuid.uuid4())


def ensure_session(args):
    """Resolve a usable x-session-id token."""
    if args.session_id:
        tok = args.session_id.strip()
        log("使用命令行传入的 session id")
        return {"token": tok, "cookies": ""}

    cached = load_cached_session()
    if cached and cached.get("cookies"):
        tok = bootstrap_via_cookies(cached["cookies"])
        if tok:
            cached["token"] = tok
            cached["saved_at"] = time.time()
            save_session(cached)
            return cached
        # cookie expired -> fall through to browser
    if cached and cached.get("token") and not args.refresh:
        log("使用缓存的 session token (失效时会自动重新获取)")
        return cached

    sess = bootstrap_via_browser(headless=args.headless)
    if not sess and not args.headless:
        log("headed 失败,再试一次 headless ...")
        sess = bootstrap_via_browser(headless=True)
    if not sess:
        sys.exit("无法获取 sessionIdToken。可用 --session-id 手动传入 "
                 "(DevTools -> Network -> 任意 support.api.openai.com 请求头里的 x-session-id)")
    sess["saved_at"] = time.time()
    save_session(sess)
    return sess


# ------------------------------------------------------------ chatkit api --

class SessionInvalid(Exception):
    pass


def post_chatkit(payload, sess, extra_headers=None, timeout=90):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(API, data=body, method="POST")
    req.add_header("accept", "text/event-stream")
    req.add_header("content-type", "application/json")
    req.add_header("origin", "https://help.openai.com")
    req.add_header("referer", "https://help.openai.com/")
    req.add_header("user-agent", UA)
    req.add_header("chatkit-frame-instance-id", sess.get("frame_id") or str(uuid.uuid4()))
    req.add_header("x-chatkit-locale", "en-US")
    req.add_header("x-chatkit-version", "rc2")
    req.add_header("x-current-page", "https://help.openai.com/en")
    req.add_header("x-help-center-session-id", session_uuid(sess["token"]))
    req.add_header("x-session-id", sess["token"])
    req.add_header("x-support-chat-login-nudge-variant", "treatment")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "ignore")
        if "x-session-id" in msg or e.code in (401, 403):
            if "session" in msg.lower():
                raise SessionInvalid(msg)
        raise RuntimeError(f"HTTP {e.code}: {msg[:300]}")


def read_sse(resp):
    buf = b""
    while True:
        chunk = resp.read(4096)
        if not chunk:
            break
        buf += chunk
        while b"\n\n" in buf:
            block, buf = buf.split(b"\n\n", 1)
            for line in block.split(b"\n"):
                if line.startswith(b"data:"):
                    data = line[5:].strip()
                    if data and data != b"[DONE]":
                        try:
                            yield json.loads(data)
                        except json.JSONDecodeError:
                            pass


def item_text(item):
    return "".join(c.get("text", "") for c in item.get("content", [])
                   if isinstance(c, dict))


def create_thread(email, sess):
    """Step 1: send the email as first message; returns (thread_id, widget_item_id)."""
    resp = post_chatkit(
        {"type": "threads.create",
         "params": {"input": {"content": [{"type": "input_text", "text": email}],
                              "quoted_text": "", "attachments": [],
                              "inference_options": {}}}},
        sess,
        {"x-customer-agents-chat-create-id": str(uuid.uuid4())},
    )
    thread_id = widget_id = None
    for ev in read_sse(resp):
        if ev["type"] == "thread.created":
            thread_id = ev["thread"]["id"]
        elif ev["type"] == "thread.item.done" and ev["item"].get("type") == "widget":
            widget_id = ev["item"]["id"]
    if not (thread_id and widget_id):
        raise RuntimeError("threads.create 未返回邮箱采集组件")
    return thread_id, widget_id


def register_email_and_read_reply(email, thread_id, widget_id, sess):
    """Step 2: submit email via custom_action; collect assistant reply text."""
    resp = post_chatkit(
        {"type": "threads.custom_action",
         "params": {"item_id": widget_id,
                    "action": {"type": "register-logged-out-email",
                               "payload": {"email": email}},
                    "thread_id": thread_id}},
        sess, timeout=120)
    replies, deltas = [], {}
    for ev in read_sse(resp):
        t = ev.get("type")
        if t == "thread.item.done" and ev["item"].get("type") == "assistant_message":
            replies.append(item_text(ev["item"]))
        elif t == "thread.item.updated":
            upd = ev.get("update", {})
            # accumulate streamed text deltas keyed by item
            iid = ev.get("item_id", "")
            for key in ("text", "delta"):
                if isinstance(upd.get(key), str):
                    deltas[iid] = deltas.get(iid, "") + upd[key]
    if not replies and deltas:
        replies = list(deltas.values())
    return "\n".join(x for x in replies if x)


def judge(reply):
    """Returns 'banned' | 'degraded' | 'normal'; None if no reply."""
    if not reply:
        return None
    if BANNED_RE.search(reply):
        return "banned"
    if DEGRADED_RE.search(reply) and TOS_RE.search(reply):
        return "degraded"
    if re.search(r"temporarily limited|access[^.]*limited", reply, re.I):
        return "degraded"
    return "normal"


def check_email(email, sess):
    thread_id, widget_id = create_thread(email, sess)
    reply = register_email_and_read_reply(email, thread_id, widget_id, sess)
    return {"email": email, "thread": thread_id, "reply": reply,
            "status": judge(reply)}


# ------------------------------------------------------------------- main --

def main():
    ap = argparse.ArgumentParser(description="OpenAI 账号降级探测 (help.openai.com 客服机器人)")
    ap.add_argument("emails", nargs="*", help="待检测邮箱")
    ap.add_argument("--file", "-f", help="邮箱列表文件, 一行一个")
    ap.add_argument("--stdin", action="store_true", help="从 stdin 读邮箱")
    ap.add_argument("--session-id", help="手动传入 x-session-id (跳过浏览器)")
    ap.add_argument("--refresh", action="store_true", help="强制重新获取 session")
    ap.add_argument("--headless", action="store_true", help="bootstrap 时用无头模式")
    ap.add_argument("--delay", type=float, default=1.5, help="每个邮箱之间的间隔秒数")
    ap.add_argument("--json", action="store_true", help="输出 JSON 结果")
    ap.add_argument("--verbose", "-v", action="store_true", help="打印机器人完整回复")
    args = ap.parse_args()

    emails = []
    for src in list(args.emails):
        e = extract_email(src)
        if e:
            emails.append(e)
    if args.file:
        for l in open(args.file):
            e = extract_email(l)
            if e:
                emails.append(e)
    if args.stdin or (not emails and not sys.stdin.isatty()):
        for l in sys.stdin:
            e = extract_email(l)
            if e:
                emails.append(e)
    emails = list(dict.fromkeys(emails))
    if not emails:
        ap.error("没有待检测的邮箱")

    sess = ensure_session(args)
    log(f"session: {sess['token'][:44]}...")

    results = []
    for i, email in enumerate(emails):
        try:
            r = check_email(email, sess)
        except SessionInvalid:
            log("session 失效,重新 bootstrap ...")
            sess = ensure_session(argparse.Namespace(**{**vars(args), "session_id": None, "refresh": True}))
            r = check_email(email, sess)
        except Exception as e:
            r = {"email": email, "status": None, "reply": "", "error": str(e)}
        results.append(r)

        if args.json:
            continue
        tag = {"banned": f"{RED}封号",
               "degraded": f"{RED}降智",
               "normal": f"{GREEN}正常"}.get(r.get("status"), f"{YELLOW}未知")
        first_line = (r.get("reply") or r.get("error") or "").splitlines()
        snippet = first_line[0][:90] if first_line else ""
        print(f"{tag}{NC}  {email:42s} {GRAY}{snippet}{NC}")
        if args.verbose and r.get("reply"):
            for ln in r["reply"].splitlines():
                print(f"      {GRAY}{ln}{NC}")
        if i < len(emails) - 1:
            time.sleep(args.delay)

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))

    n_ban = sum(1 for r in results if r.get("status") == "banned")
    n_deg = sum(1 for r in results if r.get("status") == "degraded")
    n_ok = sum(1 for r in results if r.get("status") == "normal")
    n_unk = len(results) - n_ban - n_deg - n_ok
    print(f"\n{BOLD}汇总:{NC} 共 {len(results)} | {RED}封号 {n_ban}{NC} | "
          f"{RED}降智 {n_deg}{NC} | {GREEN}正常 {n_ok}{NC} | {YELLOW}未知 {n_unk}{NC}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
