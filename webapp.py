#!/usr/bin/env python3
"""
Web 前端: OpenAI 账号状态批量检测 (降智/封号/正常)

启动:  ./.venv/bin/python webapp.py [--port 8000]
打开:  http://127.0.0.1:8000

检测逻辑复用 check_degrade.py。session 获取顺序:
  缓存 cf cookie -> 缓存 token -> 无头 Chrome -> (手动触发) 有头 Chrome
"""
import argparse
import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlparse, parse_qs

import check_degrade as cd

BASE = os.path.dirname(os.path.abspath(__file__))
INDEX_HTML = os.path.join(BASE, "index.html")

JOBS = {}          # job_id -> dict
JOBS_LOCK = threading.Lock()
SESS = None        # {"token": ..., "cookies": ...}
SESS_LOCK = threading.Lock()


def log(msg):
    print(f"[*] {msg}", flush=True)


# ----------------------------------------------------------------- session --

def obtain_session(headed=False):
    """Return session dict or None. headed=True forces visible-Chrome bootstrap."""
    cached = cd.load_cached_session() or {}
    if not headed:
        if cached.get("cookies"):
            tok = cd.bootstrap_via_cookies(cached["cookies"])
            if tok:
                cached["token"] = tok
                cached["saved_at"] = time.time()
                cd.save_session(cached)
                return cached
        if cached.get("token"):
            return cached
    try:
        sess = cd.bootstrap_via_browser(headless=not headed)
    except Exception as e:
        log(f"bootstrap_via_browser 异常: {e}")
        sess = None
    if sess:
        sess["saved_at"] = time.time()
        cd.save_session(sess)
    return sess


def get_session(refresh=False, headed=False):
    global SESS
    with SESS_LOCK:
        if SESS is None or refresh:
            s = obtain_session(headed=headed)
            if s:
                SESS = s
    return SESS


def session_info():
    with SESS_LOCK:
        s = SESS
    cached = cd.load_cached_session() or {}
    tok = (s or cached).get("token")
    return {"ready": bool(tok),
            "token_prefix": tok[:40] + "..." if tok else None,
            "saved_at": (s or cached).get("saved_at")}


# -------------------------------------------------------------------- jobs --

def run_check(email, delay=0.0):
    t0 = time.time()
    sess = get_session()
    if not sess:
        return {"email": email, "status": "error",
                "error": "session 未就绪", "ms": 0}
    try:
        r = cd.check_email(email, sess)
    except cd.SessionInvalid:
        log("session 失效,自动重新获取 ...")
        sess = get_session(refresh=True)
        if not sess:
            return {"email": email, "status": "error",
                    "error": "session 重新获取失败", "ms": int((time.time() - t0) * 1000)}
        try:
            r = cd.check_email(email, sess)
        except Exception as e:
            return {"email": email, "status": "error",
                    "error": str(e), "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"email": email, "status": "error",
                "error": str(e), "ms": int((time.time() - t0) * 1000)}
    return {"email": email, "status": r["status"] or "unknown",
            "reply": r.get("reply", ""), "thread": r.get("thread", ""),
            "ms": int((time.time() - t0) * 1000)}


def run_job(job_id, emails, concurrency, delay):
    job = JOBS[job_id]
    job["status"] = "running"

    def work(email):
        with JOBS_LOCK:
            job["inflight"].append(email)
        try:
            res = run_check(email)
        finally:
            with JOBS_LOCK:
                job["inflight"] = [e for e in job["inflight"] if e != email]
        with JOBS_LOCK:
            job["results"].append(res)
            job["done"] = len(job["results"])
        if delay:
            time.sleep(delay)

    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 8))) as ex:
        list(ex.map(work, emails))
    job["status"] = "done"


# ------------------------------------------------------------------ http --

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("content-type", ctype + ("; charset=utf-8" if ctype.startswith(("application/json", "text")) else ""))
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n) if n else b"{}"
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def log_message(self, *a):
        pass  # quiet

    def do_GET(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)
        if path == "/":
            with open(INDEX_HTML, "rb") as f:
                self._send(200, f.read(), "text/html")
        elif path == "/api/session":
            self._send(200, session_info())
        elif path == "/api/job":
            jid = (qs.get("id") or [""])[0]
            job = JOBS.get(jid)
            if not job:
                self._send(404, {"error": "job not found"})
            else:
                with JOBS_LOCK:
                    self._send(200, {"id": jid, "status": job["status"],
                                     "total": job["total"], "done": job["done"],
                                     "inflight": job["inflight"],
                                     "results": job["results"]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        global SESS
        path = urlparse(self.path).path
        data = self._body()
        if path == "/api/check":
            emails = []
            for raw in data.get("emails", []):
                e = cd.extract_email(raw)
                if e:
                    emails.append(e)
            emails = list(dict.fromkeys(emails))
            if not emails:
                self._send(400, {"error": "no valid emails"})
                return
            job_id = uuid.uuid4().hex[:12]
            JOBS[job_id] = {"status": "queued", "total": len(emails), "done": 0,
                            "inflight": [], "results": [],
                            "created": time.time()}
            threading.Thread(
                target=run_job,
                args=(job_id, emails, int(data.get("concurrency", 1)),
                      float(data.get("delay", 0))),
                daemon=True).start()
            self._send(200, {"job_id": job_id, "total": len(emails)})
        elif path == "/api/session/refresh":
            headed = bool(data.get("headed"))
            if headed:
                # headed 可能要人工点验证框，放后台，前端轮询状态
                threading.Thread(target=lambda: get_session(refresh=True, headed=True),
                                 daemon=True).start()
                self._send(200, {"ok": True, "async": True})
            else:
                s = obtain_session(headed=False)
                if s:
                    with SESS_LOCK:
                        SESS = s
                    self._send(200, {"ok": True})
                else:
                    self._send(502, {"ok": False,
                                     "error": "自动获取失败，请点「有头模式重试」"})
        else:
            self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", "-p", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"OpenAI 账号检测面板: http://{args.host}:{args.port}")
    print(f"session 状态: {session_info()}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
