"""BlastRadius demo UI. Run: python web.py, then open http://localhost:8000

Live runs go through agent.py (Gemini + MCP). If the live run fails (no key, quota, overload),
the page replays the last recorded real run for that question, clearly labeled as a replay.
Approval is a human click on the page; the server recomputes the draft from the graph itself.
"""
import asyncio
import json
import os
import re
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import agent
import server

HERE = Path(__file__).resolve().parent
PAGE = HERE / "web" / "index.html"
REPLAYS = HERE / "replays.json"  # committed, so a fresh clone can still demo with no key
PORT = int(os.environ.get("PORT", 8000))
SAFE = re.compile(r"^[\w.@:/ -]{1,120}$")  # service / CVE ids from the browser


def norm(q):
    return " ".join(q.lower().split())


def load_replays():
    return json.loads(REPLAYS.read_text(encoding="utf-8")) if REPLAYS.exists() else {}


def save_replay(rec):
    # ponytail: whole-file rewrite, fine for a handful of demo questions
    data = load_replays()
    data[norm(rec["question"])] = rec
    REPLAYS.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")


def pick_replay(q):
    data = load_replays()
    return data.get(norm(q)) or next(iter(data.values()), None)


def graph_stats():
    rows = server.G.ro_query("MATCH (s:Service) WITH count(s) AS s MATCH (v:PackageVersion) WITH s, count(v) AS v "
                             "MATCH (c:CVE) RETURN s, v, count(c)").result_set
    return dict(zip(["services", "versions", "cves"], rows[0]))


def blast(service, cve_id):
    """Path from service to CVE, plus everything downstream of the service by hop (reverse CALLS)."""
    log = []
    cve = server._cve(log, cve_id)
    if not cve:
        return {"error": f"Unknown CVE {cve_id}"}
    path, fixed = server._path(log, service, cve["id"])
    if not path:
        return {"error": f"{service} has no dependency path to {cve['id']}"}
    calls = server._q(log, "MATCH (a:Service)-[:CALLS]->(b:Service) RETURN a.name, b.name")
    callers = {}
    for a, b in calls:
        callers.setdefault(b, []).append(a)
    levels, seen, frontier = [], {service}, [service]
    while frontier:
        frontier = sorted({a for s in frontier for a in callers.get(s, []) if a not in seen})
        seen.update(frontier)
        if frontier:
            levels.append(frontier)
    exposed = sorted(s["service"] for s in server.find_exposed_services(cve["id"]).get("services", []))
    return {"cve": cve, "service": service, "path": path, "fixed": fixed or "", "levels": levels,
            "edges": [[a, b] for a, b in calls if a in seen and b in seen], "exposed": exposed, "cypher": log}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet: only the agent's own prints
        pass

    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path in ("/", "/index.html"):
            return self.reply(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if url.path == "/api/status":
            agent.load_env()
            return self.reply(200, {**graph_stats(), "key": bool(agent.os.environ.get("GEMINI_API_KEY")),
                                    "model": agent.MODEL, "replays": [r["question"] for r in load_replays().values()]})
        if url.path == "/api/blast":
            service, cve = qs.get("service", ""), qs.get("cve", "")
            if not (SAFE.match(service) and SAFE.match(cve)):
                return self.reply(400, {"error": "service and cve are required"})
            res = blast(service, cve)
            return self.reply(400 if "error" in res else 200, res)
        if url.path == "/api/ask":
            return self.ask(qs.get("q", "").strip()[:500])
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/approve":
            return self.reply(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad JSON"})
        service, cve = str(body.get("service", "")), str(body.get("cve", ""))
        if not (SAFE.match(service) and SAFE.match(cve)):
            return self.reply(400, {"error": "service and cve are required"})
        # Recompute from the graph: the browser only says *which* draft, never *what* it says.
        draft = server.draft_remediation(service, cve)
        if "error" in draft:
            return self.reply(400, {"error": draft["error"]})
        filed = agent.approve([draft], out_dir=str(HERE / "remediations"), ask=lambda _: "y")
        self.reply(200, {"file": Path(filed[0]).relative_to(HERE).as_posix()})

    def ask(self, q):
        if not q:
            return self.reply(400, {"error": "Ask a question first."})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def send(event, data):
            self.wfile.write(f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n".encode())
            self.wfile.flush()

        try:
            reason = self.live(q, send)
            if reason is None:
                return
            rec = pick_replay(q)
            if not rec:
                return send("failed", {"message": f"Live run failed ({reason}) and no recorded run exists yet."})
            send("mode", {"mode": "replay", "reason": reason, "model": rec["model"],
                          "recorded_at": rec["recorded_at"], "question": rec["question"]})
            for step in rec["steps"]:
                time.sleep(0.35)  # ponytail: paced so the replay reads like the live run
                send("step", step)
            send("done", {"answer": rec["answer"], "model": rec["model"], "replay": True})
        except ConnectionError:  # broken pipe / reset / aborted (WinError 10053): the browser left
            print("(browser closed the page or started a new run; stream dropped)")

    def live(self, q, send):
        """Stream a live run. Returns None on success, else a short reason to fall back to replay."""
        agent.load_env()
        if not agent.os.environ.get("GEMINI_API_KEY"):
            return "no GEMINI_API_KEY"
        send("mode", {"mode": "live", "model": agent.MODEL})
        steps = []

        def on_step(name, args, result):
            steps.append({"name": name, "args": args, "result": result})
            send("step", steps[-1])

        try:
            res = asyncio.run(agent.run(q, on_step))
        except Exception as e:  # quota, overload, network: the demo must not die
            leaf = e
            while isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:
                leaf = leaf.exceptions[0]  # anyio wraps errors from inside the MCP session
            if isinstance(leaf, ConnectionError):
                raise leaf  # the browser left mid-run; ask() drops the stream quietly
            reason = f"Gemini {leaf.status_code}" if getattr(leaf, "status_code", None) else str(leaf)[:80] or type(leaf).__name__
            print(f"(live run failed: {reason}; falling back to replay)")
            if not getattr(leaf, "status_code", None):
                traceback.print_exception(leaf)  # unexpected: keep the detail
            return reason
        save_replay({"question": q, "model": res["model"], "recorded_at": time.strftime("%Y-%m-%d %H:%M"),
                     "steps": steps, "answer": res["answer"]})
        send("done", {"answer": res["answer"], "model": res["model"], "replay": False})
        return None


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(f"BlastRadius demo on http://localhost:{PORT}")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")
