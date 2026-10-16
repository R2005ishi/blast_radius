"""BlastRadius bench: independent ground truth vs server.py tools, plus optional agent tool selection.

Usage:
  python bench.py           # tool accuracy (no API key needed); exit 1 on any mismatch
  python bench.py --agent   # also agent tool selection (needs GEMINI_API_KEY)
"""
import asyncio
import contextlib
import io
import os
import sys
from collections import defaultdict, deque

import server  # tool functions are plain callables; server.G is the same graph

DEMO_CVE = "GHSA-hrpp-h998-j3pp"


def bfs(start, adj):
    """Hop count from start to every reachable node."""
    dist, todo = {start: 0}, deque([start])
    while todo:
        n = todo.popleft()
        for m in adj[n]:
            if m not in dist:
                dist[m] = dist[n] + 1
                todo.append(m)
    return dist


def ground_truth():
    # Raw edges only; everything else is computed here, not by Cypher.
    rows = server.G.ro_query("MATCH (a)-[r]->(b) RETURN coalesce(a.id, a.name), type(r), coalesce(b.id, b.name)").result_set
    dep, calls_rev, affected_by, edges = defaultdict(set), defaultdict(set), defaultdict(set), set()
    for a, t, b in rows:
        edges.add((a, t, b))
        if t == "DEPENDS_ON":
            dep[a].add(b)
        elif t == "CALLS":
            calls_rev[b].add(a)  # who calls b
        elif t == "AFFECTED_BY":
            affected_by[b].add(a)  # cve -> vulnerable versions
    services = [r[0] for r in server.G.ro_query("MATCH (s:Service) RETURN s.name").result_set]
    sev = {c: float(s or 0) for c, s in server.G.ro_query("MATCH (c:CVE) RETURN c.id, c.severity").result_set}

    down = {s: set(bfs(s, calls_rev)) - {s} for s in services}
    exposed = {}  # cve -> {service: depth}
    for s in services:
        dist = bfs(s, dep)
        for c, vs in affected_by.items():
            d = min((dist[v] for v in vs if v in dist and v != s), default=None)
            if d:
                exposed.setdefault(c, {})[s] = d
    for c in sev:
        exposed.setdefault(c, {})
    return services, sev, down, exposed, affected_by, edges


def check_tools():
    services, sev, down, exposed, affected_by, edges = ground_truth()
    checks, bad = defaultdict(lambda: [0, 0]), []

    def ok(name, cond, detail):
        checks[name][0] += 1
        checks[name][1] += bool(cond)
        if not cond:
            bad.append(f"{name}: {detail}")

    for c, truth in exposed.items():
        r = server.find_exposed_services(c)
        got = {x["service"]: x["depth"] for x in r.get("services", [])}
        ok("find_exposed: resolves to same CVE", r.get("cve", {}).get("id") == c, f"{c} got {r.get('cve', {}).get('id')}")
        ok("find_exposed: service set+depth", got == truth, f"{c} got {got} want {truth}")
        for x in r.get("services", []):
            ok("find_exposed: vulnerable_package", x["vulnerable_package"] in affected_by[c], f"{c} {x}")

        for s, depth in truth.items():
            p = server.show_path(s, c).get("path") or []
            hops = list(zip(p, p[1:]))
            valid = (len(p) == depth + 2 and p[0] == s and p[-1] == c
                     and all((a, "DEPENDS_ON", b) in edges for a, b in hops[:-1])
                     and (p[-2], "AFFECTED_BY", c) in edges)
            ok("show_path: valid shortest path", valid, f"{s} {c} depth {depth} got {p}")

            n = len(down[s])
            score = sev[c] * (1 + n) / depth
            prio = "P0" if score >= 20 else "P1" if score >= 8 else "P2"
            d = server.draft_remediation(s, c)
            ok("draft_remediation: cve id", d.get("cve") == c, f"{s} {c} got {d.get('cve')}")
            ok("draft_remediation: priority", d.get("priority") == prio, f"{s} {c} got {d.get('priority')} want {prio}")
            ok("draft_remediation: score", d.get("score") == round(score, 2), f"{s} {c} got {d.get('score')} want {round(score, 2)}")
            ok("draft_remediation: inputs", d.get("inputs") == {"severity": sev[c], "downstream": n, "depth": depth},
               f"{s} {c} got {d.get('inputs')}")

    for s in services:
        r = server.service_criticality(s)
        ok("service_criticality: downstream", set(r.get("downstream", [])) == down[s] and r.get("downstream_count") == len(down[s]),
           f"{s} got {r.get('downstream_count')} want {len(down[s])}")

    for s, want in [("auth-service", "P0"), ("pdf-export", "P2")]:
        got = server.draft_remediation(s, DEMO_CVE).get("priority")
        ok("demo facts", got == want, f"{s} {DEMO_CVE} got {got} want {want}")

    print(f"{'check':40} {'cases':>6} {'passed':>7} {'acc %':>7}")
    for name, (n, p) in checks.items():
        print(f"{name:40} {n:6} {p:7} {100 * p / n:7.1f}")
    print(f"exposed (service, CVE) pairs: {sum(map(len, exposed.values()))} across {len(exposed)} CVEs")
    for b in bad[:10]:
        print("MISMATCH", b)
    return not bad


QUESTIONS = [
    ("How does auth-service reach CVE-2022-24999?", "show_path"),
    ("Show the dependency chain from pdf-export to GHSA-hrpp-h998-j3pp.", "show_path"),
    ("How critical is api-gateway?", "service_criticality"),
    ("How many services would be hit if user-store were breached?", "service_criticality"),
    ("Which single upgrade fixes the most services?", "best_single_fix"),
    ("Who is exposed to GHSA-hrpp-h998-j3pp?", "find_exposed_services"),
    ("Which services are affected by CVE-2022-24999?", "find_exposed_services"),
    ("Draft a fix for pdf-export for CVE-2022-24999.", "draft_remediation"),
]


def check_agent():
    import agent  # needs openai + mcp, only imported when asked
    calls = []
    # ponytail: patch agent's module globals instead of editing agent.py: record tool names, skip the y/N gate.
    agent.show_step = lambda name, args, result: calls.append(name)
    agent.approve = lambda drafts, *a, **k: []
    hits = 0
    for q, want in QUESTIONS:
        calls.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            asyncio.run(agent.run(q))
        hits += want in calls
        print(f"{'OK  ' if want in calls else 'MISS'} want {want:22} got {calls}  | {q}")
    print(f"agent tool selection: {hits}/{len(QUESTIONS)} = {100 * hits / len(QUESTIONS):.1f}%")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    passed = check_tools()
    if "--agent" not in sys.argv[1:]:
        print("agent tool selection: skipped (pass --agent)")
    else:
        import agent
        agent.load_env()
        if not os.environ.get("GEMINI_API_KEY"):
            print("agent tool selection: skipped (GEMINI_API_KEY not set)")
        else:
            check_agent()
    sys.exit(0 if passed else 1)
