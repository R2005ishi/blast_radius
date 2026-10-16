"""BlastRadius MCP server: graph tools over FalkorDB. See README "Contract"."""
import json
import os
import re
import sys

import falkordb
from mcp.server.mcpserver import MCPServer  # mcp 2.x name for FastMCP

G = falkordb.FalkorDB(host="localhost", port=6379).select_graph(os.environ.get("BLASTRADIUS_GRAPH", "blastradius"))
mcp = MCPServer("blastradius")
ACTIONS = {"P0": "patch now", "P1": "patch this sprint", "P2": "patch next sprint"}


def _q(log, cypher, **params):
    # Logged with params inlined so it can be pasted into the graph browser.
    log.append(re.sub(r"\$(\w+)", lambda m: json.dumps(params[m.group(1)]) if m.group(1) in params else m.group(0), cypher))
    return G.ro_query(cypher, params).result_set


def _cve(log, cve_id):
    # Exact id wins: OSV lists some GHSAs as aliases of each other.
    rows = _q(log, "MATCH (c:CVE) WHERE c.id = $cve OR $cve IN c.aliases "
                   "RETURN c.id, c.aliases, c.severity, c.summary, c.severity_label "
                   "ORDER BY CASE WHEN c.id = $cve THEN 0 ELSE 1 END, c.id LIMIT 1", cve=cve_id)
    if not rows:
        return None
    cid, aliases, sev, summary, label = rows[0]
    return {"id": cid, "aliases": aliases or [], "severity": float(sev or 0), "summary": summary, "severity_label": label}


def _path(log, service, cid):
    rows = _q(log, "MATCH (s:Service {name: $service}), (c:CVE {id: $cve}) "
                   "WITH shortestPath((s)-[:DEPENDS_ON|AFFECTED_BY*]->(c)) AS p "
                   "RETURN [n IN nodes(p) | coalesce(n.id, n.name)], relationships(p)[-1].fixed",
              service=service, cve=cid)
    return (rows[0][0], rows[0][1]) if rows and rows[0][0] else (None, None)


def _downstream(log, service):
    rows = _q(log, "MATCH (s:Service {name: $service}) "
                   "OPTIONAL MATCH (x:Service)-[:CALLS*1..]->(s) WHERE x <> s "
                   "RETURN s.name, collect(DISTINCT x.name)", service=service)
    return sorted(rows[0][1]) if rows else None  # grouping by s.name: no row when service is unknown


def _vkey(v):
    return tuple(int(n) for n in re.findall(r"\d+", v or ""))


@mcp.tool()
def find_exposed_services(cve_id: str) -> dict:
    """List every service exposed to a CVE (directly or through transitive npm dependencies).

    Use this FIRST when asked "who is affected by CVE X". Accepts the OSV/GHSA id or any alias
    (e.g. CVE-2022-24999). Returns the CVE details and services sorted by depth
    (1 = direct dependency, higher = buried deeper in the dependency tree)."""
    log = []
    cve = _cve(log, cve_id)
    if not cve:
        return {"error": f"Unknown CVE {cve_id}", "cypher": log}
    rows = _q(log, "MATCH (c:CVE {id: $cve})<-[:AFFECTED_BY]-(v:PackageVersion) "
                   "MATCH p = (s:Service)-[:DEPENDS_ON*1..]->(v) "
                   "RETURN s.name, v.id, min(length(p)) AS depth ORDER BY depth, s.name", cve=cve["id"])
    services = {}
    for name, vid, depth in rows:
        services.setdefault(name, {"service": name, "depth": depth, "vulnerable_package": vid})
    cve.pop("severity_label")
    return {"cve": cve, "services": list(services.values()), "cypher": log}


@mcp.tool()
def show_path(service: str, cve_id: str) -> dict:
    """Show HOW a service reaches a CVE: the shortest dependency chain, in order,
    from the service through each package version to the CVE.

    Use this to explain or verify one service's exposure."""
    log = []
    cve = _cve(log, cve_id)
    if not cve:
        return {"error": f"Unknown CVE {cve_id}", "cypher": log}
    path, _ = _path(log, service, cve["id"])
    if not path:
        return {"error": f"{service} has no dependency path to {cve['id']} (or does not exist)", "cypher": log}
    return {"path": path, "cypher": log}


@mcp.tool()
def service_criticality(service: str) -> dict:
    """How central a service is: which services depend on it (call it, directly or indirectly)
    and its PageRank over the CALLS graph (rank 1 = most central).

    Use this to judge blast radius: a breach in a service spreads to everything downstream."""
    log = []
    down = _downstream(log, service)
    if down is None:
        return {"error": f"Unknown service {service}", "cypher": log}
    ranks = _q(log, "CALL algo.pageRank('Service', 'CALLS') YIELD node, score "
                    "RETURN node.name, score ORDER BY score DESC")
    rank, score = next((i + 1, s) for i, (n, s) in enumerate(ranks) if n == service)
    return {"downstream_count": len(down), "downstream": down, "pagerank": score, "pagerank_rank": rank, "cypher": log}


@mcp.tool()
def best_single_fix(cve_id: str | None = None) -> dict:
    """Find the single package upgrades that remove the most exposure: top 5 vulnerable
    package versions ranked by how many services pull them in, with the fixed version and
    how many CVEs the upgrade clears.

    Use this for "what one fix helps most". Pass cve_id to only consider versions affected by
    that CVE; omit it to rank across all CVEs."""
    log = []
    filt = ""
    params = {}
    if cve_id:
        cve = _cve(log, cve_id)
        if not cve:
            return {"error": f"Unknown CVE {cve_id}", "cypher": log}
        filt = "MATCH (v:PackageVersion)-[:AFFECTED_BY]->(:CVE {id: $cve}) "
        params["cve"] = cve["id"]
    # ponytail: services_cleared = services that reach this version at all. Ceiling: a service
    # that also reaches the CVE through another version is not actually cleared; fix by
    # recomputing exposure with this version removed.
    rows = _q(log, filt + "MATCH (v:PackageVersion)-[a:AFFECTED_BY]->(c:CVE) "
                          "WITH v, collect(DISTINCT [c.id, a.fixed]) AS cf "
                          "OPTIONAL MATCH (s:Service)-[:DEPENDS_ON*1..]->(v) "
                          "RETURN v.id, cf, count(DISTINCT s) AS n ORDER BY n DESC, size(cf) DESC, v.id LIMIT 5", **params)
    fixes = []
    for vid, cf, n in rows:
        fixed = dict(cf)[params["cve"]] if cve_id else max((f for _, f in cf), key=_vkey)
        fixes.append({"package_version": vid, "fixed": fixed or "", "cves_cleared": len({c for c, _ in cf}),
                      "services_cleared": n})
    return {"fixes": fixes, "cypher": log}


@mcp.tool()
def draft_remediation(service: str, cve_id: str) -> dict:
    """Decide how urgently a service must be patched for a CVE and draft the upgrade plan.

    Priority is deterministic: score = severity * (1 + downstream services) / depth;
    P0 "patch now" if score >= 20, P1 "patch this sprint" if >= 8, else P2 "patch next sprint".
    Use this after find_exposed_services to recommend an action. It only drafts; nothing is written."""
    log = []
    cve = _cve(log, cve_id)
    if not cve:
        return {"error": f"Unknown CVE {cve_id}", "cypher": log}
    path, fixed = _path(log, service, cve["id"])
    if not path:
        return {"error": f"{service} has no dependency path to {cve['id']} (or does not exist)", "cypher": log}
    down = _downstream(log, service)
    sev, depth, n = cve["severity"], len(path) - 2, len(down)
    score = sev * (1 + n) / depth
    prio = "P0" if score >= 20 else "P1" if score >= 8 else "P2"
    vid = path[-2]
    pkg = vid.split(":", 1)[1].rsplit("@", 1)[0]
    via = f" (pulled in via {path[1]})" if depth > 1 else ""
    reasons = [
        f"{cve['id']} has severity {sev}" + (f" ({cve['severity_label']})." if cve["severity_label"] else "."),
        f"{n} services call {service} directly or indirectly, so they are in its blast radius." if n
        else f"No services call {service}, so impact stays local to it.",
        f"The vulnerable package {vid} is {depth} dependency hop{'s' if depth > 1 else ''} deep{via}.",
        f"Score = {sev} * (1 + {n}) / {depth} = {score:.2f}, so {prio} ({ACTIONS[prio]}).",
    ]
    fix_line = f"Upgrade `{pkg}` to `{fixed}`{via}." if fixed else f"No fixed version published; remove or replace `{pkg}`{via}."
    draft = "\n".join([
        f"# {service}: remediate {cve['id']}",
        "",
        f"- **Priority:** {prio} ({ACTIONS[prio]}), score {score:.2f}",
        f"- **CVE:** {cve['id']} {' '.join(cve['aliases'])} - {cve['summary'] or ''}".rstrip(" -"),
        f"- **Affected path:** {' -> '.join(path)}",
        "",
        "## Fix",
        fix_line,
        "",
        f"## Downstream services ({n})",
        *([f"- {d}" for d in down] or ["- none"]),
    ])
    return {"service": service, "cve": cve["id"], "priority": prio, "action": ACTIONS[prio], "score": round(score, 2),
            "inputs": {"severity": sev, "downstream": n, "depth": depth},
            "reasons": reasons, "draft": draft, "cypher": log}


# hub <- a1 <- b1, hub <- a2 <- b2 (4 downstream); leaf (0). Both -> web -> qs (depth 2).
FIXTURE = """
CREATE (hub:Service {name:'hub', team:'t', tier:1}), (leaf:Service {name:'leaf', team:'t', tier:3}),
       (a1:Service {name:'a1'}), (a2:Service {name:'a2'}), (b1:Service {name:'b1'}), (b2:Service {name:'b2'}),
       (a1)-[:CALLS]->(hub), (a2)-[:CALLS]->(hub), (b1)-[:CALLS]->(a1), (b2)-[:CALLS]->(a2), (b1)-[:CALLS]->(hub),
       (web:PackageVersion {id:'npm:web@1.0.0', name:'web', version:'1.0.0'}),
       (qs:PackageVersion {id:'npm:qs@1.0.0', name:'qs', version:'1.0.0'}),
       (safe:PackageVersion {id:'npm:safe@1.0.0', name:'safe', version:'1.0.0'}),
       (hub)-[:DEPENDS_ON]->(web), (leaf)-[:DEPENDS_ON]->(web), (web)-[:DEPENDS_ON]->(qs), (a1)-[:DEPENDS_ON]->(safe),
       (c1:CVE {id:'GHSA-test', aliases:['CVE-TEST'], summary:'proto pollution', severity:9.5, severity_label:'CRITICAL'}),
       (c2:CVE {id:'GHSA-two', aliases:[], summary:'other', severity:5.5, severity_label:'MODERATE'}),
       (qs)-[:AFFECTED_BY {fixed:'1.0.5'}]->(c1), (qs)-[:AFFECTED_BY {fixed:'1.0.10'}]->(c2)
"""


def selftest():
    global G
    G = falkordb.FalkorDB(host="localhost", port=6379).select_graph("blastradius_selftest")
    try:
        G.delete()
    except Exception:
        pass
    G.query(FIXTURE)
    try:
        r = find_exposed_services("CVE-TEST")
        assert r["cve"]["id"] == "GHSA-test" and r["cve"]["severity"] == 9.5, r
        assert r["services"] == [{"service": "hub", "depth": 2, "vulnerable_package": "npm:qs@1.0.0"},
                                 {"service": "leaf", "depth": 2, "vulnerable_package": "npm:qs@1.0.0"}], r
        assert "error" in find_exposed_services("GHSA-nope")
        assert show_path("hub", "GHSA-test")["path"] == ["hub", "npm:web@1.0.0", "npm:qs@1.0.0", "GHSA-test"]
        assert "error" in show_path("a1", "GHSA-test")
        r = service_criticality("hub")
        assert r["downstream_count"] == 4 and r["downstream"] == ["a1", "a2", "b1", "b2"] and r["pagerank_rank"] == 1, r
        assert service_criticality("leaf")["downstream_count"] == 0
        assert "error" in service_criticality("nope")
        f = best_single_fix()["fixes"][0]
        assert f == {"package_version": "npm:qs@1.0.0", "fixed": "1.0.10", "cves_cleared": 2, "services_cleared": 2}, f
        assert best_single_fix("GHSA-test")["fixes"][0]["fixed"] == "1.0.5"
        r = draft_remediation("hub", "GHSA-test")
        assert r["priority"] == "P0" and r["inputs"] == {"severity": 9.5, "downstream": 4, "depth": 2}, r
        assert r["score"] == 23.75 and "Upgrade `qs` to `1.0.5`" in r["draft"] and r["cypher"], r
        r = draft_remediation("leaf", "CVE-TEST")
        assert r["priority"] == "P2" and r["score"] == 4.75 and (r["service"], r["cve"]) == ("leaf", "GHSA-test"), r
        print(json.dumps(draft_remediation("hub", "GHSA-test"), indent=2))
        print("selftest OK")
    finally:
        G.delete()


if __name__ == "__main__":
    selftest() if "--selftest" in sys.argv else mcp.run()
