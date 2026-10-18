"""Load real npm dependency + vuln data (deps.dev, OSV) plus synthetic services into FalkorDB."""
import hashlib
import json
import os
import time
import urllib.parse
import urllib.request

from falkordb import FalkorDB

GRAPH = os.environ.get("BLASTRADIUS_GRAPH", "blastradius")
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".cache")
DEMO_CVE = "GHSA-hrpp-h998-j3pp"

# Real old versions with known vulns.
ROOTS = [
    "express@4.17.1", "lodash@4.17.20", "axios@0.21.1", "jsonwebtoken@8.5.1",
    "node-fetch@2.6.0", "minimist@1.2.5", "ws@7.4.5", "moment@2.29.1",
    "handlebars@4.7.6", "marked@1.2.9", "jquery@3.4.1", "ejs@3.1.5",
    "follow-redirects@1.14.0", "xml2js@0.4.23", "underscore@1.12.0", "validator@13.6.0",
]

# name: (team, tier, [root packages], [services it CALLS])
SERVICES = {
    "auth-service":      ("identity",  1, ["express@4.17.1", "jsonwebtoken@8.5.1", "lodash@4.17.20"], ["user-store"]),
    "pdf-export":        ("documents", 3, ["express@4.17.1", "handlebars@4.7.6"], []),
    "user-store":        ("identity",  1, ["lodash@4.17.20", "validator@13.6.0"], []),
    "api-gateway":       ("platform",  1, ["express@4.17.1", "axios@0.21.1", "ws@7.4.5"], ["auth-service"]),
    "web-frontend":      ("web",       2, ["jquery@3.4.1", "marked@1.2.9", "axios@0.21.1"], ["api-gateway"]),
    "mobile-bff":        ("mobile",    2, ["express@4.17.1", "node-fetch@2.6.0"], ["api-gateway"]),
    "admin-portal":      ("platform",  3, ["ejs@3.1.5", "express@4.17.1", "moment@2.29.1"], ["api-gateway"]),
    "partner-api":       ("partners",  2, ["express@4.17.1", "xml2js@0.4.23", "jsonwebtoken@8.5.1"], ["api-gateway"]),
    "checkout-service":  ("commerce",  1, ["axios@0.21.1", "moment@2.29.1"], ["api-gateway", "payments-service"]),
    "order-service":     ("commerce",  1, ["lodash@4.17.20", "node-fetch@2.6.0"], ["api-gateway", "inventory-service"]),
    "cart-service":      ("commerce",  2, ["express@4.17.1", "underscore@1.12.0"], ["api-gateway"]),
    "search-service":    ("discovery", 2, ["axios@0.21.1", "minimist@1.2.5"], ["api-gateway"]),
    "catalog-service":   ("discovery", 2, ["lodash@4.17.20", "xml2js@0.4.23"], ["api-gateway"]),
    "reviews-service":   ("discovery", 3, ["marked@1.2.9", "validator@13.6.0"], ["api-gateway"]),
    "payments-service":  ("payments",  1, ["axios@0.21.1", "jsonwebtoken@8.5.1", "follow-redirects@1.14.0"], ["auth-service"]),
    "account-service":   ("identity",  2, ["express@4.17.1", "validator@13.6.0"], ["auth-service", "email-service"]),
    "support-portal":    ("support",   3, ["ejs@3.1.5", "moment@2.29.1"], ["account-service"]),
    "email-service":     ("platform",  2, ["handlebars@4.7.6", "node-fetch@2.6.0"], []),
    "inventory-service": ("commerce",  2, ["lodash@4.17.20", "moment@2.29.1"], []),
    "metrics-collector": ("platform",  3, ["ws@7.4.5", "minimist@1.2.5"], []),
}

# ponytail: GHSA label -> number per README; anything unlabeled gets 0.0
SEVERITY = {"LOW": 3.0, "MODERATE": 5.5, "HIGH": 7.5, "CRITICAL": 9.5}


def http(url, body=None):
    """GET (or POST json body), cached forever in .cache/ by url+body hash.
    Returns None if not cached and network is unavailable."""
    os.makedirs(CACHE, exist_ok=True)
    data = json.dumps(body).encode() if body is not None else None
    path = os.path.join(CACHE, hashlib.sha1(url.encode() + (data or b"")).hexdigest() + ".json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            out = json.load(r)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f)
        return out
    except Exception as e:
        print(f"  [warn] skipping {url}: {e}")
        return None


def pid(name, version):
    return f"npm:{name}@{version}"


def split(root):
    name, _, version = root.rpartition("@")
    return name, version


def semver(v):
    # ponytail: numeric major.minor.patch only, prerelease tags dropped; fine for picking OSV ranges
    return tuple(int(x) for x in v.split("-")[0].split("+")[0].split(".") if x.isdigit())


def fixed_for(vuln, name, version):
    """`fixed` of the OSV range containing this version; else first fixed for the package; else ""."""
    ranges = [e for a in vuln.get("affected", []) if a.get("package", {}).get("name") == name
              for rg in a.get("ranges", []) if rg.get("type") in ("SEMVER", "ECOSYSTEM") for e in [rg["events"]]]
    for events in ranges:
        lo = "0"
        for e in events:
            lo = e.get("introduced", lo)
            if "fixed" in e and semver(lo) <= semver(version) < semver(e["fixed"]):
                return e["fixed"]
    return next((e["fixed"] for events in ranges for e in events if "fixed" in e), "")


def main():
    t0 = time.time()
    q = urllib.parse.quote

    # 1-2. real dependency trees from deps.dev
    pkgs, deps = {}, set()
    for root in ROOTS:
        name, version = split(root)
        g = http(f"https://api.deps.dev/v3/systems/npm/packages/{q(name, safe='')}/versions/{q(version, safe='')}:dependencies")
        if g is None:
            print(f"  [warn] skipping deps for {root} (not cached, network unavailable)")
            continue
        ids = [pid(n["versionKey"]["name"], n["versionKey"]["version"]) for n in g["nodes"]]
        for n, i in zip(g["nodes"], ids):
            pkgs[i] = (n["versionKey"]["name"], n["versionKey"]["version"])
        deps |= {(ids[e["fromNode"]], ids[e["toNode"]]) for e in g.get("edges", [])}
        assert ids[0] == pid(name, version), f"root mismatch for {root}: {ids[0]}"

    # 3. OSV: which versions are vulnerable, then details per vuln
    order = sorted(pkgs)
    affected = []  # (package id, vuln id)
    for i in range(0, len(order), 1000):
        chunk = order[i:i + 1000]
        res = http("https://api.osv.dev/v1/querybatch", {"queries": [
            {"package": {"name": pkgs[p][0], "ecosystem": "npm"}, "version": pkgs[p][1]} for p in chunk]})
        if res is None:
            print("  [warn] skipping OSV querybatch (not cached, network unavailable)")
            continue
        # ponytail: ignores next_page_token; fine unless one version has >1000 vulns
        for p, r in zip(chunk, res["results"]):
            affected += [(p, v["id"]) for v in r.get("vulns", [])]

    cves, edges = {}, []
    for p, vid in affected:
        v = http(f"https://api.osv.dev/v1/vulns/{q(vid, safe='')}")
        if v is None:
            print(f"  [warn] skipping vuln details for {vid} (not cached, network unavailable)")
            continue
        label = (v.get("database_specific") or {}).get("severity") or "UNKNOWN"
        cves[vid] = {"id": vid, "aliases": v.get("aliases", []), "summary": v.get("summary", ""),
                     "severity": SEVERITY.get(label, 0.0), "severity_label": label}
        edges.append({"pkg": p, "cve": vid, "fixed": fixed_for(v, *pkgs[p])})

    # 4-5. write graph
    g = FalkorDB(host=os.environ.get("BLASTRADIUS_HOST", "localhost"), port=int(os.environ.get("BLASTRADIUS_PORT", "6379"))).select_graph(GRAPH)
    try:
        g.delete()
    except Exception:
        pass
    for label, prop in [("Service", "name"), ("PackageVersion", "id"), ("CVE", "id")]:
        g.query(f"CREATE INDEX FOR (n:{label}) ON (n.{prop})")

    def unwind(cypher, rows):
        for i in range(0, len(rows), 1000):
            g.query("UNWIND $rows AS r " + cypher, {"rows": rows[i:i + 1000]})

    unwind("MERGE (p:PackageVersion {id: r.id}) SET p.name = r.name, p.version = r.version",
           [{"id": i, "name": n, "version": v} for i, (n, v) in pkgs.items()])
    unwind("MATCH (a:PackageVersion {id: r.a}), (b:PackageVersion {id: r.b}) MERGE (a)-[:DEPENDS_ON]->(b)",
           [{"a": a, "b": b} for a, b in deps])
    unwind("MERGE (c:CVE {id: r.id}) SET c.aliases = r.aliases, c.summary = r.summary, "
           "c.severity = r.severity, c.severity_label = r.severity_label", list(cves.values()))
    unwind("MATCH (p:PackageVersion {id: r.pkg}), (c:CVE {id: r.cve}) MERGE (p)-[e:AFFECTED_BY]->(c) SET e.fixed = r.fixed",
           edges)
    unwind("MERGE (s:Service {name: r.name}) SET s.team = r.team, s.tier = r.tier",
           [{"name": s, "team": t, "tier": tier} for s, (t, tier, _, _) in SERVICES.items()])
    unwind("MATCH (s:Service {name: r.s}), (p:PackageVersion {id: r.p}) MERGE (s)-[:DEPENDS_ON]->(p)",
           [{"s": s, "p": pid(*split(r))} for s, (_, _, roots, _) in SERVICES.items() for r in roots])
    unwind("MATCH (a:Service {name: r.a}), (b:Service {name: r.b}) MERGE (a)-[:CALLS]->(b)",
           [{"a": s, "b": c} for s, (_, _, _, calls) in SERVICES.items() for c in calls])

    # 7. summary + demo guarantees
    for label in ["Service", "PackageVersion", "CVE"]:
        print(f"{label:16}", g.query(f"MATCH (n:{label}) RETURN count(n)").result_set[0][0])
    for rel in ["DEPENDS_ON", "AFFECTED_BY", "CALLS"]:
        print(f"{rel:16}", g.query(f"MATCH ()-[e:{rel}]->() RETURN count(e)").result_set[0][0])

    def downstream(svc):
        return sorted(r[0] for r in g.query(
            "MATCH (x:Service)-[:CALLS*1..]->(s:Service {name: $s}) WHERE x <> s RETURN DISTINCT x.name",
            {"s": svc}).result_set)

    demo = g.query("MATCH (c:CVE {id: $id}) RETURN c.aliases", {"id": DEMO_CVE}).result_set
    assert demo and "CVE-2022-24999" in demo[0][0], demo
    for svc in ["auth-service", "pdf-export"]:
        hit = g.query("MATCH (:Service {name: $s})-[:DEPENDS_ON*]->(:PackageVersion {id: 'npm:qs@6.7.0'})"
                      "-[:AFFECTED_BY]->(:CVE {id: $id}) RETURN count(*)", {"s": svc, "id": DEMO_CVE}).result_set[0][0]
        assert hit > 0, f"{svc} does not reach {DEMO_CVE}"
    assert fixed_for(http(f"https://api.osv.dev/v1/vulns/{DEMO_CVE}"), "qs", "6.7.0") == "6.7.3"
    auth = downstream("auth-service")
    assert len(auth) == 14, auth
    assert downstream("pdf-export") == [] and "pdf-export" not in auth
    assert len(SERVICES) == 20
    print("auth-service downstream:", ", ".join(auth))
    print(f"ok in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
