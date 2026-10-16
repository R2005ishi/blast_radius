# BlastRadius

A dependency and vulnerability triage agent.

Ask: "Which of our services are exposed to this CVE, how, and what should we do first?"
The agent walks a graph in FalkorDB, picks a graded action, and waits for approval.

## Demo moment

Same CVE, two services:

- Leaf service: "patch next sprint"
- Central service: "patch now, 14 services are downstream"

Each answer shows the path, the Cypher it ran, and why.

## Setup

```bash
docker run -d --name blastradius-db -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python load.py
```

Needs Python 3.10+, Docker, and internet for the first `load.py` (~35s; later runs use `.cache/`).
On Mac/Linux use `.venv/bin/python` instead of `.venv\Scripts\python`.

Graph browser: http://localhost:3000 (paste any Cypher the agent prints to see the path).

## Run

```bash
.venv\Scripts\python agent.py "Which services are exposed to CVE-2022-24999 and what should we do first?"
```

Needs a free Gemini key (Google AI Studio) in a `.env` file: `GEMINI_API_KEY=...` (git-ignored). Model: `gemini-3.8-flash`; when it is overloaded or out of free quota the agent tries `gemini-3.6-flash`, `gemini-2.5-flash`, then `gemini-3.5-flash-lite` (free tier is ~20 requests/day per model, ~5/minute; one question uses 3-20); override with env `BLASTRADIUS_MODEL`. Drafts are filed to `remediations/` only after you answer `y`.

### Demo web page

```bash
.venv\Scripts\python web.py
```

Open http://localhost:8000. Ask a question; the page streams each tool call with its Cypher, ranks the drafts, draws the dependency path and every downstream caller, and files a draft only when you click Approve.

If the live run fails (no key, quota, overload), the page replays the last recorded real run from `replays.json`, labeled as a replay. Every successful live run re-records it, so commit `replays.json` to keep the demo working on a fresh clone.

## Check

```bash
.venv\Scripts\python server.py --selftest
.venv\Scripts\python agent.py --check
.venv\Scripts\python bench.py
.venv\Scripts\python bench.py --agent
```

`bench.py` checks every tool against ground truth computed separately (347 service/CVE pairs, all 100%). `--agent` also checks the agent picks the right tool (needs the API key).

Use the same tools from Claude Code or Claude Desktop: add `server.py` as an MCP server (command: `.venv\Scripts\python`, args: `server.py`).

## Files

| File | Job |
|------|-----|
| `load.py` | Pull real npm data (deps.dev + OSV), add synthetic services, write graph |
| `server.py` | MCP server: graph tools |
| `agent.py` | Gemini agent: connects to `server.py` over MCP, answers, asks for approval |
| `bench.py` | Ground truth vs tool output |
| `web.py` + `web/index.html` | Demo page: live agent run with replay fallback, blast graph, approval |

---

## Contract (all files follow this)

FalkorDB at `localhost:6379`. Graph name: env `BLASTRADIUS_GRAPH`, default `blastradius`.

### Nodes

| Label | Properties |
|-------|-----------|
| `Service` | `name` (unique), `team`, `tier` |
| `PackageVersion` | `id` = `"npm:<name>@<version>"` (unique), `name`, `version` |
| `CVE` | `id` = OSV id e.g. `GHSA-hrpp-h998-j3pp` (unique), `aliases` (list, e.g. `["CVE-2022-24999"]`), `summary`, `severity` (float 0-10), `severity_label` |

### Edges

| Edge | Meaning |
|------|---------|
| `(:Service)-[:DEPENDS_ON]->(:PackageVersion)` | direct dependency |
| `(:PackageVersion)-[:DEPENDS_ON]->(:PackageVersion)` | transitive dependency (real, from deps.dev) |
| `(:PackageVersion)-[:AFFECTED_BY {fixed}]->(:CVE)` | OSV says this version is vulnerable; `fixed` = fixed version of the OSV range containing this version, `""` if none |
| `(:Service)-[:CALLS]->(:Service)` | A calls B, so A relies on B |

**Downstream of service S** = every service with a `CALLS` path to S: `(x:Service)-[:CALLS*1..]->(s)`, distinct, excluding S.

**Depth** of a CVE in a service = number of `DEPENDS_ON` hops from the service to the vulnerable version (direct dependency = 1), shortest.

Severity: GHSA label to number: LOW 3.0, MODERATE 5.5, HIGH 7.5, CRITICAL 9.5.

### Fixed demo data (load.py must guarantee)

- Demo CVE: `GHSA-hrpp-h998-j3pp` (alias `CVE-2022-24999`, qs prototype pollution) on `npm:qs@6.7.0`.
- `auth-service`: hub. Depends on `express@4.17.1`. Exactly **14** downstream services.
- `pdf-export`: leaf. Depends on `express@4.17.1`. **0** downstream services.
- About 20 services total, each depending on 1-4 real npm root packages at real old versions.

### Priority (deterministic, in server.py)

```
score = severity * (1 + downstream) / depth
P0 "patch now"         if score >= 20
P1 "patch this sprint" if score >= 8
P2 "patch next sprint" otherwise
```

### MCP tools (server.py)

Every tool returns a dict that includes `"cypher"`: the list of Cypher queries it ran.
`cve_id` accepts the OSV id or any alias (e.g. `CVE-2022-24999`).

| Tool | Args | Returns (besides `cypher`) |
|------|------|---------|
| `find_exposed_services` | `cve_id` | `cve` {id, aliases, severity, summary}, `services`: [{service, depth, vulnerable_package}] sorted by depth |
| `show_path` | `service`, `cve_id` | `path`: list of node names in order, e.g. `["auth-service","npm:express@4.17.1","npm:qs@6.7.0","GHSA-hrpp-h998-j3pp"]` |
| `service_criticality` | `service` | `downstream_count`, `downstream`: [names], `pagerank`, `pagerank_rank` (1 = most central) |
| `best_single_fix` | `cve_id` (optional) | `fixes`: top 5 [{package_version, fixed, cves_cleared, services_cleared}] sorted by services_cleared desc; with no `cve_id`, `fixed` = highest fixed version across that version's CVEs |
| `draft_remediation` | `service`, `cve_id` | `service`, `cve` (canonical OSV id), `priority` (P0/P1/P2), `action`, `score`, `inputs` {severity, downstream, depth}, `reasons` [strings], `draft` (markdown upgrade plan) |

### Approval

`draft_remediation` only drafts. `agent.py` (code, not the model) shows each draft and asks the human `y/N`.
On `y` it writes `remediations/<service>-<cve>.md`. Nothing is written without a `y`.
