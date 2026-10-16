# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS/JS in one page, served by a small Python standard-library server next to `agent.py`. No Node, no build step (user choice: must be easy for a teammate to clone and run).

## Users

Primary: hackathon judges (Track 1, "Agents That Act on Connected Data") watching a live demo on a projector or screen share. They must understand what the agent did and why within about 60 seconds.

Secondary (believability): security engineers who triage CVEs across many services.

## Product Purpose

BlastRadius answers "Which of our services are exposed to this CVE, how, and what should we do first?" by walking a dependency graph in FalkorDB, then drafting a graded remediation that a human must approve. Success: the judge sees the same CVE get "patch now" on a central service and "patch next sprint" on a leaf service, and sees the graph path that justified each.

## Positioning

The graph decides the action. Priority comes from a deterministic formula over graph facts (severity x (1 + downstream services) / dependency depth), not from model opinion. Every answer shows the path, the Cypher that ran, and the reason.

## Operating Context

- Agent: `agent.py` (Gemini via OpenAI-compatible API) connects to `server.py` over MCP stdio.
- Five MCP tools: `find_exposed_services`, `show_path`, `service_criticality`, `best_single_fix`, `draft_remediation`. Each returns the Cypher it ran.
- FalkorDB in Docker on localhost:6379; FalkorDB Browser on :3000.
- Approval is enforced in code: nothing is written to `remediations/` without an explicit human yes.
- Gemini free tier is small (about 20 requests/day per model, about 5/minute), so the demo must survive quota exhaustion.

## Capabilities and Constraints

- Live agent run with a replay fallback: if Gemini is unavailable, replay a saved real run so the demo never dies. Replays must be labeled as replays.
- Demo CVE: GHSA-hrpp-h998-j3pp (CVE-2022-24999, qs prototype pollution, HIGH 7.5). auth-service: P0, score 56.25, 14 downstream. pdf-export: P2, score 3.75, 0 downstream. Fix: qs 6.7.3.
- Terminology: service, package version, CVE, downstream (services that call into a service), depth (dependency hops), P0/P1/P2.

## Evidence on Hand

- Real OSV advisory data and real deps.dev dependency trees for 16 npm root packages (94 versions, 86 CVEs).
- Synthetic services (20) and their CALLS edges: must be labeled synthetic wherever a viewer could mistake them for a real company.
- Benchmark: 347 service/CVE pairs, 100% tool accuracy; agent tool selection 8/8 on gemini-3.6-flash.
- No customers, testimonials, or production deployments exist; never imply them.

## Product Principles

1. The graph decides; the model explains.
2. Show the work: path, Cypher, and reason for every claim.
3. Nothing acts without a human yes.
4. The demo never dies: degrade to a labeled replay, never to an error screen.

## Accessibility & Inclusion

Projector legibility: large type, high contrast, no meaning carried by color alone.
