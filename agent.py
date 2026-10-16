"""BlastRadius agent: Gemini + the server.py MCP tools, with human approval for remediations.

Usage:
  python agent.py "Which services are exposed to CVE-2022-24999 and what should we do first?"
  python agent.py --check     # no API key needed: MCP tool list + approval self-test

Key: GEMINI_API_KEY in the environment or in a .env file next to this script.
"""
import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import AsyncOpenAI, InternalServerError, RateLimitError

# ponytail: Gemini via its OpenAI-compatible endpoint; Groq/Ollama work by changing BASE_URL + model.
BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
MODEL = os.environ.get("BLASTRADIUS_MODEL", "gemini-3.8-flash")
# Free tier, each with its own daily quota; tried in order on 503 "high demand" or 429 daily quota.
FALLBACK_MODELS = ["gemini-3.6-flash", "gemini-2.5-flash", "gemini-3.5-flash-lite"]
EXHAUSTED = set()  # ponytail: in-memory, resets on restart; daily quotas reset anyway
MAX_TURNS = 15
HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
CONTRACT_TOOLS = {"find_exposed_services", "show_path", "service_criticality",
                  "best_single_fix", "draft_remediation"}

SYSTEM = """You are BlastRadius, a vulnerability triage agent over a service/package/CVE graph.
Always use the tools; never guess graph facts (services, paths, counts, versions).
For each exposed service give: the path, the priority with its numbers (severity, downstream, depth, score), and the reason.
Call draft_remediation for each exposed service worth acting on. A human approves drafts afterwards; never say anything was filed.
Final answer: the findings, then every step as: tool used, why, and the Cypher it ran.
Keep it short."""


def load_env():
    """Read KEY=value lines from .env (already-set env vars win). Keeps the key out of code and git."""
    f = HERE / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.strip().startswith("#"):
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


def server_params():
    # ponytail: pass our env through (minus the API key) so BLASTRADIUS_GRAPH reaches server.py
    env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
    return StdioServerParameters(command=sys.executable, args=[str(SERVER)], env=env, cwd=str(HERE))


def to_openai_tools(mcp_tools):
    return [{"type": "function",
             "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema}}
            for t in mcp_tools]


def parse_result(res):
    """MCP CallToolResult -> dict (contract: every tool returns a dict with 'cypher')."""
    text = "".join(getattr(c, "text", "") for c in res.content)
    if res.is_error:
        return {"error": text or "tool error"}
    data = res.structured_content
    if data is None:
        try:
            data = json.loads(text)
        except ValueError:
            return {"result": text}
    if isinstance(data, dict) and set(data) == {"result"} and isinstance(data["result"], dict):
        data = data["result"]  # FastMCP wraps some return types
    return data if isinstance(data, dict) else {"result": data}


def show_step(name, args, result):
    print(f"\n> tool: {name} {json.dumps(args)}")
    for q in result.get("cypher") or []:
        print(f"  cypher: {q}")
    summary = json.dumps({k: v for k, v in result.items() if k not in ("cypher", "draft")})
    print(f"  result: {summary[:400]}{'...' if len(summary) > 400 else ''}")


def approve(drafts, out_dir="remediations", ask=input):
    """Human gate (code, not model): nothing is written without an explicit y/yes."""
    filed, skipped = [], []
    for d in drafts:
        print(f"\n=== {d.get('priority')} {d.get('action', '')} | service={d['service']} cve={d['cve']} "
              f"score={d.get('score')} inputs={d.get('inputs')}")
        print(d.get("draft", ""))
        if ask("Approve and file? [y/N] ").strip().lower() in ("y", "yes"):
            safe = re.sub(r"[^\w.-]", "_", f"{d['service']}-{d['cve']}")  # names come from the model
            path = Path(out_dir) / f"{safe}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(d.get("draft", ""), encoding="utf-8")
            filed.append(str(path))
        else:
            skipped.append(f"{d['service']}-{d['cve']}")
    print(f"\nFiled: {filed or 'none'}\nSkipped: {skipped or 'none'}")
    return filed


async def complete(client, model, messages, tools):
    """One model call. Free tier: wait out the per-minute cap; on overload (503) or daily quota (429)
    move down FALLBACK_MODELS. Returns (model now in use, response)."""
    err = None
    for m in [model] + [f for f in FALLBACK_MODELS if f != model]:
        if m in EXHAUSTED:
            continue
        for _ in range(3):
            try:
                return m, await client.chat.completions.create(model=m, messages=messages, tools=tools)
            except RateLimitError as e:
                err = e
                if "PerMinute" not in str(e):
                    EXHAUSTED.add(m)  # daily cap: don't spend requests on it again this process
                    break
                print("\n(free-tier per-minute limit, waiting 30s)")
                await asyncio.sleep(30)
            except InternalServerError as e:
                err = e
                break
        print(f"\n({m} unavailable ({err.status_code}), trying the next model)")
    raise err or RuntimeError("every Gemini model is out of free quota today")


async def run(question, on_step=None):
    """Answer one question. on_step(name, args, result) fires per tool call (default: print it).
    Returns {"answer", "drafts", "model"}; approval is the caller's job."""
    on_step = on_step or show_step
    # max_retries=0: complete() owns retries; SDK retries would double-spend the tiny free quota
    client = AsyncOpenAI(api_key=os.environ["GEMINI_API_KEY"], base_url=BASE_URL, max_retries=0)
    drafts = []
    async with stdio_client(server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = to_openai_tools((await session.list_tools()).tools)
            messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
            msg, model = None, MODEL
            for _ in range(MAX_TURNS):
                model, response = await complete(client, model, messages, tools)
                msg = response.choices[0].message
                # model_dump keeps Gemini's extra fields (thought signatures) that it needs back next turn
                messages.append(msg.model_dump(exclude_none=True))
                if not msg.tool_calls:
                    break
                for call in msg.tool_calls:
                    args = json.loads(call.function.arguments or "{}")
                    result = parse_result(await session.call_tool(call.function.name, args))
                    on_step(call.function.name, args, result)
                    if call.function.name == "draft_remediation" and "error" not in result and result.get("draft"):
                        # server's canonical service/cve win over the model's args
                        drafts.append({"service": args.get("service"), "cve": args.get("cve_id"), **result})
                    messages.append({"role": "tool", "tool_call_id": call.id,
                                     "content": json.dumps(result, default=str)})
            else:
                print(f"\n(stopped after {MAX_TURNS} turns)")
    return {"answer": msg.content or "", "drafts": drafts, "model": model}


async def check():
    # 1. approval gate, stubbed input, temp dir
    fake = {"service": "pdf-export", "cve": "CVE-2022-24999", "priority": "P2",
            "action": "patch next sprint", "score": 7.5, "inputs": {}, "draft": "# upgrade qs"}
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "pdf-export-CVE-2022-24999.md"
        approve([fake], tmp, ask=lambda _: "n")
        assert not f.exists(), "written without approval"
        approve([fake], tmp, ask=lambda _: "y")
        assert f.read_text(encoding="utf-8") == "# upgrade qs", "not written on y"
    print("approval check: OK")

    # 2. MCP: list tools from server.py, convert, assert contract names
    if not SERVER.exists():
        sys.exit(f"MCP check: SKIPPED, {SERVER} not found")
    async with stdio_client(server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = [t["function"] for t in to_openai_tools((await session.list_tools()).tools)]
    names = {t["name"] for t in tools}
    assert all(t["parameters"].get("type") == "object" for t in tools), "bad parameters schema"
    assert CONTRACT_TOOLS <= names, f"missing tools: {CONTRACT_TOOLS - names}"
    print(f"MCP check: OK, tools = {sorted(names)}")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows console vs. unicode in drafts
    if "--check" in sys.argv[1:]:
        asyncio.run(check())
        return
    load_env()
    if not os.environ.get("GEMINI_API_KEY"):
        sys.exit("GEMINI_API_KEY is not set. Put it in .env (GEMINI_API_KEY=...) or the environment and re-run.")
    question = " ".join(sys.argv[1:]).strip() or input("Question: ").strip()
    res = asyncio.run(run(question))
    print("\n=== Answer ===")
    print(res["answer"])
    if res["drafts"]:
        approve(res["drafts"])
    else:
        print("\nNo drafts to approve.")


if __name__ == "__main__":
    main()
