"""Model Context Protocol surface: Arbiter as tools an agent can call.

This is one of two front doors over `service.py`, which holds the containment
rules. The other is the hosted API. Nothing about where output may go, whether
the network is reachable, or what a caller may not do is decided here -- that
would mean deciding it twice.

## What MCP does and does not deliver

It lets an agent run a scan, a gate and a review queue without a person typing
CLI commands, on a machine where Arbiter is already installed. It relocates the
installation rather than removing it. Removing it is what the hosted API is for
(REQ-018); this surface remains the right one for source that must not leave the
machine it sits on.

## The tool that is deliberately absent

There is no tool that records a verdict, here or in `service.py`. `review
--apply` is outside the surface: an agent marking findings in a loop would fill
the calibration ledger with the model's opinion of the model's output, and
`learn.record()` refuses to re-adjudicate a fingerprint, so those marks would be
permanent. The server generates queues. A person marks them.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from .service import EXIT_ERROR, EXIT_OK, ServiceError, gate, review_queue, scan

# Kept as an alias so callers and tests that catch the MCP-era name still work.
ToolError = ServiceError

# The schemas are data so tests can assert on them without the SDK installed --
# including asserting that no tool records a verdict.
TOOLS: list[dict[str, Any]] = [
    {
        "name": "arbiter_scan",
        "description": "Analyse a repository for security, compliance, quality "
                       "and drift findings. Returns the full report JSON.",
        "inputSchema": {
            "type": "object",
            "required": ["target", "output_dir"],
            "properties": {
                "target": {"type": "string", "description": "path to the repository to scan"},
                "output_dir": {"type": "string",
                               "description": "directory for output; nothing is written outside it"},
                "profile": {"type": "string", "enum": ["offline", "ci"], "default": "offline",
                            "description": "both run with the network off"},
                "only": {"type": "string", "description": "comma-separated probes to run"},
                "skip": {"type": "string", "description": "comma-separated probes to skip"},
            },
        },
    },
    {
        "name": "arbiter_gate",
        "description": "Run the policy gate over a repository. Returns pass or "
                       "fail with the claim ledger.",
        "inputSchema": {
            "type": "object",
            "required": ["target", "output_dir"],
            "properties": {
                "target": {"type": "string"},
                "output_dir": {"type": "string"},
                "profile": {"type": "string", "enum": ["offline", "ci"], "default": "ci"},
                "only": {"type": "string"},
                "skip": {"type": "string"},
            },
        },
    },
    {
        "name": "arbiter_review_queue",
        "description": "Generate a queue of findings for a person to adjudicate. "
                       "Every mark is blank. This tool cannot record verdicts.",
        "inputSchema": {
            "type": "object",
            "required": ["report_path", "output_dir"],
            "properties": {
                "report_path": {"type": "string", "description": "path to a report.json"},
                "output_dir": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "rule": {"type": "string",
                         "description": "only findings whose rule id contains this"},
            },
        },
    },
]

HANDLERS = {
    "arbiter_scan": scan,
    "arbiter_gate": gate,
    "arbiter_review_queue": review_queue,
}


def dispatch(name: str, arguments: dict) -> dict:
    """Call one tool by name. Unknown names are refused, not guessed at."""
    handler = HANDLERS.get(name)
    if handler is None:
        raise ServiceError(f"no such tool: {name}")
    return handler(**arguments)


def serve() -> int:
    """Run the MCP server on stdio.

    The SDK is imported here rather than at module scope so the schemas and the
    dispatch stay importable -- and testable -- without it. `mcp` is an optional
    extra; the core install is PyYAML alone.
    """
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool
    except ImportError:
        print("arbiter: the MCP server needs the optional 'mcp' dependency.\n"
              "         pip install 'arbiter-eval[mcp]'", file=sys.stderr)
        return EXIT_ERROR

    import asyncio

    server = Server("arbiter")

    @server.list_tools()
    async def _list() -> list:
        return [Tool(name=t["name"], description=t["description"],
                     inputSchema=t["inputSchema"]) for t in TOOLS]

    @server.call_tool()
    async def _call(name: str, arguments: dict) -> list:
        try:
            result = await asyncio.to_thread(dispatch, name, arguments or {})
        except ServiceError as exc:
            return [TextContent(type="text", text=f"error: {exc}")]
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async def _main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_main())
    return EXIT_OK
