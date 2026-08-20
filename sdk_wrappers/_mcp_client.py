"""
Shared MCP client — talks the real protocol (JSON-RPC over Streamable
HTTP) via the official `mcp` Python SDK. Every framework wrapper in
this package calls through here; none of them touch HTTP directly.
"""

# --- PATCH dedup_tool_full_name ---
import asyncio
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_SERVER_URL = "https://live-entity-verification.railway.app/mcp"


async def _call_tool_async(tool_name: str, arguments: dict) -> Any:
    async with streamablehttp_client(MCP_SERVER_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            if result.isError:
                error_text = "; ".join(
                    getattr(c, "text", str(c)) for c in result.content
                )
                raise RuntimeError(f"MCP tool '{tool_name}' returned an error: {error_text}")
            if result.structuredContent is not None:
                return result.structuredContent
            return "\n".join(getattr(c, "text", str(c)) for c in result.content)


def call_mcp_tool(tool_name: str, arguments: dict) -> Any:
    """Sync entry point — safe to call from sync framework code
    (CrewAI's BaseTool._run, AutoGen's registered functions).
    If already inside an event loop (e.g. an async LangChain agent),
    use call_mcp_tool_async instead."""
    return asyncio.run(_call_tool_async(tool_name, arguments))


async def call_mcp_tool_async(tool_name: str, arguments: dict) -> Any:
    return await _call_tool_async(tool_name, arguments)
