"""CI-safe MCP smoke: initialize handshake + tools/list only. No live scan."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=["-u", "-m", "infosec_recon.mcp_server"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            expected = {"cancel_scan", "get_findings", "get_scan_data",
                        "list_modules", "list_scans", "run_scan",
                        "scan_status"}
            assert expected <= set(names), f"missing tools: {expected - set(names)}"

            r = await session.call_tool("list_modules", {})
            mods = json.loads(r.content[0].text)
            assert set(mods) == {"recon", "cvescan", "jsleak", "leakhunt",
                                 "cloudhunt", "phishlab"}, mods
    print("MCP SMOKE OK")


asyncio.run(main())
