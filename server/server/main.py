from fastmcp import FastMCP

mcp = FastMCP("mcp-noc-telecom")

from server.tools.supervision import snmp_get

mcp.tool()(snmp_get)


if __name__ == "__main__":
    mcp.run()
