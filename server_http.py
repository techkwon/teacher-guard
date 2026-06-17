"""Remote HTTP entrypoint — Streamable HTTP MCP 서버 (PlayMCP in KC 등).

Local:        uvicorn server_http:app --host 0.0.0.0 --port 8000
MCP endpoint: http(s)://<host>[:<port>]/mcp
Health:       http(s)://<host>[:<port>]/healthz
"""
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from server import mcp


async def healthz(request):  # noqa: ANN001
    return PlainTextResponse("ok")


app = mcp.streamable_http_app()
app.router.routes.append(Route("/healthz", healthz, methods=["GET"]))
