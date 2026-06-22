"""Remote HTTP entrypoint — Streamable HTTP MCP 서버 (PlayMCP in KC 등).

Local:        uvicorn server_http:app --host 0.0.0.0 --port 8000
MCP endpoint: http(s)://<host>[:<port>]/mcp
Health:       http(s)://<host>[:<port>]/healthz
"""
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from server import mcp

# MCP Streamable HTTP 규격상 클라이언트는 Accept 헤더에 application/json 과
# text/event-stream 을 모두 실어야 한다. 일부 클라이언트·게이트웨이(PlayMCP 심사 등)는
# 이를 누락해 모든 요청이 406 Not Acceptable 로 실패한다("No approval received").
# /mcp 요청에 한해 Accept 를 보정해 호환성을 높인다(규격을 지키는 클라이언트엔 영향 없음).
_REQUIRED_ACCEPT = b"application/json, text/event-stream"


class AcceptHeaderShim:
    """/mcp 요청의 Accept 헤더를 application/json + text/event-stream 으로 정규화."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path", "").startswith("/mcp"):
            headers = [(k, v) for k, v in scope["headers"] if k.lower() != b"accept"]
            headers.append((b"accept", _REQUIRED_ACCEPT))
            scope = {**scope, "headers": headers}
        await self.app(scope, receive, send)


async def healthz(request):  # noqa: ANN001
    return PlainTextResponse("ok")


_app = mcp.streamable_http_app()
_app.router.routes.append(Route("/healthz", healthz, methods=["GET"]))

# 미들웨어로 감싸 export — uvicorn server_http:app 로 그대로 구동.
app = AcceptHeaderShim(_app)
