# PlayMCP in KC / 컨테이너 배포용 — uvicorn Streamable HTTP MCP 서버
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 인증키 불필요(큐레이션 KB 내장형). 플랫폼이 PORT 주입 시 사용, 없으면 8000.
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn server_http:app --host 0.0.0.0 --port ${PORT:-8000}"]
