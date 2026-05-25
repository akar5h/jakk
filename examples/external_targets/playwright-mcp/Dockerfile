# microsoft/playwright-mcp wrapped for the docker-compose target pattern.
# Base image ships Playwright + browsers pre-installed, so we just npx the MCP server.
FROM mcr.microsoft.com/playwright:v1.49.0-jammy

WORKDIR /app

ENV NODE_ENV=production \
    MCP_PORT=8765 \
    MCP_HOST=0.0.0.0

EXPOSE 8765

# --port / --host flags taken from @playwright/mcp README. npx fetches at first run; the
# downloaded package is then cached in the image's npm cache layer.
CMD ["sh", "-c", "npx -y @playwright/mcp@latest --port $MCP_PORT --host $MCP_HOST"]
