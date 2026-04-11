from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import HTMLResponse


app = FastAPI()


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>GuardRail Demo App</title>
      <style>
        :root {{
          color-scheme: light;
          font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        }}
        body {{
          margin: 0;
          min-height: 100vh;
          display: grid;
          place-items: center;
          background:
            radial-gradient(circle at top, #dbeafe 0%, #f8fafc 48%, #e2e8f0 100%);
          color: #0f172a;
        }}
        main {{
          width: min(680px, calc(100% - 32px));
          padding: 32px;
          border-radius: 20px;
          background: rgba(255, 255, 255, 0.92);
          box-shadow: 0 24px 60px rgba(15, 23, 42, 0.12);
        }}
        h1 {{
          margin: 0 0 12px;
          font-size: clamp(2rem, 4vw, 2.8rem);
        }}
        p {{
          margin: 0 0 16px;
          line-height: 1.6;
        }}
        .status {{
          display: inline-flex;
          align-items: center;
          gap: 10px;
          margin: 8px 0 20px;
          padding: 10px 14px;
          border-radius: 999px;
          background: #ecfdf5;
          color: #166534;
          font-weight: 600;
        }}
        .status-dot {{
          width: 12px;
          height: 12px;
          border-radius: 999px;
          background: #22c55e;
          box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.15);
        }}
        .meta {{
          padding-top: 16px;
          border-top: 1px solid #cbd5e1;
          color: #334155;
          font-size: 0.95rem;
        }}
        code {{
          padding: 2px 6px;
          border-radius: 6px;
          background: #e2e8f0;
          font-size: 0.95em;
        }}
      </style>
    </head>
    <body>
      <main>
        <h1>GuardRail Demo App</h1>
        <p>This is the release target protected by GuardRail. The supply-chain pipeline decides whether this container is allowed to deploy.</p>
        <div class="status">
          <span class="status-dot" aria-hidden="true"></span>
          <span>Health status: ok</span>
        </div>
        <p class="meta">Current UTC timestamp: <code>{timestamp_utc}</code></p>
      </main>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/hello")
def hello() -> dict[str, str]:
    return {"message": "hello"}
