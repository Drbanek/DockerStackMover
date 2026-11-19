from pathlib import Path
import re

from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .core import app, APP_VERSION
from .routes import general, proxy, migration, capacity, dns, settings, users, operations, provisioning, bootstrap_infra

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def index():
    # Version every static asset with APP_VERSION so browsers never keep stale
    # JS/CSS after a DSM update, and never cache the shell page itself.
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    html = re.sub(r'(/static/[A-Za-z0-9_.-]+\.(?:js|css))(?:\?v=[^"\']*)?(["\'])',
                  lambda m: m.group(1) + "?v=" + APP_VERSION + m.group(2), html)
    return HTMLResponse(html, headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
