"""
Server entrypoint — run with:

    # Development (auto-reload)
    python -m apk_extractor.api.server

    # Or directly:
    uvicorn apk_extractor.api.server:app --host 0.0.0.0 --port 8000 --reload

Environment Variables
---------------------
    GEMINI_API_KEY      — Required for LLM explanation (Stage 3)
MODELS_DIR          — Path to .pkl model files (default: ./models)
MAX_APK_SIZE_MB     — Max upload size in MB (default: 100)
LOG_LEVEL           — Logging level (default: INFO)
PORT                — Server port (default: 8000)
HOST                — Server host (default: 0.0.0.0)
"""

import os
import sys
from pathlib import Path

# Ensure src/ is on the path when running as __main__
_src = Path(__file__).resolve().parents[3]
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import uvicorn
from apk_extractor.api.app import create_app

# Create the ASGI app (used by uvicorn when this module is imported as a string)
app = create_app()

if __name__ == "__main__":
    host      = os.environ.get("HOST", "0.0.0.0")
    port      = int(os.environ.get("PORT", "8000"))
    log_level = os.environ.get("LOG_LEVEL", "info").lower()
    reload    = os.environ.get("RELOAD", "true").lower() == "true"

    print(f"\n{'='*60}")
    print(f"  Android Malware Detection API")
    print(f"  http://{host}:{port}")
    print(f"  Docs: http://{host}:{port}/docs")
    print(f"  LLM: {'enabled' if os.environ.get('GEMINI_API_KEY') else 'disabled (set GEMINI_API_KEY)'}")
    print(f"{'='*60}\n")

    uvicorn.run(
        "apk_extractor.api.server:app",
        host=host,
        port=port,
        log_level=log_level,
        reload=reload,
        reload_dirs=[str(Path(__file__).resolve().parents[3])],
    )
