# =============================================================================
# CONFIG — loads secrets from .env or environment variables
# =============================================================================

import os
from dotenv import load_dotenv

# Load local .env file automatically
load_dotenv()

# --- Google PageSpeed Insights -------------------------------------------
PSI_API_KEY = os.environ.get("PSI_API_KEY", "")
PSI_STRATEGY = os.environ.get("PSI_STRATEGY", "mobile")  # "mobile" or "desktop"

# --- Load Test (k6 / Threaded fallback) -----------------------------------
K6_VIRTUAL_USERS = int(os.environ.get("K6_VIRTUAL_USERS", 10))
K6_DURATION_SECONDS = int(os.environ.get("K6_DURATION_SECONDS", 15))
K6_RAMP_UP_SECONDS = int(os.environ.get("K6_RAMP_UP_SECONDS", 3))

# --- AI (Google AI — Gemma 27B / Gemini) ----------------------------------
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemma-4-26b-a4b-it")

# --- Flask Server ---------------------------------------------------------
FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", 5000))
FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
