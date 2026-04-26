import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from workos import WorkOSClient

# Initialized without app; call csrf.init_app(app) in the app factory.
csrf = CSRFProtect()

# Rate limiter — initialized without app; call limiter.init_app(app) in the app factory.
# storage_uri defaults to in-memory (per-replica limits, acceptable for single-node, DoS protection).
# To share limits across replicas, set RATELIMIT_STORAGE_URI=redis://... in the environment.
# DDoS protection will be at the FW level. This is primarily to prevent abuse of the API and brute-force attacks on the /api/token endpoint.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

# WorkOS client — reads env vars populated by load_dotenv() in main.py.
workos_client = WorkOSClient(
    api_key=os.getenv("WORKOS_API_KEY"),
    client_id=os.getenv("WORKOS_CLIENT_ID"),
    request_timeout=5,   # fail fast if WorkOS is unreachable; callers handle 503
    max_retries=1,       # one retry for transient network blips; fail fast after that
)

cookie_password: str = os.getenv("WORKOS_COOKIE_PASSWORD", "")
is_development: bool = os.getenv("ENV", "production").lower() == "development"
