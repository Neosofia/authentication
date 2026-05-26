from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from workos import WorkOSClient

from src.config import settings

# Rate limiter — initialized without app; call limiter.init_app(app) in the app factory.
# storage_uri defaults to in-memory (per-replica limits, acceptable for single-node, DoS protection).
# To share limits across replicas, set RATELIMIT_STORAGE_URI=redis://... in the environment.
# DDoS protection will be at the FW level. This is primarily to prevent abuse of the API and brute-force attacks on the /api/token endpoint.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=settings.ratelimit_storage_uri,
)

workos_client = WorkOSClient(
    api_key=settings.workos_api_key,
    client_id=settings.workos_client_id,
    request_timeout=5,   # fail fast if WorkOS is unreachable; callers handle 503
    max_retries=1,       # one retry for transient network blips; fail fast after that
)
