from flask import Blueprint, jsonify
from sqlalchemy import text

from src.db.engine import SessionLocal
from src.bootstrap.logging import log_event, log_exception

bp = Blueprint("health", __name__, url_prefix="")


@bp.route("/health")
def health():
    """
    Liveness and readiness probe for Kubernetes/Docker orchestration.

    Executes SELECT 1 against PostgreSQL. Returns 200 if the database is
    reachable, 200 with degraded status on timeout, and 503 when the database
    is unavailable. Used by load balancers and container orchestrators to route traffic.

    Response: {"status": "ok"}, {"status": "degraded", "detail": "<reason>"}, or {"status": "error", "detail": "<reason>"}
    Status: 200 (healthy or degraded), 503 (unhealthy)
    """
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except TimeoutError:
        log_event("health_check_degraded", reason="database timeout")
        return jsonify({"status": "degraded", "detail": "database timeout, service JWTs can not be issued"}), 200
    except Exception as e:
        log_exception("health_check_failed", e)
        return jsonify({"status": "error", "detail": "database unavailable"}), 503
