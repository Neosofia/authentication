from authorization_in_the_middle.security import with_security
from flask import Blueprint, jsonify
from werkzeug.exceptions import NotFound

from src.authorization import entities
from src.bootstrap.capabilities import Capabilities
from src.bootstrap.logging import log_exception
from src.db.engine import SessionLocal
from src.services import tenant_management

bp = Blueprint("tenants", __name__, url_prefix="/api/v1/tenants")


@bp.route("/<tenant_uuid>", methods=["GET"])
@with_security(
    action=Capabilities.TENANT_READ,
    rate_limit="120 per minute",
    id_arg="tenant_uuid",
    entities_fn=entities.tenant_entities,
)
def get_tenant(tenant_uuid: str):
    """Return tenant metadata from the authentication identity store."""
    try:
        with SessionLocal() as db:
            tenant = tenant_management.get_tenant_or_404(db, tenant_uuid)
            return jsonify(tenant)
    except NotFound:
        return jsonify({"error": "not found", "message": "tenant not found"}), 404
    except Exception as exc:
        log_exception("tenant_fetch_failed", exc, tenant_uuid=tenant_uuid)
        return jsonify({"error": "failed to fetch tenant"}), 503
