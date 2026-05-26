import uuid as _uuid
from functools import wraps
from flask import Blueprint, jsonify, request, g
from authentication_in_the_middle.decorators import with_authentication

from src.config import settings
from src.db.engine import SessionLocal
from src.bootstrap.extensions import limiter
from src.bootstrap.logging import log_event, log_exception
from src.services import service_management

bp = Blueprint("services", __name__, url_prefix="/api/services")


def require_admin(f):
    @with_authentication(
        public_key=settings.jwt_public_key_pem,
        audience=settings.jwt_web_audience,
        enforce_active_role=False
    )
    @wraps(f)
    def decorated(*args, **kwargs):
        claims = getattr(g, "jwt_claims", {})

        roles = claims.get(f"{settings.jwt_claim_namespace}:roles", [])
        if "admin" not in roles and "platform-admin" not in roles:
            return jsonify({"error": "forbidden", "message": "requires admin role"}), 403

        user_uuid = claims.get("sub")
        if not user_uuid:
            return jsonify({"error": "unauthenticated", "message": "re-authenticate to obtain a platform identity"}), 401
        try:
            _uuid.UUID(str(user_uuid))
        except ValueError:
            return jsonify({"error": "unauthenticated", "message": "re-authenticate to obtain a platform identity"}), 401
        kwargs["user_uuid"] = user_uuid
        return f(*args, **kwargs)
    return decorated




@bp.route("", methods=["GET"])
@limiter.limit("60 per minute")
@require_admin
def list_services(user_uuid: str):
    """
    List registered platform services with credential metadata.
    Supports pagination and search by name, slug, or base_url.
    """
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(100, max(1, int(request.args.get("page_size", 20))))
    search = (request.args.get("q", "") or "").strip()

    try:
        with SessionLocal() as db:
            items, total = service_management.list_services(db, page, page_size, search)
            return jsonify({
                "items": items,
                "total": total,
                "page": page,
                "page_size": page_size,
            }), 200
    except Exception as exc:
        log_exception("list_services_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("", methods=["POST"])
@limiter.limit("60 per minute")
@require_admin
def create_service(user_uuid: str):
    """
    Register a new platform service and generate its service credentials exactly once.
    """
    data = request.get_json()
    if not data or not all(k in data for k in ("name", "slug", "base_url")):
        return jsonify({"error": "missing required fields (name, slug, base_url)"}), 400

    name = data["name"].strip()
    slug = data["slug"].strip()
    base_url = data["base_url"].strip()

    try:
        with SessionLocal() as db:
            result = service_management.create_service(db, user_uuid, name, slug, base_url)
            log_event("service_created", service_slug=slug, admin=user_uuid)
            return jsonify(result), 201
    except service_management.ConflictError:
        return jsonify({"error": "service name or slug or base_url already exists"}), 409
    except Exception as exc:
        log_exception("create_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>", methods=["GET"])
@limiter.limit("60 per minute")
@require_admin
def get_service(slug: str, user_uuid: str):
    """Return details for a single service including its latest credential metadata."""
    try:
        with SessionLocal() as db:
            result = service_management.get_service(db, slug)
            return jsonify(result), 200
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except Exception as exc:
        log_exception("get_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>", methods=["PUT"])
@limiter.limit("60 per minute")
@require_admin
def update_service(slug: str, user_uuid: str):
    """Update name, slug, or base_url for a service."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "request body required"}), 400

    allowed = {"name", "slug", "base_url"}
    updates = {k: v.strip() for k, v in data.items() if k in allowed and isinstance(v, str)}
    if not updates:
        return jsonify({"error": "no updatable fields provided"}), 400

    try:
        with SessionLocal() as db:
            result = service_management.update_service(db, slug, user_uuid, updates)
            log_event("service_updated", service_slug=result["slug"], admin=user_uuid)
            return jsonify(result), 200
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except service_management.ConflictError:
        return jsonify({"error": "name, slug, or base_url already in use"}), 409
    except Exception as exc:
        log_exception("update_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>/rotate", methods=["POST"])
@limiter.limit("60 per minute")
@require_admin
def rotate_service(slug: str, user_uuid: str):
    """
    Rotate the active service credential in-place. The audit trigger captures
    the before-image automatically so history is preserved without extra rows.
    Returns the new plaintext secret exactly once.
    """
    try:
        with SessionLocal() as db:
            result = service_management.rotate_service(db, slug, user_uuid)
            log_event("service_credential_rotated", service_slug=slug, admin=user_uuid)
            return jsonify(result), 200
    except service_management.CredentialNotFoundError:
        return jsonify({"error": "no credential"}), 404
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except Exception as exc:
        log_exception("rotate_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>/audits", methods=["GET"])
@limiter.limit("60 per minute")
@require_admin
def get_service_audits(slug: str, user_uuid: str):
    """Return paginated audit history for a service's credentials."""
    page = max(1, int(request.args.get("page", 1)))
    page_size = min(100, max(1, int(request.args.get("page_size", 20))))
    source = request.args.get("source")

    try:
        with SessionLocal() as db:
            service = service_management.get_service(db, slug)
            items, total = service_management.get_service_audits(
                db,
                service["uuid"],
                source,
                page,
                page_size,
            )

            return jsonify({
                "service_uuid": service["uuid"],
                "slug": service["slug"],
                "total": total,
                "page": page,
                "page_size": page_size,
                "items": items,
            }), 200
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except service_management.InvalidAuditSourceError:
        return jsonify({"error": "invalid source", "message": "source must be 'service' or 'credential'"}), 400
    except Exception as exc:
        log_exception("get_service_audits_failed", exc)
        return jsonify({"error": "database error"}), 500

