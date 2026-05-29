from authorization_in_the_middle.security import with_security
from flask import Blueprint, jsonify, request

from src.authorization import entities as auth_entities
from src.bootstrap.capabilities import Capabilities
from src.bootstrap.logging import log_event, log_exception
from src.db.engine import SessionLocal
from src.services import service_management

bp = Blueprint("services", __name__, url_prefix="/api/services")

_DEFAULT_PAGE_SIZE = 20
_MAX_PAGE_SIZE = 100


def _parse_pagination() -> tuple[int, int] | tuple[None, tuple]:
    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(
            _MAX_PAGE_SIZE,
            max(1, int(request.args.get("page_size", _DEFAULT_PAGE_SIZE))),
        )
    except (TypeError, ValueError):
        return None, (
            jsonify({"error": "invalid pagination", "message": "page and page_size must be integers"}),
            400,
        )
    return (page, page_size), None


@bp.route("", methods=["GET"])
@with_security(
    action=Capabilities.SERVICE_LIST,
    rate_limit="60 per minute",
    entities_fn=auth_entities.service_catalog_entities,
)
def list_services():
    """
    List registered platform services with credential metadata.
    Supports pagination and search by name, slug, or base_url.
    """
    pagination, error = _parse_pagination()
    if error:
        return error
    page, page_size = pagination
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
@with_security(
    action=Capabilities.SERVICE_CREATE,
    rate_limit="60 per minute",
    entities_fn=auth_entities.service_catalog_entities,
)
def create_service():
    """
    Register a new platform service and generate its service credentials exactly once.
    """
    data = request.get_json()
    if not data or not all(k in data for k in ("name", "slug", "base_url")):
        return jsonify({"error": "missing required fields (name, slug, base_url)"}), 400

    name = data["name"].strip()
    slug = data["slug"].strip()
    base_url = data["base_url"].strip()
    operator_uuid = auth_entities.principal_sub()

    try:
        with SessionLocal() as db:
            result = service_management.create_service(db, operator_uuid, name, slug, base_url)
            log_event("service_created", service_slug=slug, operator=operator_uuid)
            return jsonify(result), 201
    except service_management.ConflictError:
        return jsonify({"error": "service name or slug or base_url already exists"}), 409
    except Exception as exc:
        log_exception("create_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>", methods=["GET"])
@with_security(
    action=Capabilities.SERVICE_READ,
    rate_limit="60 per minute",
    id_arg="slug",
    entities_fn=auth_entities.service_entities,
)
def get_service(slug: str):
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
@with_security(
    action=Capabilities.SERVICE_UPDATE,
    rate_limit="60 per minute",
    id_arg="slug",
    entities_fn=auth_entities.service_entities,
)
def update_service(slug: str):
    """Update name, slug, or base_url for a service."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "request body required"}), 400

    allowed = {"name", "slug", "base_url"}
    updates = {k: v.strip() for k, v in data.items() if k in allowed and isinstance(v, str)}
    if not updates:
        return jsonify({"error": "no updatable fields provided"}), 400

    operator_uuid = auth_entities.principal_sub()
    try:
        with SessionLocal() as db:
            result = service_management.update_service(db, slug, operator_uuid, updates)
            log_event("service_updated", service_slug=result["slug"], operator=operator_uuid)
            return jsonify(result), 200
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except service_management.ConflictError:
        return jsonify({"error": "name, slug, or base_url already in use"}), 409
    except Exception as exc:
        log_exception("update_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>/rotate", methods=["POST"])
@with_security(
    action=Capabilities.SERVICE_ROTATE,
    rate_limit="60 per minute",
    id_arg="slug",
    entities_fn=auth_entities.service_entities,
)
def rotate_service(slug: str):
    """
    Rotate the active service credential in-place. The audit trigger captures
    the before-image automatically so history is preserved without extra rows.
    Returns the new plaintext secret exactly once.
    """
    operator_uuid = auth_entities.principal_sub()
    try:
        with SessionLocal() as db:
            result = service_management.rotate_service(db, slug, operator_uuid)
            log_event("service_credential_rotated", service_slug=slug, operator=operator_uuid)
            return jsonify(result), 200
    except service_management.CredentialNotFoundError:
        return jsonify({"error": "no credential"}), 404
    except service_management.NotFoundError:
        return jsonify({"error": "not found"}), 404
    except Exception as exc:
        log_exception("rotate_service_failed", exc)
        return jsonify({"error": "database error"}), 500


@bp.route("/<slug>/audits", methods=["GET"])
@with_security(
    action=Capabilities.SERVICE_AUDIT_READ,
    rate_limit="60 per minute",
    id_arg="slug",
    entities_fn=auth_entities.service_entities,
)
def get_service_audits(slug: str):
    """Return paginated audit history for a service's credentials."""
    pagination, error = _parse_pagination()
    if error:
        return error
    page, page_size = pagination
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
