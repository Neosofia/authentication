from authorization_in_the_middle.entities import entity_uid
from authorization_in_the_middle.security import with_security
from flask import Blueprint, jsonify, request

from src.authorization import entities as auth_entities
from src.bootstrap.capabilities import Capabilities
from src.bootstrap.logging import log_exception
from src.services import idp_observability

bp = Blueprint("idp", __name__, url_prefix="/api/idp")

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100


def _parse_cursor_pagination() -> tuple[int, str | None, str | None] | tuple[None, tuple]:
    try:
        limit = min(
            _MAX_LIMIT,
            max(1, int(request.args.get("limit", _DEFAULT_LIMIT))),
        )
    except (TypeError, ValueError):
        return None, (
            jsonify({
                "error": "invalid pagination",
                "message": "limit must be an integer between 1 and 100",
            }),
            400,
        )

    before = (request.args.get("before") or "").strip() or None
    after = (request.args.get("after") or "").strip() or None
    return (limit, before, after), None


def _idp_observability_resource_uid() -> str:
    return entity_uid(
        f"{auth_entities.NAMESPACE}::IdpObservability",
        auth_entities.IDP_OBSERVABILITY_ID,
    )


@bp.route("/failed-authentications", methods=["GET"])
@with_security(
    action=Capabilities.IDP_FAILED_AUTH_READ,
    rate_limit="30 per minute",
    resource_fn=_idp_observability_resource_uid,
    entities_fn=auth_entities.idp_observability_entities,
    rest=False,
)
def list_failed_authentications():
    """
    List recent failed sign-in attempts reported by the configured identity provider.

    Cursor pagination uses provider ``before`` / ``after`` event ids (not page numbers).
    """
    parsed, error = _parse_cursor_pagination()
    if error:
        return error
    limit, before, after = parsed

    try:
        payload = idp_observability.list_failed_authentications(
            limit=limit,
            before=before,
            after=after,
        )
        return jsonify(payload), 200
    except idp_observability.IdpObservabilityUnsupportedError:
        return jsonify({
            "error": "not supported",
            "message": "configured identity provider does not expose failed authentication events",
        }), 501
    except idp_observability.IdpObservabilityUnavailableError:
        return jsonify({
            "error": "identity provider unavailable",
            "message": "unable to fetch failed authentication events",
        }), 503
    except Exception as exc:
        log_exception("list_failed_authentications_failed", exc)
        return jsonify({"error": "internal error"}), 500
