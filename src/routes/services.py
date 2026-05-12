import secrets
from functools import wraps
import bcrypt
import jwt as pyjwt
from flask import Blueprint, jsonify, request
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from src.config import settings
from src.db.engine import SessionLocal
from src.models.service import Service
from src.models.service_credential import ServiceCredential
from src.bootstrap.extensions import csrf
from src.bootstrap.logging import log_event

bp = Blueprint("services", __name__, url_prefix="/api/services")

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "unauthenticated"}), 401

        raw_token = auth_header[7:]
        try:
            decoded = pyjwt.decode(
                raw_token,
                settings.jwt_public_key_pem,
                algorithms=["RS256"],
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
                options={"require": ["exp", "iat", "iss", "sub", "aud"]},
            )
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "token expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        user_id = decoded.get("sub")
        if not user_id:
            return jsonify({"error": "invalid token"}), 401
            
        roles = decoded.get(f"{settings.jwt_claim_namespace}:roles", [])
        if "admin" not in roles and "platform-admin" not in roles:
             return jsonify({"error": "forbidden", "message": "requires admin role"}), 403

        # Inject into request or kwargs if needed
        kwargs["user_uuid"] = user_id
        return f(*args, **kwargs)
    return decorated


@bp.route("", methods=["GET"])
@csrf.exempt
@require_admin
def list_services(user_uuid: str):
    """
    List all registered platform services.
    """
    try:
        with SessionLocal() as db:
            services = db.scalars(select(Service).order_by(Service.name)).all()
            return jsonify([
                {
                    "uuid": str(svc.uuid),
                    "name": svc.name,
                    "slug": svc.slug,
                    "base_url": svc.base_url
                }
                for svc in services
            ]), 200
    except Exception as e:
        log_event("list_services_failed", error_class=type(e).__name__)
        return jsonify({"error": "database error"}), 500


@bp.route("", methods=["POST"])
@csrf.exempt
@require_admin
def create_service(user_uuid: str):
    """
    Register a new platform service and generate its machine credentials exactly once.
    """
    data = request.get_json()
    if not data or not all(k in data for k in ("name", "slug", "base_url")):
        return jsonify({"error": "missing required fields (name, slug, base_url)"}), 400

    name = data["name"].strip()
    slug = data["slug"].strip()
    base_url = data["base_url"].strip()

    # Generate a secure random secret
    plain_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(plain_secret.encode(), bcrypt.gensalt()).decode()

    try:
        with SessionLocal() as db:
            # Audit setup (1 = User Actor)
            db.execute(text("SET LOCAL app.current_actor_uuid = :actor").bindparams(actor=user_uuid))
            db.execute(text("SET LOCAL app.current_actor_type = '1'"))

            new_service = Service(name=name, slug=slug, base_url=base_url)
            db.add(new_service)
            db.flush() # flush to get uuid

            new_credential = ServiceCredential(
                service_uuid=new_service.uuid,
                hashed_secret=hashed_secret
            )
            db.add(new_credential)

            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return jsonify({"error": "service name or slug or base_url already exists"}), 409

            log_event("service_created", service_slug=slug, admin=user_uuid)
            
            return jsonify({
                "uuid": str(new_service.uuid),
                "name": new_service.name,
                "slug": new_service.slug,
                "base_url": new_service.base_url,
                "client_secret": plain_secret  # returned EXACTLY ONCE
            }), 201

    except Exception as e:
        log_event("create_service_failed", error_class=type(e).__name__)
        return jsonify({"error": "database error"}), 500
