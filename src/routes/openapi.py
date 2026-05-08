from flask import Blueprint, jsonify
from src.routes.token import _load_openapi_spec
from src.bootstrap.extensions import csrf

bp = Blueprint("openapi", __name__)

@bp.route("/openapi.json")
@csrf.exempt
def openapi():
    return jsonify(_load_openapi_spec())
