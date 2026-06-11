import pytest
from flask import Flask, g

from src.authorization import entities

pytestmark = pytest.mark.unit


def test_resolve_principal_builds_operator_user():
    app = Flask(__name__)
    with app.test_request_context():
        g.jwt_claims = {
            "sub": "00000000-0000-7000-8000-000000000001",
            "neosofia:actors": ["operator"],
            "neosofia:token_type": "human",
        }
        principal = entities.resolve_principal()

    assert principal["uid"]["__entity"]["type"] == "authentication::User"
    assert principal["attrs"]["isOperator"] is True


def test_resolve_principal_builds_service_entity():
    app = Flask(__name__)
    with app.test_request_context():
        g.jwt_claims = {
            "sub": "care-episode",
            "neosofia:token_type": "service",
        }
        principal = entities.resolve_principal()

    assert principal["uid"]["__entity"]["type"] == "authentication::Service"
    assert principal["uid"]["__entity"]["id"] == "care-episode"
    assert principal["attrs"]["serviceSlug"] == "care-episode"
    assert principal["attrs"]["tokenType"] == "service"
