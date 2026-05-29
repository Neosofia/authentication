from unittest.mock import MagicMock, patch

_PROFILE_ID = "019e02e1-94e1-722b-bd61-f7f95fb1602a"
_PROFILE_PATH = f"/api/v1/profiles/{_PROFILE_ID}"


def test_profile_unauthorized(client, api_spec, validate_response):
    response = client.get(_PROFILE_PATH)
    assert response.status_code == 401
    validate_response(api_spec, _PROFILE_PATH, "get", 401, response.json)


def test_profile_happy_path(client, api_spec, validate_response, app):
    with app.app_context():
        from src.config import settings
        from src.services.tokens import issue_token

        human_token = issue_token(
            sub=_PROFILE_ID,
            token_type="human",
            roles=["operator"],
            tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1601f",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )

    with patch("src.routes.profile.SessionLocal") as mock_db_session:
        mock_db = MagicMock()
        mock_db_session.return_value.__enter__.return_value = mock_db

        mock_user = MagicMock()
        mock_user.uuid = _PROFILE_ID
        mock_user.idp_id = "user_01HABC"
        mock_user.first_name = "Jane"
        mock_user.last_name = "Doe"
        mock_user.email = "jane@example.com"

        mock_org = MagicMock()
        mock_org.uuid = "019e02e1-94e1-722b-bd61-f7f95fb1601f"
        mock_org.name = "Acme Corp"

        mock_db.scalar.side_effect = [mock_user, mock_org]

        response = client.get(
            _PROFILE_PATH,
            headers={"Authorization": f"Bearer {human_token}"},
        )

        assert response.status_code == 200
        assert response.json["first_name"] == "Jane"
        assert response.json["tenant_name"] == "Acme Corp"
        validate_response(api_spec, _PROFILE_PATH, "get", 200, response.json)
