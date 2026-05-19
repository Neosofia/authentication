from unittest.mock import patch, MagicMock

def test_profile_unauthorized(client, api_spec, validate_response):
    response = client.get("/api/profile")
    assert response.status_code == 401
    validate_response(api_spec, "/api/profile", "get", 401, response.json)

def test_profile_happy_path(client, api_spec, validate_response, app):
    with app.app_context():
        from src.services.tokens import issue_token
        from src.config import settings
        human_token = issue_token(
            sub="user_123",
            token_type="human",
            roles=["admin"],
            tenant_id="tenant_456",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )

    with patch("src.routes.profile.SessionLocal") as mock_db_session:
        mock_db = MagicMock()
        mock_db_session.return_value.__enter__.return_value = mock_db
        
        mock_user = MagicMock()
        mock_user.uuid = "user_123"
        mock_user.first_name = "Jane"
        mock_user.last_name = "Doe"
        mock_user.email = "jane@example.com"
        
        mock_org = MagicMock()
        mock_org.uuid = "tenant_456"
        mock_org.name = "Acme Corp"
        
        # When querying for User or Tenant
        mock_db.scalar.side_effect = [mock_user, mock_org]

        response = client.get("/api/profile", headers={
            "Authorization": f"Bearer {human_token}"
        })
        
        assert response.status_code == 200
        assert response.json["first_name"] == "Jane"
        assert response.json["tenant_name"] == "Acme Corp"
        validate_response(api_spec, "/api/profile", "get", 200, response.json)
