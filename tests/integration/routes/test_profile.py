from unittest.mock import patch, MagicMock

def test_profile_unauthorized(client, api_spec, validate_response):
    with patch("src.routes.profile.workos_client"):
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

    with patch("src.routes.profile.workos_client") as mock_workos:
        mock_user = MagicMock()
        mock_user.first_name = "Jane"
        mock_user.last_name = "Doe"
        mock_user.email = "jane@example.com"
        
        mock_org = MagicMock()
        mock_org.name = "Acme Corp"
        
        mock_workos.user_management.get_user.return_value = mock_user
        mock_workos.organizations.get_organization.return_value = mock_org

        response = client.get("/api/profile", headers={
            "Authorization": f"Bearer {human_token}"
        })
        
        assert response.status_code == 200
        validate_response(api_spec, "/api/profile", "get", 200, response.json)
