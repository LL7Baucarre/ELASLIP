"""Tests for API config routes."""

import pytest


class TestAPIConfigRoutes:
    """Test API configuration routes."""

    def test_api_config_authenticated(self, authenticated_client):
        """Test API config page."""
        response = authenticated_client.get('/settings/external-apis')
        assert response.status_code == 200

    def test_api_config_requires_auth(self, client):
        """Test API config requires authentication."""
        response = client.get('/settings/external-apis')
        assert response.status_code == 302
