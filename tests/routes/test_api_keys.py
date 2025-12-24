"""Tests for API keys routes."""

import pytest


class TestAPIKeysRoutes:
    """Test API keys routes."""

    def test_api_keys_page_authenticated(self, authenticated_client):
        """Test API keys page."""
        response = authenticated_client.get('/settings/api-keys')
        assert response.status_code == 200
