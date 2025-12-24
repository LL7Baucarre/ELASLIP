"""Tests for tools routes."""

import pytest


class TestToolsRoutes:
    """Test tools routes."""

    def test_tools_page_authenticated(self, authenticated_client):
        """Test tools page."""
        response = authenticated_client.get('/tools')
        assert response.status_code == 200

    def test_tools_page_requires_auth(self, client):
        """Test tools page requires authentication."""
        response = client.get('/tools')
        assert response.status_code == 302
