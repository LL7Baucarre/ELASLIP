"""Tests for auth routes."""

import pytest


class TestAuthRoutes:
    """Test authentication routes."""

    def test_login_get(self, client):
        """Test login page."""
        response = client.get('/auth/login')
        assert response.status_code == 200

    def test_logout(self, authenticated_client):
        """Test logout."""
        response = authenticated_client.get('/auth/logout')
        assert response.status_code in [200, 302]
