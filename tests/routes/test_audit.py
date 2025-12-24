"""Tests for audit routes."""

import pytest


class TestAuditRoutes:
    """Test audit routes."""

    def test_activity_authenticated(self, authenticated_client):
        """Test activity page."""
        response = authenticated_client.get('/activity')
        assert response.status_code == 200

    def test_activity_requires_auth(self, client):
        """Test activity requires authentication."""
        response = client.get('/activity')
        assert response.status_code == 302
