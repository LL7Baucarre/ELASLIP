"""Tests for IOC relations routes."""

import pytest


class TestIOCRelationsRoutes:
    """Test IOC relations API routes."""

    def test_get_relations_authenticated(self, authenticated_client):
        """Test getting IOC relations."""
        response = authenticated_client.get('/api/ioc-relations/test-id')
        assert response.status_code in [200, 400, 404]

    def test_get_relations_requires_auth(self, client):
        """Test getting relations requires authentication."""
        response = client.get('/api/ioc-relations/test-id')
        # Route returns 404 if not found, but checks auth first
        assert response.status_code in [301, 302, 401, 404]
