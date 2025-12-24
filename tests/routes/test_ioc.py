"""Tests for IOC routes."""

import pytest


class TestIOCRoutes:
    """Test IOC API routes."""

    def test_list_iocs_requires_auth(self, client):
        """Test listing IOCs requires authentication."""
        response = client.get('/api/ioc')
        assert response.status_code in [301, 302, 401]

    def test_list_iocs_authenticated(self, authenticated_client):
        """Test listing IOCs."""
        response = authenticated_client.get('/api/ioc')
        assert response.status_code in [200, 400]

    def test_get_ioc_requires_auth(self, client):
        """Test getting IOC requires authentication."""
        response = client.get('/api/ioc/test-id')
        assert response.status_code in [301, 302, 401]

    def test_get_ioc_not_found(self, authenticated_client):
        """Test getting non-existent IOC."""
        response = authenticated_client.get('/api/ioc/nonexistent')
        assert response.status_code in [404, 400]
