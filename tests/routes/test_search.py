"""Tests for search routes."""

import pytest


class TestSearchRoutes:
    """Test search routes."""

    def test_search_page_authenticated(self, authenticated_client):
        """Test search page."""
        response = authenticated_client.get('/search')
        assert response.status_code == 200

    def test_search_page_requires_auth(self, client):
        """Test search page requires authentication."""
        response = client.get('/search')
        assert response.status_code == 302
