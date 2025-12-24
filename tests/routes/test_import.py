"""Tests for import routes."""

import pytest


class TestImportRoutes:
    """Test import routes."""

    def test_import_page_authenticated(self, authenticated_client):
        """Test import page."""
        response = authenticated_client.get('/import')
        assert response.status_code == 200

    def test_import_page_requires_auth(self, client):
        """Test import page requires authentication."""
        response = client.get('/import')
        assert response.status_code == 302
