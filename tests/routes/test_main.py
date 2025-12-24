"""Tests for main routes."""

import pytest


class TestMainRoutes:
    """Test main routes."""

    def test_index_redirect_authenticated(self, authenticated_client):
        """Test authenticated users redirected to dashboard."""
        response = authenticated_client.get('/')
        assert response.status_code == 302
        assert 'dashboard' in response.location

    def test_index_redirect_unauthenticated(self, client):
        """Test unauthenticated users redirected to login."""
        response = client.get('/')
        assert response.status_code == 302
        assert 'login' in response.location

    def test_dashboard_requires_auth(self, client):
        """Test dashboard requires authentication."""
        response = client.get('/dashboard')
        assert response.status_code == 302

    def test_dashboard_authenticated(self, authenticated_client):
        """Test dashboard for authenticated user."""
        response = authenticated_client.get('/dashboard')
        assert response.status_code == 200

    def test_iocs_list_authenticated(self, authenticated_client):
        """Test IOCs list."""
        response = authenticated_client.get('/iocs')
        assert response.status_code == 200

    def test_iocs_add_authenticated(self, authenticated_client):
        """Test add IOC page."""
        response = authenticated_client.get('/iocs/add')
        assert response.status_code == 200

    def test_search_authenticated(self, authenticated_client):
        """Test search page."""
        response = authenticated_client.get('/search')
        assert response.status_code == 200

    def test_import_authenticated(self, authenticated_client):
        """Test import page."""
        response = authenticated_client.get('/import')
        assert response.status_code == 200

    def test_tools_authenticated(self, authenticated_client):
        """Test tools page."""
        response = authenticated_client.get('/tools')
        assert response.status_code == 200

    def test_activity_authenticated(self, authenticated_client):
        """Test activity page."""
        response = authenticated_client.get('/activity')
        assert response.status_code == 200

    def test_settings_authenticated(self, authenticated_client):
        """Test settings page."""
        response = authenticated_client.get('/settings')
        assert response.status_code == 200
