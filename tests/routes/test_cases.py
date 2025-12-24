"""Tests for cases routes."""

import pytest


class TestCasesRoutes:
    """Test cases routes."""

    def test_cases_requires_auth(self, client):
        """Test cases requires authentication."""
        response = client.get('/cases')
        assert response.status_code == 302

    def test_cases_authenticated(self, authenticated_client):
        """Test cases for authenticated user."""
        response = authenticated_client.get('/cases')
        assert response.status_code == 200
