"""Tests for webhook routes."""

import pytest


class TestWebhookRoutes:
    """Test webhook routes."""

    def test_webhooks_page_authenticated(self, authenticated_client):
        """Test webhooks page."""
        response = authenticated_client.get('/settings/webhooks')
        assert response.status_code == 200
