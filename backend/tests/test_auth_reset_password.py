"""
Tests for the /api/auth/reset-password endpoint (CWE-287 remediation).

The endpoint must require authentication, and only the account owner or an
admin may change a password.
"""
from models import User, db


URL = '/api/auth/reset-password'


class TestResetPasswordAuthentication:
    """Unauthenticated callers must not be able to reset any password"""

    def test_unauthenticated_request_rejected(self, client, sample_user):
        response = client.post(URL, json={
            'email': sample_user.email,
            'new_password': 'attacker-pass',
        })
        assert response.status_code == 401
        db.session.refresh(sample_user)
        assert sample_user.check_password('password123')
        assert not sample_user.check_password('attacker-pass')

    def test_invalid_token_rejected(self, client, sample_user):
        response = client.post(
            URL,
            json={'email': sample_user.email, 'new_password': 'attacker-pass'},
            headers={'Authorization': 'Bearer not-a-valid-token'},
        )
        assert response.status_code == 401
        db.session.refresh(sample_user)
        assert sample_user.check_password('password123')


class TestResetPasswordAuthorization:
    """Authenticated callers may only reset what they own (or admin)"""

    def test_owner_can_reset_own_password(self, client, sample_user, auth_headers):
        response = client.post(
            URL,
            json={'email': sample_user.email, 'new_password': 'brand-new-pass'},
            headers=auth_headers,
        )
        assert response.status_code == 200
        db.session.refresh(sample_user)
        assert sample_user.check_password('brand-new-pass')

    def test_user_cannot_reset_other_users_password(
            self, client, sample_user, admin_user, auth_headers):
        response = client.post(
            URL,
            json={'email': admin_user.email, 'new_password': 'attacker-pass'},
            headers=auth_headers,
        )
        assert response.status_code == 403
        db.session.refresh(admin_user)
        assert admin_user.check_password('admin123')

    def test_unknown_email_indistinguishable_from_foreign(
            self, client, sample_user, auth_headers):
        response = client.post(
            URL,
            json={'email': 'nobody@example.com', 'new_password': 'x-pass'},
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_admin_can_reset_other_users_password(
            self, client, sample_user, admin_auth_headers):
        response = client.post(
            URL,
            json={'email': sample_user.email, 'new_password': 'admin-set-pass'},
            headers=admin_auth_headers,
        )
        assert response.status_code == 200
        db.session.refresh(sample_user)
        assert sample_user.check_password('admin-set-pass')

    def test_missing_fields_rejected(self, client, auth_headers):
        response = client.post(URL, json={}, headers=auth_headers)
        assert response.status_code == 400
