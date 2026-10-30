import json

from django.conf import settings
from django.test import Client, TestCase

from rbac.builtin import BuiltinRole
from users.models import User

J = 'application/json'


class ClosedGapsTest(TestCase):
    """ The gaps closed after the security review: version, custom SSO checks, malformed input. """

    def setUp(self):
        BuiltinRole.sync_to_db()
        self.admin = User.objects.get(username='admin')
        User.objects.filter(pk=self.admin.pk).update(is_first_login=False)
        self.anon = Client(HTTP_HOST='localhost')
        self.client = Client(HTTP_HOST='localhost')
        self.client.force_login(self.admin)

    def test_the_login_page_does_not_tell_the_version(self):
        anon = self.anon.get('/api/v1/settings/public/open/').json()['INTERFACE']
        self.assertNotIn('version', anon)
        signed_in = self.client.get('/api/v1/settings/public/open/').json()['INTERFACE']
        self.assertIn('version', signed_in)

    def test_custom_sso_goes_through_the_login_checks(self):
        self.assertIn(settings.AUTH_BACKEND_CUSTOM_SSO, settings.AUTHENTICATION_BACKENDS_THIRD_PARTY)

    def test_malformed_input_is_a_bad_request(self):
        self.assertEqual(self.client.get('/api/v1/assets/categories/constraints/').status_code, 400)
        r = self.client.post('/api/v1/terminal/tasks/kill-session-for-ticket/', data=json.dumps({'x': 1}),
                             content_type=J)
        self.assertEqual(r.status_code, 400)
        r = self.client.post('/api/v1/ops/playbooks/', data=json.dumps({}), content_type=J)
        self.assertEqual(r.status_code, 400)

    def test_the_login_confirmation_status_does_not_sign_out(self):
        # (a GET any page could embed: without a confirmation in progress it changes nothing)
        self.assertEqual(self.client.get('/api/v1/authentication/login-confirm-ticket/status/').status_code, 404)
        self.assertEqual(self.client.get('/api/v1/users/profile/').status_code, 200)

    def test_a_passkey_is_made_by_registration_only(self):
        r = self.client.post('/api/v1/authentication/passkeys/', data=json.dumps({}), content_type=J)
        self.assertEqual(r.status_code, 405)
