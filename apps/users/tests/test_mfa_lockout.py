import random

from django.test import TestCase, override_settings
from rest_framework.serializers import ValidationError

from authentication.mfa.face import MFAFace
from authentication.mfa.policy import usable_mfa_types
from settings.serializers.security import SecurityAuthSerializer
from users import face_sface
from users.models import User
from users.serializers import UserSerializer

FACE_ON = dict(FACE_RECOGNITION_ENABLED=True, XPACK_LICENSE_IS_VALID=True)


def face_code(seed=1):
    rnd = random.Random(seed)
    return face_sface.encode_code([rnd.uniform(-1, 1) for _ in range(face_sface.FEATURE_SIZE)])


@override_settings(**FACE_ON)
class MFALockoutTest(TestCase):
    """ An admin cannot leave a user without an MFA method to sign in with (e.g. face only, no face enrolled). """

    def setUp(self):
        face_sface.register()
        self.user = User.objects.create(username='mfa-lockout', name='MFA lockout', email='lockout@example.com')

    def check(self, user, allowed):
        UserSerializer(instance=user).check_mfa_lockout({'allowed_mfa_types': allowed})

    def test_face_only_without_a_face_is_refused(self):
        with self.assertRaises(ValidationError) as caught:
            self.check(self.user, ['face'])
        self.assertIn('allowed_mfa_types', caught.exception.detail)

    def test_face_only_with_a_face_and_otp_with_face_are_accepted(self):
        self.check(self.user, ['otp', 'face'])
        self.user.face_vector = face_code()
        self.user.save(update_fields=['face_vector'])
        self.check(self.user, ['face'])

    def test_a_new_user_cannot_be_created_face_only(self):
        new = {'allowed_mfa_types': ['email'], 'email': 'new@example.com'}
        with self.assertRaises(ValidationError):
            UserSerializer().check_mfa_lockout(dict(new, allowed_mfa_types=['face']))
        with self.assertRaises(ValidationError):  # (email MFA is off by default)
            UserSerializer().check_mfa_lockout(new)
        with self.settings(SECURITY_MFA_BY_EMAIL=True):
            UserSerializer().check_mfa_lockout(new)  # (the address is in the form)
            with self.assertRaises(ValidationError):
                UserSerializer().check_mfa_lockout(dict(new, email=''))

    def test_an_unchanged_list_does_not_block_other_edits(self):
        User.objects.filter(pk=self.user.pk).update(allowed_mfa_types=['face'])
        self.user.refresh_from_db()
        self.check(self.user, ['face'])
        self.check(self.user, [])  # (empty: the global methods)

    @override_settings(FACE_RECOGNITION_ENABLED=False)
    def test_a_method_that_is_off_does_not_count(self):
        self.user.face_vector = face_code()
        self.user.save(update_fields=['face_vector'])
        with self.assertRaises(ValidationError):
            self.check(self.user, ['face'])

    def test_the_only_face_cannot_be_removed(self):
        self.user.face_vector = face_code()
        self.user.allowed_mfa_types = ['face']
        self.user.save(update_fields=['face_vector', 'allowed_mfa_types'])
        self.assertFalse(MFAFace(self.user).can_disable())
        self.assertEqual(usable_mfa_types(self.user), {'face'})
        self.user.allowed_mfa_types = ['face', 'otp']
        self.assertTrue(MFAFace(self.user).can_disable())

    def test_global_methods_need_one_that_can_be_set_up_while_signing_in(self):
        serializer = SecurityAuthSerializer()
        for methods in (['face'], ['passkey'], ['face', 'passkey']):
            with self.assertRaises(ValidationError):
                serializer.validate({'SECURITY_MFA_AUTH': 0, 'SECURITY_MFA_METHODS': methods})
        serializer.validate({'SECURITY_MFA_AUTH': 0, 'SECURITY_MFA_METHODS': ['face', 'otp']})
