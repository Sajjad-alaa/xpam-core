import math
import random
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings
from users import face_codec, face_sface
from users.models.user._face import FaceMixin


def make_feature(seed, size=face_sface.FEATURE_SIZE):
    rng = random.Random(seed)
    return [rng.uniform(-1, 1) for _ in range(size)]


def blend(feature, other, weight):
    """A feature that is `weight` like `other` (0 = same as feature)."""
    return [a * (1 - weight) + b * weight for a, b in zip(feature, other)]


class FaceSubject(FaceMixin):
    pass


class FaceSfaceCodeTest(SimpleTestCase):
    def test_encode_decode_keeps_the_feature_scaled_to_length_one(self):
        feature = make_feature(1)
        code = face_sface.encode_code(feature)

        self.assertTrue(code.startswith('xpamf1:'))
        decoded = face_sface.decode_code(code)
        self.assertEqual(len(decoded), 128)
        self.assertAlmostEqual(math.sqrt(sum(v * v for v in decoded)), 1.0, places=5)
        norm = math.sqrt(sum(v * v for v in feature))
        for original, value in zip(feature, decoded):
            self.assertAlmostEqual(original / norm, value, places=5)

    def test_is_native_code_checks_prefix_size_and_content(self):
        good = face_sface.encode_code(make_feature(2))
        self.assertTrue(face_sface.is_native_code(good))
        self.assertFalse(face_sface.is_native_code(None))
        self.assertFalse(face_sface.is_native_code(''))
        self.assertFalse(face_sface.is_native_code('enterprise-face-code'))
        self.assertFalse(face_sface.is_native_code(good[len('xpamf1:'):]))
        self.assertFalse(face_sface.is_native_code(good[:-8]))
        self.assertFalse(face_sface.is_native_code('xpamf1:' + '!' * 684))
        self.assertFalse(face_sface.is_native_code('xpamf1:'))
        # all zero numbers and NaN are not a face
        zero = 'xpamf1:' + __import__('base64').b64encode(bytes(512)).decode()
        self.assertFalse(face_sface.is_native_code(zero))
        nan = 'xpamf1:' + __import__('base64').b64encode(b'\x00\x00\xc0\x7f' * 128).decode()
        self.assertFalse(face_sface.is_native_code(nan))

    def test_decode_code_raises_for_a_bad_code(self):
        with self.assertRaises(ValueError):
            face_sface.decode_code('nope')
        with self.assertRaises(ValueError):
            face_sface.decode_code('xpamf1:AAAA')

    def test_encode_code_refuses_a_bad_feature(self):
        with self.assertRaises(ValueError):
            face_sface.encode_code([0.0] * 128)
        with self.assertRaises(ValueError):
            face_sface.encode_code([1.0] * 12)


class FaceSfaceCompareTest(SimpleTestCase):
    thresholds = dict(cosine_threshold=0.40, distance_threshold=1.0955)

    def test_same_feature_matches(self):
        code = face_sface.encode_code(make_feature(3))
        self.assertAlmostEqual(face_sface.similarity(code, code), 1.0, places=5)
        self.assertTrue(face_sface.compare_codes(code, code, **self.thresholds))

    def test_close_feature_matches_and_far_feature_does_not(self):
        base = make_feature(4)
        other = make_feature(5)
        stored = face_sface.encode_code(base)
        near = face_sface.encode_code(blend(base, other, 0.3))
        far = face_sface.encode_code(other)

        self.assertGreater(face_sface.similarity(stored, near), 0.40)
        self.assertTrue(face_sface.compare_codes(stored, near, **self.thresholds))
        self.assertLess(face_sface.similarity(stored, far), 0.40)
        self.assertFalse(face_sface.compare_codes(stored, far, **self.thresholds))

    def test_cut_is_on_the_cosine_threshold(self):
        base = make_feature(6)
        other = make_feature(7)
        stored = face_sface.encode_code(base)
        # search the blend weight where the cosine crosses 0.40
        low, high = 0.0, 1.0
        for _ in range(40):
            mid = (low + high) / 2
            if face_sface.similarity(stored, face_sface.encode_code(blend(base, other, mid))) > 0.40:
                low = mid
            else:
                high = mid
        inside = face_sface.encode_code(blend(base, other, low - 0.01))
        outside = face_sface.encode_code(blend(base, other, high + 0.01))
        self.assertTrue(face_sface.compare_codes(stored, inside, **self.thresholds))
        self.assertFalse(face_sface.compare_codes(stored, outside, **self.thresholds))

    def test_the_stricter_of_the_two_limits_wins(self):
        base = make_feature(8)
        stored = face_sface.encode_code(base)
        candidate = face_sface.encode_code(blend(base, make_feature(9), 0.3))
        cosine = face_sface.similarity(stored, candidate)
        distance = math.sqrt(2 - 2 * cosine)

        self.assertTrue(face_sface.compare_codes(
            stored, candidate, cosine_threshold=cosine - 0.01, distance_threshold=distance + 0.01))
        self.assertFalse(face_sface.compare_codes(
            stored, candidate, cosine_threshold=cosine + 0.01, distance_threshold=distance + 0.01))
        self.assertFalse(face_sface.compare_codes(
            stored, candidate, cosine_threshold=cosine - 0.01, distance_threshold=distance - 0.01))

    def test_bad_codes_never_match(self):
        code = face_sface.encode_code(make_feature(10))
        self.assertIsNone(face_sface.similarity(code, 'enterprise-face-code'))
        self.assertIsNone(face_sface.similarity('', code))
        self.assertFalse(face_sface.compare_codes(code, 'junk', **self.thresholds))
        self.assertFalse(face_sface.compare_codes('junk', code, **self.thresholds))


class FaceSfaceRegistrationTest(SimpleTestCase):
    @override_settings(FACE_RECOGNITION_COSINE_THRESHOLD=0.40, FACE_RECOGNITION_DISTANCE_THRESHOLD=1.0955)
    def test_registered_codec_serves_check_face(self):
        base = make_feature(11)
        stored = face_sface.encode_code(base)
        same_person = face_sface.encode_code(blend(base, make_feature(12), 0.25))
        other_person = face_sface.encode_code(make_feature(13))
        subject = FaceSubject()
        subject.face_vector = stored

        with patch('users.face_codec._adapter', None):
            face_sface.register()
            self.assertIsNotNone(face_codec.get_face_codec())
            self.assertTrue(subject.is_face_code_set)
            self.assertTrue(subject.check_face(same_person))
            self.assertFalse(subject.check_face(other_person))
            self.assertFalse(subject.check_face('enterprise-face-code'))
            self.assertEqual(len(subject.get_face_vector()), 128)

    def test_a_face_in_another_format_is_not_a_set_face(self):
        subject = FaceSubject()
        subject.face_vector = 'enterprise-face-code'
        with patch('users.face_codec._adapter', None):
            face_sface.register()
            self.assertFalse(subject.is_face_code_set)
            with self.assertRaises(ValidationError):
                FaceSubject().check_face(face_sface.encode_code(make_feature(14)))

    def test_users_app_registers_the_codec(self):
        # (the users app calls face_sface.register() in ready())
        self.assertIsNotNone(face_codec.get_face_codec())
