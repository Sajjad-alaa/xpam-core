"""Face codes made by the XPAM facelive engine (OpenCV SFace).

A face code is "xpamf1:" followed by the base64 of 128 little-endian float32 numbers: the SFace feature
of the face, scaled to length 1. Two codes are compared with the cosine similarity of the two features.
The codes carry no image. They are registered with users.face_codec when the users app starts.
"""
import base64
import binascii
import math
import struct

from .face_codec import register_face_codec

CODE_PREFIX = 'xpamf1:'
FEATURE_SIZE = 128
_RAW_SIZE = FEATURE_SIZE * 4
_STRUCT = struct.Struct('<%df' % FEATURE_SIZE)


def encode_code(values):
    """Used by tests and tools; the engine makes the same format on its side."""
    if len(values) != FEATURE_SIZE:
        raise ValueError('A face feature has %d numbers.' % FEATURE_SIZE)
    norm = math.sqrt(sum(v * v for v in values))
    if not norm or not math.isfinite(norm):
        raise ValueError('The face feature is empty.')
    raw = _STRUCT.pack(*[v / norm for v in values])
    return CODE_PREFIX + base64.b64encode(raw).decode('ascii')


def decode_code(code):
    if not isinstance(code, str) or not code.startswith(CODE_PREFIX):
        raise ValueError('Not a face code of this server.')
    try:
        raw = base64.b64decode(code[len(CODE_PREFIX):], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('The face code is damaged.') from None
    if len(raw) != _RAW_SIZE:
        raise ValueError('The face code has the wrong size.')
    values = list(_STRUCT.unpack(raw))
    if not all(math.isfinite(v) for v in values):
        raise ValueError('The face code is damaged.')
    return values


def is_native_code(code):
    try:
        values = decode_code(code)
    except ValueError:
        return False
    return math.sqrt(sum(v * v for v in values)) > 0.5


def _unit(values):
    norm = math.sqrt(sum(v * v for v in values))
    if not norm:
        raise ValueError('The face code is empty.')
    return [v / norm for v in values]


def similarity(stored_code, candidate_code):
    """Cosine similarity of two codes, or None when one of them is not a valid code."""
    try:
        a = _unit(decode_code(stored_code))
        b = _unit(decode_code(candidate_code))
    except ValueError:
        return None
    return sum(x * y for x, y in zip(a, b))


def compare_codes(stored_code, candidate_code, *, cosine_threshold, distance_threshold):
    """True when the two faces are the same person.

    cosine_threshold: smallest cosine similarity. distance_threshold: largest L2 distance between the two
    features scaled to length 1 (that distance is sqrt(2 - 2 * cosine), so the two limits say the same thing
    when set as a pair; when they differ the stricter one wins).
    """
    cosine = similarity(stored_code, candidate_code)
    if cosine is None:
        return False
    distance = math.sqrt(max(0.0, 2.0 - 2.0 * cosine))
    return cosine >= float(cosine_threshold) and distance <= float(distance_threshold)


def register():
    register_face_codec(
        is_native_code=is_native_code,
        compare_codes=compare_codes,
        decode_code=decode_code,
    )
