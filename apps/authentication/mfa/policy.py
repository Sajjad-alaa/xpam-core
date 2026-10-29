from django.conf import settings
from django.utils.module_loading import import_string
from django.utils.translation import gettext as _

from authentication.const import MFAType

# MFA methods that must be set up while signed in: a face or a passkey cannot be added in the middle of a login
# (a password alone must not be enough to register one). A user whose only methods are these, and not set up, is
# locked out.
SETUP_WHEN_SIGNED_IN = {MFAType.Face.value, MFAType.Passkey.value}
# Methods a user can set up while signing in (the login sends the user to bind an authenticator app)
SETUP_AT_SIGNIN = {MFAType.OTP.value}


def get_allowed_mfa_types(user=None):
    user_allowed = getattr(user, 'allowed_mfa_types', None)
    if user_allowed:
        return set(user_allowed)
    return set(settings.SECURITY_MFA_METHODS or MFAType.values)


def _is_set_up(backend):
    try:
        return bool(backend.is_active())
    except ValueError:
        return False  # (a user not saved yet has no passkeys)


def usable_mfa_types(user, allowed=None, without=()):
    """ The MFA methods this user can sign in with, or set up while signing in.

    allowed: the methods to consider (default: those the user may use); without: methods to count as not set up
    (one about to be reset or removed).
    """
    allowed = set(allowed) if allowed else get_allowed_mfa_types(user)
    usable = set()
    for path in settings.MFA_BACKENDS:
        cls = import_string(path)
        if cls.name not in allowed or not cls.global_enabled():
            continue
        if cls.name in SETUP_AT_SIGNIN or (cls.name not in without and _is_set_up(cls(user))):
            usable.add(cls.name)
    return usable


def lockout_message(allowed):
    """ Why a list of MFA methods would leave the user unable to sign in. """
    labels = ', '.join(str(MFAType(name).label) for name in sorted(allowed) if name in MFAType.values)
    return _(
        'The user could not sign in: none of the allowed MFA methods ({}) is set up or available. '
        'A face or a passkey can only be added while signed in, so allow OTP as well until the user has set '
        'one up (or turn the method on in the settings).'
    ).format(labels)
