from django.db import models
from django.utils.translation import gettext_lazy as _

from assets.const import FillType
from .common import Asset


class Web(Asset):
    allowed_urls = models.JSONField(blank=True, default=list, verbose_name=_("Allowed sites"))
    autofill = models.CharField(max_length=16, choices=FillType.choices, default='basic', verbose_name=_("Autofill"))
    # XPAM: all optional — the Remote browser finds the login form and recognises success by itself
    username_selector = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_("Username selector"),
        help_text=_("Leave empty: XPAM finds the login form by itself. Example: id=username, name=user.")
    )
    password_selector = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_("Password selector"),
        help_text=_("Leave empty: XPAM uses the visible password field.")
    )
    submit_selector = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_("Submit selector"),
        help_text=_("Leave empty: XPAM presses the sign-in button (or Enter).")
    )
    success_selector = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_("Success selector"),
        help_text=_(
            "Optional: an element that appears only after a successful sign-in, e.g. css=#dashboard. "
            "Empty: the sign-in counts as successful once the login form is gone."
        )
    )
    interactive_selector = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_("Interactive selector"),
        help_text=_("Optional interactive verification area, e.g. css=#mfa-dialog. Exclude credentials and password visibility controls.")
    )
    script = models.JSONField(blank=True, default=list, verbose_name=_("Script"))
    # XPAM: Remote browser checks the site's certificate (off = self-signed internal sites; the stored
    # account would then also be sent to a site that only pretends to be this one)
    verify_cert = models.BooleanField(
        default=True, verbose_name=_("Verify certificate"),
        help_text=_("Remote browser refuses the site when its certificate is not trusted. Turn off only for "
                    "internal sites with a self-signed certificate.")
    )

    class Meta:
        verbose_name = _("Web")
