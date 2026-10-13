# -*- coding: utf-8 -*-
#
import datetime
import os
import re
from django.conf import settings
from django.templatetags.static import static
from django.utils.translation import gettext_lazy as _

default_interface = dict((
    ('logo_logout', static('img/logo.png')),
    ('logo_index', static('img/logo_text_white.svg')),
    ('login_image', static('img/login_image.png')),
    ('logo_white', static('img/logo_white.png')),
    ('logo_text_white', static('img/logo_text_white.svg')),
    ('favicon', static('img/facio.ico')),
    # XPAM: product name and look of a new installation (everything can be changed in the console)
    ('login_title', 'XPAM'),
    ('theme', 'midnight_dark'),
    ('theme_mode', 'light'),
    ('custom_primary', '#38bdf8'),
    ('theme_info', {}),
    ('footer_content', ''),
    # XPAM: show the product version without the upstream edition suffix (v5.0.0-ce -> v5.0.0)
    ('version', re.sub(r'-ce$', '', os.environ.get("CURRENT_VERSION", "")))
))

current_year = datetime.datetime.now().year

default_context = {
    'DEFAULT_PK': '00000000-0000-0000-0000-000000000000',
    'LOGIN_CAS_logo_logout': static('img/login_cas_logo.png'),
    'LOGIN_WECOM_logo_logout': static('img/login_wecom_logo.png'),
    'LOGIN_DINGTALK_logo_logout': static('img/login_dingtalk_logo.png'),
    'LOGIN_FEISHU_logo_logout': static('img/login_feishu_logo.png'),
    'COPYRIGHT': '',
    'INTERFACE': default_interface,
}


def jumpserver_processor(request):
    from settings.utils import get_interface_setting_or_default
    # Setting default pk
    context = {**default_context}
    try:
        context['INTERFACE'] = get_interface_setting_or_default()
    except Exception:
        pass
    context.update({
        'VERSION': settings.VERSION,
        'SECURITY_COMMAND_EXECUTION': settings.SECURITY_COMMAND_EXECUTION,
        'SECURITY_MFA_VERIFY_TTL': settings.SECURITY_MFA_VERIFY_TTL,
        'FORCE_SCRIPT_NAME': settings.FORCE_SCRIPT_NAME,
        'SECURITY_VIEW_AUTH_NEED_MFA': settings.SECURITY_VIEW_AUTH_NEED_MFA,
    })
    return context
