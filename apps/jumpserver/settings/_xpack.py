# -*- coding: utf-8 -*-
#

import datetime
import os

from .base import CONFIG, INSTALLED_APPS, TEMPLATES
from .. import const

current_year = datetime.datetime.now().year
corporation = f'FIT2CLOUD 飞致云 © 2014-{current_year}'

XPACK_DIR = os.path.join(const.BASE_DIR, 'apps', 'xpack')
XPACK_ENABLED = True
JDMC_ENABLED = False
XPACK_TEMPLATES_DIR = []
XPACK_CONTEXT_PROCESSOR = []
XPACK_LICENSE_IS_VALID = False
XPACK_LICENSE_EDITION = "Standard"
XPACK_LICENSE_EDITION_ULTIMATE = False
XPACK_LICENSE_INFO = {
    'corporation': corporation,
}

XPACK_LICENSE_CONTENT = 'community'

if XPACK_ENABLED:
    from xpack.utils import get_xpack_templates_dir, get_xpack_context_processor

    INSTALLED_APPS.insert(0, 'xpack.apps.XpackConfig')
    XPACK_TEMPLATES_DIR = get_xpack_templates_dir(const.BASE_DIR)
    XPACK_CONTEXT_PROCESSOR = get_xpack_context_processor()
    TEMPLATES[0]['DIRS'].extend(XPACK_TEMPLATES_DIR)
    TEMPLATES[0]['OPTIONS']['context_processors'].extend(XPACK_CONTEXT_PROCESSOR)

