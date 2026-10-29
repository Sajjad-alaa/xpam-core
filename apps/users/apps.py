from __future__ import unicode_literals

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class UsersConfig(AppConfig):
    name = 'users'
    verbose_name = _('App Users')

    def ready(self):
        from . import signal_handlers  # noqa
        from . import tasks  # noqa
        from . import notifications  # noqa
        from . import face_sface
        # Face codes of the facelive engine (without this, check_face says "backend is not available")
        face_sface.register()
        super().ready()
