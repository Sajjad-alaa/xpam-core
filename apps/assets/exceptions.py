from django.utils.translation import gettext_lazy as _

from common.exceptions import JMSException


class NotSupportedTemporarilyError(JMSException):
    default_detail = _("This function is not supported temporarily")
