from django.utils.translation import gettext_lazy as _

from common.exceptions import JMSException


class SSOAuthClosed(JMSException):
    default_code = 'sso_auth_closed'
    default_detail = _('SSO auth closed')







class IntervalTooShort(JMSException):
    default_code = 'interval_too_short'
    default_detail = _('Please wait for %s seconds before retry')

    def __init__(self, interval, *args, **kwargs):
        super().__init__(detail=self.default_detail % interval, *args, **kwargs)
