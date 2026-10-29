from django.utils.translation import gettext_lazy as _

from common.exceptions import JMSException


class StorageInvalid(JMSException):
    default_code = 'storage_invalid'
    default_detail = _('Storage is invalid')
