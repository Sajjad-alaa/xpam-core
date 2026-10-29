from django.utils.translation import gettext_lazy as _
from common.exceptions import JMSException


class UnableToDeleteAllUsers(JMSException):
    default_code = 'unable_to_delete_all_users'
    default_detail = _('Unable to delete all users')


class CreateSSHKeyExceedLimit(JMSException):
    default_code = 'create_ssh_key_exceed_limit'
    default_detail = _('Create failed. The number of SSH keys has reached the limit')
