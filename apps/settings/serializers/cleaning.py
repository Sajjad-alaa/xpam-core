from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

__all__ = ['CleaningSerializer']

MIN_VALUE= settings.LOG_KEEP_MIN_DAYS

class CleaningSerializer(serializers.Serializer):
    PREFIX_TITLE = _('Period clean')

    LOGIN_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Login log retention days"),
    )
    TASK_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Task log retention days"),
    )
    OPERATE_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Operate log retention days"),
    )
    PASSWORD_CHANGE_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Password change log retention days"),
    )
    FTP_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("FTP log retention days"),
    )
    CLOUD_SYNC_TASK_EXECUTION_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Cloud sync task history retention days"),
    )
    JOB_EXECUTION_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("job execution retention days"),
    )
    ACTIVITY_LOG_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Activity log retention days"),
    )
    TERMINAL_SESSION_KEEP_DURATION = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=99999, required=True, label=_('Session log retention days'),
        help_text=_(
            'Session, record, command will be delete if more than duration, only in database, OSS will not be affected.')
    )
    # XPAM: a full disk stops XPAM; recordings are what fills it
    TERMINAL_REPLAY_MAX_GB = serializers.IntegerField(
        min_value=0, max_value=1000000, required=False, default=0, label=_('Recordings: size limit (GB)'),
        help_text=_('Session recordings kept on this server use at most this much space: the oldest are deleted '
                    'first. 0: no limit. Recordings in object storage (S3, SFTP...) are not affected.')
    )
    TERMINAL_REPLAY_MIN_FREE_PERCENT = serializers.IntegerField(
        min_value=0, max_value=90, required=False, default=10, label=_('Recordings: keep disk free (%)'),
        help_text=_('When the disk holding the recordings has less free space than this, the oldest recordings '
                    'are deleted until it has (checked every 10 minutes). 0: off.')
    )

    ACCOUNT_CHANGE_SECRET_RECORD_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Change secret and push record retention days"),
    )
    AUDIT_REPORT_SEND_RECORD_KEEP_DAYS = serializers.IntegerField(
        min_value=MIN_VALUE, max_value=9999,
        label=_("Audit report send record retention days"),
    )