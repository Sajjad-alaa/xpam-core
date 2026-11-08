# XPAM: WeCom, DingTalk, FeiShu, Lark and Slack are no longer supported. Drop them from the stored
# message subscriptions, so only existing channels (e-mail, site message) are left.
from django.db import migrations

REMOVED = {'wecom', 'dingtalk', 'feishu', 'lark', 'slack'}


def remove_chat_channels(apps, schema_editor):
    for model_name in ('UserMsgSubscription', 'SystemMsgSubscription'):
        model = apps.get_model('notifications', model_name)
        for sub in model.objects.all().only('id', 'receive_backends'):
            backends = sub.receive_backends or []
            kept = [b for b in backends if b not in REMOVED]
            if kept != backends:
                model.objects.filter(id=sub.id).update(receive_backends=kept)


class Migration(migrations.Migration):

    dependencies = [
        ('notifications', '0003_messagecontent_display_mode'),
    ]

    operations = [
        migrations.RunPython(remove_chat_channels, migrations.RunPython.noop),
    ]
