import accounts.models.jit
import perms.const
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0018_xpam_vault_routing'),
    ]

    operations = [
        migrations.AddField(
            model_name='jitpolicy',
            name='protocols',
            field=models.JSONField(default=accounts.models.jit.default_rule_protocols, verbose_name='Allowed protocols'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='actions',
            field=models.IntegerField(default=perms.const.ActionChoices.all, verbose_name='Allowed actions'),
        ),
    ]
