# XPAM 5.1.2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('perms', '0006_xpam_jit_policy'),
    ]

    operations = [
        migrations.AddField(
            model_name='assetpermission',
            name='jit_disabled',
            field=models.BooleanField(default=False, verbose_name='No just-in-time account'),
        ),
    ]
