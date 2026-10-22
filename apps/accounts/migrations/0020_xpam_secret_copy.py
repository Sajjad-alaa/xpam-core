import common.db.fields
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0019_xpam_jit_protocols_actions'),
    ]

    operations = [
        migrations.AddField(
            model_name=model,
            name='_secret_copy',
            field=common.db.fields.EncryptTextField(blank=True, null=True, verbose_name='Secret copy'),
        )
        for model in ('account', 'accounttemplate', 'personalassetcredential')
    ]
