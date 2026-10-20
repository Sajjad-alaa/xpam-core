from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0016_xpam_jit_approvers'),
    ]

    operations = [
        migrations.AddField(
            model_name='jitpolicy',
            name='device_role',
            field=models.CharField(choices=[('read_only', 'Read only'), ('operator', 'Operator'), ('admin', 'Administrator'), ('custom', 'Custom')], default='read_only', max_length=16, verbose_name='Device role'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='device_custom_role',
            field=models.CharField(blank=True, default='', max_length=128, verbose_name='Custom device role'),
        ),
    ]
