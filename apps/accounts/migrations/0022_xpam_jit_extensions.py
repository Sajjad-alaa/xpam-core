from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0021_xpam_jit_approval_route'),
    ]

    operations = [
        migrations.AddField(
            model_name='jitpolicy',
            name='allow_extension',
            field=models.BooleanField(default=True, verbose_name='Allow access extensions'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='extension_approval',
            field=models.CharField(
                choices=[
                    ('same', 'Same as initial request'),
                    ('auto', 'Approve extensions automatically'),
                    ('manual', 'Always require manual approval'),
                ],
                default='same',
                max_length=16,
                verbose_name='Extension approval',
            ),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='extension_max_hours',
            field=models.PositiveIntegerField(default=0, verbose_name='Longest extension (hours)'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='max_extensions',
            field=models.PositiveSmallIntegerField(default=0, verbose_name='Max extensions per access'),
        ),
    ]

