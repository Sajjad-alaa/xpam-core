from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('tickets', '0009_xpam_apply_jit_auto'),
    ]

    operations = [
        migrations.AddField(
            model_name='applyassetticket',
            name='apply_extends',
            field=models.CharField(blank=True, default='', max_length=36, verbose_name='Extends access'),
        ),
    ]
