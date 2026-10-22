from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('tickets', '0010_xpam_apply_extends'),
    ]

    operations = [
        migrations.AddField(
            model_name='applyassetticket',
            name='apply_protocols',
            field=models.JSONField(blank=True, default=list, verbose_name='Protocols'),
        ),
    ]
