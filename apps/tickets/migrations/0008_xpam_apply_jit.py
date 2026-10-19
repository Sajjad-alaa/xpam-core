# XPAM 5.1.2

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tickets', '0007_ticketflow_name_and_five_approval_levels'),
    ]

    operations = [
        migrations.AddField(
            model_name='applyassetticket',
            name='apply_jit',
            field=models.CharField(blank=True, default='auto', max_length=64, verbose_name='Just-in-time account'),
        ),
    ]
