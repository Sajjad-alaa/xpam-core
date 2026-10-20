from django.db import migrations, models


class Migration(migrations.Migration):
    """Existing web assets keep working as before (not verified); new ones verify by default."""

    dependencies = [
        ('assets', '0030_xpam_network_platforms'),
    ]

    operations = [
        migrations.AddField(
            model_name='web',
            name='verify_cert',
            field=models.BooleanField(default=False, verbose_name='Verify certificate'),
        ),
        migrations.AlterField(
            model_name='web',
            name='verify_cert',
            field=models.BooleanField(
                default=True, verbose_name='Verify certificate',
                help_text='Remote browser refuses the site when its certificate is not trusted. Turn off only '
                          'for internal sites with a self-signed certificate.'),
        ),
    ]
