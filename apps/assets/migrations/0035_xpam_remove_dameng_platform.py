# XPAM: Dameng (a China-only database) is no longer supported. Remove the built-in Dameng platform
# when no asset uses it; its protocols and automation go with it (CASCADE). A platform that still has
# assets is left alone, so the upgrade never fails or orphans an asset.
from django.db import migrations


def remove_unused_dameng_platforms(apps, schema_editor):
    Platform = apps.get_model('assets', 'Platform')
    Platform.objects.filter(type='dameng', assets__isnull=True).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('assets', '0034_xpam_more_device_web_admin'),
    ]

    operations = [
        migrations.RunPython(remove_unused_dameng_platforms, migrations.RunPython.noop),
    ]
