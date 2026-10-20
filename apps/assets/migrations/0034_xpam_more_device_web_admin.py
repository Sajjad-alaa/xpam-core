"""
XPAM: web admin pages of Juniper (J-Web), Huawei and H3C devices in the Remote browser. These platforms
also cover switches and routers without a web server, so HTTP(s) is offered (one click on the asset)
but not added to every device. The login form is found automatically.
"""
from django.db import migrations

SETTING = {'autofill': 'basic', 'username_selector': '', 'password_selector': '', 'submit_selector': '',
           'success_selector': '', 'interactive_selector': '', 'script': [], 'safe_mode': False,
           'verify_cert': False}


def forwards(apps, schema_editor):
    platform_model = apps.get_model('assets', 'Platform')
    protocol_model = apps.get_model('assets', 'PlatformProtocol')
    for name in ('Juniper', 'Huawei', 'H3C'):
        platform = platform_model.objects.filter(name=name, category='device').first()
        if not platform or protocol_model.objects.filter(platform=platform, name='http').exists():
            continue
        protocol_model.objects.create(platform=platform, name='http', port=443, primary=False, required=False,
                                      default=False, public=True, setting=dict(SETTING))


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0033_xpam_web_selector_help'),
    ]

    operations = [
        migrations.RunPython(forwards, reverse_code=migrations.RunPython.noop),
    ]
