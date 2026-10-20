"""
XPAM: web admin pages of FortiGate and Palo Alto devices in the Remote browser — the platforms get an
HTTP(S) protocol (port 443) with their login form fields, and their assets get the protocol too.
Platforms the administrator has changed keep their own HTTP protocol when they have one.
"""
from django.db import migrations

BASE = {'autofill': 'basic', 'success_selector': '', 'interactive_selector': '', 'script': [],
        'safe_mode': False, 'verify_cert': False}
FORMS = {
    'FortiGate': {'username_selector': 'id=username', 'password_selector': 'id=secretkey',
                  'submit_selector': 'id=login_button'},
    'PaloAlto': {'username_selector': 'id=user', 'password_selector': 'id=passwd',
                 'submit_selector': 'id=submit'},
}


def forwards(apps, schema_editor):
    platform_model = apps.get_model('assets', 'Platform')
    protocol_model = apps.get_model('assets', 'PlatformProtocol')
    asset_protocol_model = apps.get_model('assets', 'Protocol')
    asset_model = apps.get_model('assets', 'Asset')
    for name, form in FORMS.items():
        platform = platform_model.objects.filter(name=name, category='device').first()
        if not platform:
            continue
        if not protocol_model.objects.filter(platform=platform, name='http').exists():
            protocol_model.objects.create(platform=platform, name='http', port=443, primary=False, required=False,
                                          default=True, public=True, setting={**BASE, **form})
        for asset in asset_model.objects.filter(platform=platform):
            if not asset_protocol_model.objects.filter(asset=asset, name='http').exists():
                asset_protocol_model.objects.create(asset=asset, name='http', port=443)


class Migration(migrations.Migration):
    dependencies = [
        ('assets', '0031_xpam_web_verify_cert'),
    ]

    operations = [
        migrations.RunPython(forwards, reverse_code=migrations.RunPython.noop),
    ]
