from django.db import migrations

# Upstream code name -> XPAM name, for components that registered before the names were normalised
PREFIXES = (
    ('[Chen]', '[WebConnector]'),
    ('[KoKo]', '[SecureConnection]'),
    ('[Koko]', '[SecureConnection]'),
    ('[Lion]', '[SecureConnection Desktop]'),
    ('[Kael]', '[AI]'),
)


def rename_component_terminals(apps, schema_editor):
    Terminal = apps.get_model('terminal', 'Terminal')
    for old, new in PREFIXES:
        for terminal in Terminal.objects.filter(name__startswith=old):
            new_name = new + terminal.name[len(old):]
            if Terminal.objects.filter(name=new_name).exists():
                continue
            terminal.name = new_name
            terminal.save(update_fields=['name'])


class Migration(migrations.Migration):

    dependencies = [
        ('terminal', '0016_xpam_worker_label'),
    ]

    operations = [
        migrations.RunPython(rename_component_terminals, migrations.RunPython.noop),
    ]
