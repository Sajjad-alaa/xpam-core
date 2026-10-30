from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ('audits', '0009_alter_passwordchangelog_datetime'),
        ('tickets', '0011_xpam_apply_protocols'),  # (XPAM: a proxy of Ticket; XPAM's tickets history)
    ]

    operations = [
        migrations.CreateModel(
            name='TicketAudit',
            fields=[],
            options={
                'verbose_name': 'Ticket audit',
                'proxy': True,
                'default_permissions': ('view',),
                'indexes': [],
                'constraints': [],
            },
            bases=('tickets.ticket',),
        ),
    ]
