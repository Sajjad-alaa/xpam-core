import django.db.models.deletion
from django.db import migrations, models


def route_from_approvers(apps, schema_editor):
    # rules that named approvers keep them; the others use the approval flow, as before
    JITPolicy = apps.get_model('accounts', 'JITPolicy')
    for policy in JITPolicy.objects.all().only('id', 'approvers'):
        value = getattr(policy.approvers, 'value', policy.approvers)
        if isinstance(value, dict) and value.get('type'):
            JITPolicy.objects.filter(id=policy.id).update(approval_route='approvers')


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0020_xpam_secret_copy'),
        ('tickets', '0011_xpam_apply_protocols'),
    ]

    operations = [
        migrations.AddField(
            model_name='jitpolicy',
            name='approval_route',
            field=models.CharField(choices=[('flow', 'An approval flow'), ('approvers', 'Specific people')],
                                   default='flow', max_length=16, verbose_name='Approved by'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='approval_flow',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='+', to='tickets.ticketflow', verbose_name='Approval flow'),
        ),
        migrations.RunPython(route_from_approvers, migrations.RunPython.noop),
    ]
