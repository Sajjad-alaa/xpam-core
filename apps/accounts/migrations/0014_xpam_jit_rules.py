# XPAM 5.1.2: just-in-time policies apply by rules (users, assets, priority)

import django.core.validators
from django.db import migrations, models

import common.db.fields


def forwards(apps, schema_editor):
    JITPolicy = apps.get_model('accounts', 'JITPolicy')
    AssetPermission = apps.get_model('perms', 'AssetPermission')
    for policy in JITPolicy.objects.all():
        for_requests = policy.apply_to_requests or policy.mode == 'approved_window'
        policy.scope = 'requests' if for_requests else 'linked'
        policy.users = {'type': 'all'}
        policy.assets = {'type': 'all'}
        policy.save(update_fields=['scope', 'users', 'assets'])
        if for_requests:
            # 5.1.1 attached the policy to approved requests by itself; the rules cover them now
            AssetPermission.objects.filter(jit_policy=policy, from_ticket=True).update(jit_policy=None)


def backwards(apps, schema_editor):
    JITPolicy = apps.get_model('accounts', 'JITPolicy')
    JITPolicy.objects.filter(scope__in=['requests', 'all']).update(apply_to_requests=True)


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0013_xpam_jit_requests'),
        ('perms', '0007_xpam_jit_disabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='jitpolicy',
            name='scope',
            field=models.CharField(choices=[('linked', 'Only the asset permissions linked to it'), ('requests', 'Approved access requests'), ('all', 'Asset permissions and approved access requests')], default='all', max_length=16, verbose_name='Applies to'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='users',
            field=common.db.fields.JSONManyToManyField(default=dict, to='users.User', verbose_name='Users'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='assets',
            field=common.db.fields.JSONManyToManyField(default=dict, to='assets.Asset', verbose_name='Assets'),
        ),
        migrations.AddField(
            model_name='jitpolicy',
            name='priority',
            field=models.IntegerField(default=50, help_text='1-100, the lower the value will be match first', validators=[django.core.validators.MinValueValidator(1), django.core.validators.MaxValueValidator(100)], verbose_name='Priority'),
        ),
        migrations.AlterModelOptions(
            name='jitpolicy',
            options={'ordering': ['priority', 'name'], 'verbose_name': 'Just-in-time policy'},
        ),
        migrations.RunPython(forwards, backwards),
        migrations.RemoveField(
            model_name='jitpolicy',
            name='apply_to_requests',
        ),
    ]
