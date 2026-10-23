import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0003_rename_report_range_days_to_days'),
        ('users', '0004_fix_user_wechat_phone'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomDashboard',
            fields=[
                ('created_by', models.CharField(blank=True, max_length=128, null=True, verbose_name='Created by')),
                ('updated_by', models.CharField(blank=True, max_length=128, null=True, verbose_name='Updated by')),
                ('date_created', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date created')),
                ('date_updated', models.DateTimeField(auto_now=True, verbose_name='Date updated')),
                ('comment', models.TextField(blank=True, default='', verbose_name='Comment')),
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('org_id', models.CharField(blank=True, db_index=True, default='', max_length=36, verbose_name='Organization')),
                ('name', models.CharField(max_length=128, verbose_name='Name')),
                ('description', models.CharField(blank=True, default='', max_length=512, verbose_name='Description')),
                ('icon', models.CharField(blank=True, default='dashboard', max_length=64, verbose_name='Icon')),
                ('scope', models.CharField(
                    choices=[
                        ('all', 'All dashboards (Console, PAM, Audit)'),
                        ('console', 'Console'),
                        ('pam', 'PAM'),
                        ('audit', 'Audit'),
                    ],
                    default='all', max_length=16, verbose_name='Section',
                )),
                ('template', models.CharField(blank=True, default='custom', max_length=64, verbose_name='Template')),
                ('layout', models.JSONField(blank=True, default=list, verbose_name='Widgets layout')),
                ('days', models.PositiveIntegerField(default=7, verbose_name='Default time range (days)')),
                ('refresh_seconds', models.PositiveIntegerField(default=0, verbose_name='Auto-refresh (seconds)')),
                ('is_default', models.BooleanField(default=False, verbose_name='Default dashboard')),
                ('is_shared_all', models.BooleanField(default=False, verbose_name='Share with all organization members')),
                ('sort_order', models.PositiveSmallIntegerField(default=10, verbose_name='Sort order')),
                ('owner', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='owned_dashboards', to='users.user', verbose_name='Owner',
                )),
                ('shared_users', models.ManyToManyField(
                    blank=True, related_name='shared_dashboards', to='users.user', verbose_name='Shared users',
                )),
                ('shared_groups', models.ManyToManyField(
                    blank=True, related_name='shared_dashboards', to='users.usergroup', verbose_name='Shared user groups',
                )),
            ],
            options={
                'verbose_name': 'Custom dashboard',
                'ordering': ['sort_order', 'name', '-date_created'],
            },
        ),
    ]

