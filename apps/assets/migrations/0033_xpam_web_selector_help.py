from django.db import migrations, models


class Migration(migrations.Migration):
    """Help texts only: the sign-in selectors of web assets are optional (found automatically)."""

    dependencies = [
        ('assets', '0032_xpam_device_web_admin'),
    ]

    operations = [
        migrations.AlterField(
            model_name='web', name='username_selector',
            field=models.CharField(blank=True, default='', max_length=128, verbose_name='Username selector',
                                   help_text='Leave empty: XPAM finds the login form by itself. Example: id=username, name=user.'),
        ),
        migrations.AlterField(
            model_name='web', name='password_selector',
            field=models.CharField(blank=True, default='', max_length=128, verbose_name='Password selector',
                                   help_text='Leave empty: XPAM uses the visible password field.'),
        ),
        migrations.AlterField(
            model_name='web', name='submit_selector',
            field=models.CharField(blank=True, default='', max_length=128, verbose_name='Submit selector',
                                   help_text='Leave empty: XPAM presses the sign-in button (or Enter).'),
        ),
        migrations.AlterField(
            model_name='web', name='success_selector',
            field=models.CharField(blank=True, default='', max_length=128, verbose_name='Success selector',
                                   help_text='Optional: an element that appears only after a successful sign-in, e.g. '
                                             'css=#dashboard. Empty: the sign-in counts as successful once the login form is gone.'),
        ),
    ]
