# XPAM: no usable token in a copy of the database.
# - connection token values are encrypted like account secrets (existing values encrypted here);
# - OAuth2 access/refresh tokens are kept only as their SHA-256 (COMPLIANT_BCP_RFC9700_TOKEN_STORAGE):
#   the plain copies of tokens issued before are blanked (the lookup already uses token_checksum).
import common.db.fields
from django.db import migrations


def encrypt_values(apps, schema_editor):
    from common.db.utils import Encryptor
    conn = schema_editor.connection
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, value FROM authentication_connectiontoken WHERE value <> ''")
        rows = cursor.fetchall()
        for pk, value in rows:
            if len(value) > 64:  # already encrypted
                continue
            cursor.execute("UPDATE authentication_connectiontoken SET value = %s WHERE id = %s",
                           [Encryptor(value).encrypt(), pk])


def decrypt_values(apps, schema_editor):
    from common.db.utils import Encryptor
    conn = schema_editor.connection
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, value FROM authentication_connectiontoken WHERE value <> ''")
        for pk, value in cursor.fetchall():
            if len(value) <= 64:
                continue
            cursor.execute("UPDATE authentication_connectiontoken SET value = %s WHERE id = %s",
                           [Encryptor(value).decrypt()[:64], pk])


def blank_oauth_tokens(apps, schema_editor):
    for name in ('AccessToken', 'RefreshToken'):
        model = apps.get_model('oauth2_provider', name)
        model.objects.exclude(token='').exclude(token_checksum='').update(token='')


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0010_connectiontoken_personal_credential_id'),
        ('oauth2_provider', '0022_refreshtoken_token_family_index'),
    ]

    operations = [
        migrations.AlterField(
            model_name='connectiontoken',
            name='value',
            field=common.db.fields.EncryptCharField(default='', max_length=64, verbose_name='Value'),
        ),
        migrations.RunPython(encrypt_values, decrypt_values),
        migrations.RunPython(blank_oauth_tokens, migrations.RunPython.noop),
    ]
