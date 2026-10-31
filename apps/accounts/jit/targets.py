"""
Just-in-time accounts on databases and network devices.

Hosts use the push/remove automations (Ansible). Databases and devices are handled here, directly
from the worker, with the privileged account of the asset:

database  MySQL/MariaDB, PostgreSQL, SQL Server, Oracle: a login with the rights the policy chooses
          (read only, read and write, administrator or custom SQL); removal ends the user's
          database sessions and drops the login.
device    FortiGate, Palo Alto, Cisco IOS/ASA/NX-OS, Juniper, Huawei, H3C: the built-in drivers
          (libs/ansible/modules_utils/network_device.py) create the account with the policy's role,
          also through the asset's gateway. Other SSH devices: the policy's command templates are run
          in an interactive shell, like the "SSH account push" automation.
"""
import contextlib
import re
import tempfile

from django.utils.translation import gettext as _

from common.utils import get_logger
from .policy import admin_account

logger = get_logger(__name__)

CONNECT_TIMEOUT = 15
DEFAULT_PORTS = {'mysql': 3306, 'mariadb': 3306, 'postgresql': 5432, 'sqlserver': 1433, 'oracle': 1521}


class TargetError(Exception):
    pass


class TargetExists(TargetError):
    """The name is already taken on the target by an account XPAM did not create: never touch it."""


def db_username(name):
    """Database logins: letters, digits and "_" only (Oracle and SQL Server do not like "-")."""
    return name.replace('-', '_')


def _db_spec(asset):
    from assets.models import Database
    db = Database.objects.filter(id=asset.id).first()
    tp = asset.platform.type
    port = asset.get_protocol_port(tp) or asset.get_protocol_port('mariadb' if tp == 'mysql' else tp) \
        or DEFAULT_PORTS.get(tp, 0)
    return tp, port, (db.db_name if db else '') or '', db


def _admin(asset):
    account = admin_account(asset)
    if not account:
        raise TargetError(_('Add a privileged account on the asset that may create users'))
    return account


def _custom_sql(policy, username, database):
    text = (policy.db_custom_sql or '').replace('{username}', username).replace('{database}', database)
    return [s.strip() for s in re.split(r';\s*(?:\n|$)', text) if s.strip()]


def _ident_check(name):
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,29}', name):
        raise TargetError(_('Invalid database account name: %s') % name)


# ---------------------------------------------------------------- MySQL / MariaDB

def _mysql_conn(asset, user, password, port, database='', db=None):
    import MySQLdb
    kwargs = dict(host=asset.address, port=int(port), user=user, passwd=password,
                  connect_timeout=CONNECT_TIMEOUT, autocommit=True)
    if database:
        kwargs['db'] = database
    if db and db.use_ssl:
        kwargs['ssl'] = {'ca': None} if db.allow_invalid_cert else {}
    return MySQLdb.connect(**kwargs)


def _mysql_create(asset, admin, username, password, policy, port, database, db):
    conn = _mysql_conn(asset, admin.username, admin.secret, port, db=db)
    try:
        cur = conn.cursor()
        cur.execute("CREATE USER %s@'%%' IDENTIFIED BY %s", (username, password))
        target = '`{}`.*'.format(database.replace('`', '``')) if database else '*.*'
        privileges = {
            'read_only': 'SELECT, SHOW VIEW',
            'read_write': 'SELECT, INSERT, UPDATE, DELETE, SHOW VIEW, EXECUTE, CREATE TEMPORARY TABLES, LOCK TABLES',
            'admin': 'ALL PRIVILEGES',
        }.get(policy.db_privilege)
        if privileges:
            cur.execute("GRANT {} ON {} TO %s@'%%'".format(privileges, target), (username,))
        else:
            for statement in _custom_sql(policy, username, database):
                cur.execute(statement)
    finally:
        conn.close()


def _mysql_remove(asset, admin, username, port, database, db):
    conn = _mysql_conn(asset, admin.username, admin.secret, port, db=db)
    try:
        cur = conn.cursor()
        cur.execute('SELECT id FROM information_schema.processlist WHERE user = %s', (username,))
        for (pid,) in cur.fetchall():
            try:
                cur.execute('KILL %s', (int(pid),))
            except Exception:
                pass
        cur.execute("DROP USER IF EXISTS %s@'%%'", (username,))
    finally:
        conn.close()


# ---------------------------------------------------------------- PostgreSQL

def _pg_conn(asset, user, password, port, database, db):
    import psycopg2
    sslmode = (db.pg_ssl_mode if db and db.use_ssl else 'prefer') or 'prefer'
    conn = psycopg2.connect(host=asset.address, port=int(port), user=user, password=password,
                            dbname=database or 'postgres', connect_timeout=CONNECT_TIMEOUT, sslmode=sslmode)
    conn.autocommit = True
    return conn


def _pg_schemas(cur):
    cur.execute("SELECT nspname FROM pg_namespace WHERE nspname NOT LIKE 'pg\\_%%' "
                "AND nspname <> 'information_schema'")
    return [r[0] for r in cur.fetchall()]


def _pg_create(asset, admin, username, password, policy, port, database, db, valid_until):
    from psycopg2 import sql
    conn = _pg_conn(asset, admin.username, admin.secret, port, database, db)
    try:
        cur = conn.cursor()
        u = sql.Identifier(username)
        # VALID UNTIL: the password stops working by itself even if the removal could not run
        cur.execute(sql.SQL('CREATE ROLE {} LOGIN PASSWORD %s VALID UNTIL %s').format(u),
                    (password, valid_until.isoformat()))
        if policy.db_privilege == 'custom':
            for statement in _custom_sql(policy, username, database or 'postgres'):
                cur.execute(statement)
            return
        dbname = sql.Identifier(database or 'postgres')
        cur.execute(sql.SQL('GRANT CONNECT, TEMPORARY ON DATABASE {} TO {}').format(dbname, u))
        if policy.db_privilege == 'admin':
            cur.execute(sql.SQL('GRANT ALL PRIVILEGES ON DATABASE {} TO {}').format(dbname, u))
        for schema in _pg_schemas(cur):
            s = sql.Identifier(schema)
            cur.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(s, u))
            tables = {'read_only': 'SELECT', 'read_write': 'SELECT, INSERT, UPDATE, DELETE',
                      'admin': 'ALL PRIVILEGES'}[policy.db_privilege]
            cur.execute(sql.SQL('GRANT {} ON ALL TABLES IN SCHEMA {} TO {}').format(sql.SQL(tables), s, u))
            if policy.db_privilege != 'read_only':
                cur.execute(sql.SQL('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA {} TO {}').format(s, u))
            if policy.db_privilege == 'admin':
                cur.execute(sql.SQL('GRANT CREATE ON SCHEMA {} TO {}').format(s, u))
                cur.execute(sql.SQL('GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA {} TO {}').format(s, u))
    finally:
        conn.close()


def _pg_remove(asset, admin, username, port, database, db):
    from psycopg2 import sql
    conn = _pg_conn(asset, admin.username, admin.secret, port, database, db)
    try:
        cur = conn.cursor()
        cur.execute('SELECT 1 FROM pg_roles WHERE rolname = %s', (username,))
        if not cur.fetchone():
            return
        cur.execute('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s', (username,))
        u = sql.Identifier(username)
        for statement in ('REASSIGN OWNED BY {} TO CURRENT_USER', 'DROP OWNED BY {}'):
            try:
                cur.execute(sql.SQL(statement).format(u))
            except Exception as e:
                logger.debug('JIT PostgreSQL cleanup of %s: %s', username, e)
        cur.execute(sql.SQL('DROP ROLE IF EXISTS {}').format(u))
    finally:
        conn.close()


# ---------------------------------------------------------------- SQL Server

def _mssql_conn(asset, user, password, port, database):
    import pymssql
    return pymssql.connect(server=asset.address, port=str(port), user=user, password=password,
                           database=database or 'master', login_timeout=CONNECT_TIMEOUT, autocommit=True)


def _mssql_create(asset, admin, username, password, policy, port, database, db):
    conn = _mssql_conn(asset, admin.username, admin.secret, port, database)
    try:
        cur = conn.cursor()
        secret = password.replace("'", "''")
        cur.execute(f"CREATE LOGIN [{username}] WITH PASSWORD = N'{secret}', CHECK_EXPIRATION = OFF")
        cur.execute(f'CREATE USER [{username}] FOR LOGIN [{username}]')
        roles = {'read_only': ['db_datareader'], 'read_write': ['db_datareader', 'db_datawriter'],
                 'admin': ['db_owner']}.get(policy.db_privilege)
        if roles is None:
            for statement in _custom_sql(policy, username, database or 'master'):
                cur.execute(statement)
        for role in roles or []:
            cur.execute(f'ALTER ROLE [{role}] ADD MEMBER [{username}]')
    finally:
        conn.close()


def _mssql_remove(asset, admin, username, port, database, db):
    conn = _mssql_conn(asset, admin.username, admin.secret, port, database)
    try:
        cur = conn.cursor()
        cur.execute('SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = %s', (username,))
        for (sid,) in cur.fetchall():
            try:
                cur.execute(f'KILL {int(sid)}')
            except Exception:
                pass
        cur.execute(f"IF EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'{username}') "
                    f"DROP USER [{username}]")
        cur.execute(f"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'{username}') "
                    f"DROP LOGIN [{username}]")
    finally:
        conn.close()


# ---------------------------------------------------------------- Oracle

def _oracle_conn(asset, user, password, port, database):
    import oracledb
    kwargs = dict(user=user, password=password, dsn=f'{asset.address}:{int(port)}/{database or "XEPDB1"}',
                  tcp_connect_timeout=CONNECT_TIMEOUT)
    if user.lower() == 'sys':
        kwargs['mode'] = oracledb.AUTH_MODE_SYSDBA
    return oracledb.connect(**kwargs)


def _oracle_create(asset, admin, username, password, policy, port, database, db):
    conn = _oracle_conn(asset, admin.username, admin.secret, port, database)
    try:
        cur = conn.cursor()
        cur.execute(f'CREATE USER {username} IDENTIFIED BY "{password}"')
        cur.execute(f'GRANT CREATE SESSION TO {username}')
        grants = {
            'read_only': ['SELECT ANY TABLE'],
            'read_write': ['SELECT ANY TABLE', 'INSERT ANY TABLE', 'UPDATE ANY TABLE', 'DELETE ANY TABLE'],
            'admin': ['DBA'],
        }.get(policy.db_privilege)
        if grants is None:
            for statement in _custom_sql(policy, username, database):
                cur.execute(statement)
        for grant in grants or []:
            cur.execute(f'GRANT {grant} TO {username}')
    finally:
        conn.close()


def _oracle_remove(asset, admin, username, port, database, db):
    conn = _oracle_conn(asset, admin.username, admin.secret, port, database)
    try:
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM dba_users WHERE username = :u', u=username.upper())
        if not cur.fetchone()[0]:
            return
        cur.execute('SELECT sid, serial# FROM v$session WHERE username = :u', u=username.upper())
        for sid, serial in cur.fetchall():
            try:
                cur.execute(f"ALTER SYSTEM KILL SESSION '{int(sid)},{int(serial)}' IMMEDIATE")
            except Exception:
                pass
        cur.execute(f'DROP USER {username} CASCADE')
    finally:
        conn.close()


# ---------------------------------------------------------------- databases

def _db_verify(asset, username, password, tp, port, database, db):
    conn = {
        'mysql': lambda: _mysql_conn(asset, username, password, port, db=db),
        'mariadb': lambda: _mysql_conn(asset, username, password, port, db=db),
        'postgresql': lambda: _pg_conn(asset, username, password, port, database, db),
        'sqlserver': lambda: _mssql_conn(asset, username, password, port, database),
        'oracle': lambda: _oracle_conn(asset, username, password, port, database),
    }[tp]()
    conn.close()


def _db_login_exists(asset, admin, username, tp, port, database, db):
    queries = {
        'mysql': ("SELECT 1 FROM mysql.user WHERE user = %s", lambda: _mysql_conn(asset, admin.username, admin.secret,
                                                                                    port, db=db)),
        'postgresql': ("SELECT 1 FROM pg_roles WHERE rolname = %s",
                       lambda: _pg_conn(asset, admin.username, admin.secret, port, database, db)),
        'sqlserver': ("SELECT 1 FROM sys.server_principals WHERE name = %s",
                      lambda: _mssql_conn(asset, admin.username, admin.secret, port, database)),
        'oracle': ("SELECT 1 FROM dba_users WHERE username = UPPER(:1)",
                   lambda: _oracle_conn(asset, admin.username, admin.secret, port, database)),
    }
    query, connect = queries['mysql' if tp == 'mariadb' else tp]
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(query, [username] if tp == 'oracle' else (username,))
        return cur.fetchone() is not None
    finally:
        conn.close()


def create_database_account(asset, username, password, policy, valid_until, allow_existing=False):
    _ident_check(username)
    tp, port, database, db = _db_spec(asset)
    admin = _admin(asset)
    creators = {'mysql': _mysql_create, 'mariadb': _mysql_create, 'sqlserver': _mssql_create,
                'oracle': _oracle_create}
    try:
        exists = _db_login_exists(asset, admin, username, tp, port, database, db)
    except Exception as e:
        raise TargetError(_redact(e, password, admin.secret))
    if exists and not allow_existing:
        # a login XPAM did not create: no CREATE, and above all no clean-up (DROP USER ... CASCADE)
        raise TargetExists(_('A database login named %s already exists') % username)
    try:
        if tp == 'postgresql':
            _pg_create(asset, admin, username, password, policy, port, database, db, valid_until)
        else:
            creators[tp](asset, admin, username, password, policy, port, database, db)
        _db_verify(asset, username, password, tp, port, database, db)
    except TargetError:
        raise
    except Exception as e:
        logger.warning('JIT database account %s on %s failed: %s', username, asset, e)
        try:
            remove_database_account(asset, username)
        except Exception:
            pass
        raise TargetError(_redact(e, password, admin.secret))


def extend_database_account(asset, username, valid_until):
    """The access was extended: move PostgreSQL's VALID UNTIL (the other databases have no expiry)."""
    tp, port, database, db = _db_spec(asset)
    if tp != 'postgresql':
        return
    from psycopg2 import sql
    _ident_check(username)
    admin = _admin(asset)
    try:
        conn = _pg_conn(asset, admin.username, admin.secret, port, database, db)
        try:
            conn.cursor().execute(sql.SQL('ALTER ROLE {} VALID UNTIL %s').format(sql.Identifier(username)),
                                  (valid_until.isoformat(),))
        finally:
            conn.close()
    except Exception as e:
        raise TargetError(_redact(e, admin.secret))


def remove_database_account(asset, username):
    _ident_check(username)
    tp, port, database, db = _db_spec(asset)
    admin = _admin(asset)
    removers = {'mysql': _mysql_remove, 'mariadb': _mysql_remove, 'postgresql': _pg_remove,
                'sqlserver': _mssql_remove, 'oracle': _oracle_remove}
    try:
        removers[tp](asset, admin, username, port, database, db)
    except Exception as e:
        raise TargetError(_redact(e, admin.secret))


# ---------------------------------------------------------------- devices

class _Module:
    """The few things the SSH client of the "SSH account push" automation needs from Ansible."""

    def __init__(self, params):
        from libs.ansible.modules_utils.remote_client import common_argument_spec
        self.params = {k: v.get('default') for k, v in common_argument_spec().items()}
        self.params.update(params)

    def fail_json(self, **kwargs):
        raise TargetError(kwargs.get('msg') or 'SSH error')


def _device_commands(text, values):
    # (a line break in a value would send a command of its own to the device)
    if any('\r' in value or '\n' in value for value in values.values()):
        raise TargetError('A value for the device commands contains a line break')
    lines = []
    for line in (text or '').replace('\r\n', '\n').split('\n'):
        if not line.strip():
            continue
        for key, value in values.items():
            line = line.replace('{%s}' % key, value)
        lines.append(line)
    return lines


def _device_run(asset, commands):
    from libs.ansible.modules_utils.remote_client import SSHClient
    admin = _admin(asset)
    module = _Module({
        'login_host': asset.address, 'login_port': asset.get_protocol_port('ssh') or 22,
        'login_user': admin.username, 'login_password': admin.secret if admin.secret_type == 'password' else '',
        'login_secret_type': admin.secret_type, 'recv_timeout': 30, 'delay_time': 2,
        'prompt': '.*',
    })
    client = SSHClient(module)
    try:
        client.connect(raise_on_error=True)
        output, error = client.execute(commands)
    finally:
        try:
            client.client.close()
        except Exception:
            pass
    if error:
        raise TargetError(error)
    return output


def _device_login_works(asset, username, password):
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(asset.address, port=asset.get_protocol_port('ssh') or 22, username=username, password=password,
                  timeout=CONNECT_TIMEOUT, look_for_keys=False, allow_agent=False)
        return True
    except Exception as e:
        logger.debug('JIT device login check for %s failed: %s', username, e)
        return False
    finally:
        c.close()


def device_vendor(asset):
    """Vendor and driver options: the platform's network method settings, else the platform name."""
    from libs.ansible.modules_utils.network_device import vendor_from_name
    params = {}
    auto = getattr(asset.platform, 'automation', None)
    for kind in ('push_account', 'change_secret', 'remove_account', 'gather_accounts'):
        method = (getattr(auto, f'{kind}_method', '') or '') if auto else ''
        if method.endswith('_network'):
            params = (getattr(auto, f'{kind}_params', None) or {}).get(method) or {}
            if params:
                break
    vendor = params.get('vendor') or 'auto'
    if vendor == 'auto':
        vendor = vendor_from_name(asset.platform.name) or 'auto'
    return vendor, {'commit': params.get('commit') or 'partial', 'vdom': params.get('vdom') or 'root'}


def _device_gateway(asset, tmp):
    if not (getattr(asset, 'zone_id', None) and asset.platform.gateway_enabled):
        return None
    gateway = asset.zone.select_gateway()
    if not gateway:
        raise TargetError(_('No gateway is available in the zone of the asset'))
    return {'address': gateway.address, 'port': gateway.port, 'username': gateway.username,
            'password': gateway.password or None,
            'key_path': gateway.get_private_key_path(tmp) if gateway.private_key else None}


def _device_credentials(asset, admin, tmp):
    """(ssh user, password, key file, enable password): "su from" signs in, the privileged secret enables."""
    login = admin.su_from if (admin.su_from_id and asset.platform.su_enabled) else admin
    password = login.secret if login.secret_type == 'password' else ''
    key = login.get_private_key_path(tmp) if login.secret_type == 'ssh_key' else None
    enable = admin.secret if admin.secret_type == 'password' else ''
    return login.username, password or '', key, enable or ''


@contextlib.contextmanager
def _device_session(asset):
    from libs.ansible.modules_utils.network_device import DeviceError, session
    admin = _admin(asset)
    vendor, options = device_vendor(asset)
    with tempfile.TemporaryDirectory(prefix='xpam-jit-') as tmp:
        user, password, key, enable = _device_credentials(asset, admin, tmp)
        gateway = _device_gateway(asset, tmp)
        try:
            with session(vendor, asset.address, asset.get_protocol_port('ssh') or 22, user, password, key_file=key,
                         enable_password=enable, gateway=gateway, timeout=CONNECT_TIMEOUT * 2,
                         options=options) as dev:
                yield dev
        except DeviceError as e:
            raise TargetError(_redact(e, password, enable))


def _device_login_works_via(asset, username, password):
    """Signs in with the new account (password or keyboard-interactive), through the gateway if any."""
    import paramiko
    from libs.ansible.modules_utils.network_device import tunnel
    with tempfile.TemporaryDirectory(prefix='xpam-jit-') as tmp:
        gateway = _device_gateway(asset, tmp)
        with tunnel(gateway, asset.address, asset.get_protocol_port('ssh') or 22) as (host, port):
            t = paramiko.Transport((host, int(port)))
            try:
                t.start_client(timeout=CONNECT_TIMEOUT)
                try:
                    t.auth_password(username, password)
                except paramiko.BadAuthenticationType:
                    t.auth_interactive(username, lambda title, instructions, prompts: [password] * len(prompts))
                return t.is_authenticated()
            except Exception as e:
                logger.debug('JIT device login check for %s failed: %s', username, e)
                return False
            finally:
                t.close()


def create_device_account(asset, username, password, policy, allow_existing=False):
    if (policy.device_create_commands or '').strip():
        return _create_device_account_by_commands(asset, username, password, policy)
    with _device_session(asset) as dev:
        if dev.user(username) and not allow_existing:
            # never take over (or later remove) an account XPAM did not create
            raise TargetExists(_('An account named %s already exists on the device') % username)
        dev.push(username, password, policy.device_role or 'read_only', policy.device_custom_role or '')
    for _attempt in range(3):  # (PAN-OS and Junos apply the account a moment after the commit)
        if _device_login_works_via(asset, username, password):
            return
        import time
        time.sleep(3)
    raise TargetError(_('The account was created, but it cannot sign in to the device'))


def remove_device_account(asset, username, policy):
    if policy and (policy.device_remove_commands or '').strip():
        return _remove_device_account_by_commands(asset, username, policy)
    with _device_session(asset) as dev:
        dev.remove(username)


def _create_device_account_by_commands(asset, username, password, policy):
    admin = _admin(asset)
    values = {'username': username, 'password': password, 'login_password': admin.secret or ''}
    commands = _device_commands(policy.device_create_commands, values)
    if not commands:
        raise TargetError(_('The policy has no commands for network devices'))
    try:
        _device_run(asset, commands)
    except Exception as e:
        raise TargetError(_redact(e, password, admin.secret))
    if not _device_login_works(asset, username, password):
        raise TargetError(_('The commands ran, but the new account cannot sign in; check the commands'))


def _remove_device_account_by_commands(asset, username, policy):
    admin = _admin(asset)
    commands = _device_commands(policy.device_remove_commands,
                                {'username': username, 'password': '', 'login_password': admin.secret or ''})
    if not commands:
        raise TargetError(_('The policy has no commands to remove the account from the device'))
    try:
        _device_run(asset, commands)
    except Exception as e:
        raise TargetError(_redact(e, admin.secret))


def _redact(error, *secrets):
    text = str(error) or error.__class__.__name__
    for secret in secrets:
        if secret:
            text = text.replace(secret, '******')
    return text[:1000]
