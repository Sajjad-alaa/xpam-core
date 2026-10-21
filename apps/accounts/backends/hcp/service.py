# -*- coding: utf-8 -*-
#
"""
HashiCorp Vault (KV v2) client.

XPAM: two ways to log in
- token: a fixed token (VAULT_HCP_TOKEN), as before; the client may create its KV mount.
- cert:  TLS client-certificate login (auth/cert, role VAULT_HCP_CERT_ROLE) — the hardened setup of the XPAM
  Vault kit. Short-lived tokens are renewed before they expire and replaced by a new login when they cannot
  be; the client never needs administrative rights (the mount exists, it is never created from here).
Several Vault servers may be given (VAULT_HCP_HOST comma-separated): on a connection failure the next one is
used. TLS is always verified — against VAULT_HCP_CA_FILE only when it is set (else the system CAs) — and must be
TLS 1.3 (VAULT_HCP_TLS_MIN_VERSION=1.2 only for an older Vault outside the kit).
"""
import ssl
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, Timeout

from common.utils import get_logger

logger = get_logger(__name__)

__all__ = ['VaultKVClient', 'VaultRequestError']


class VaultRequestError(Exception):
    def __init__(self, status, errors):
        self.status = status
        self.errors = errors
        super().__init__(f'Vault error {status}: {"; ".join(errors) or "no detail"}')


class StrictTLSAdapter(HTTPAdapter):
    """ TLS 1.3 at least (unless set lower), and only the given CA when there is one (not the public CAs) """

    def __init__(self, ca_file='', min_version='1.3', **kwargs):
        self.ctx = ssl.create_default_context(cafile=ca_file or None)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if str(min_version) == '1.2' else ssl.TLSVersion.TLSv1_3
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ctx
        return super().init_poolmanager(*args, **kwargs)


class VaultKVClient(object):
    max_versions = 20
    renew_when_left = 1 / 3  # renew a token when a third of its lifetime is left

    def __init__(self, url, token='', mount_point='pam', auth='token', cert_role='', ca_file='',
                 client_cert_file='', client_key_file='', namespace='', timeout=10, tls_min_version='1.3'):
        self.urls = [u.strip().rstrip('/') for u in str(url or '').split(',') if u.strip()]
        if not self.urls:
            raise ValueError('Vault address is empty')
        self.mount_point = (mount_point or 'pam').strip('/')
        self.auth = auth or 'token'
        self.cert_role = cert_role
        self.namespace = namespace
        self.timeout = int(timeout or 10)
        self.session = requests.Session()
        self.session.verify = ca_file or True
        self.session.mount('https://', StrictTLSAdapter(ca_file=ca_file, min_version=tls_min_version))
        if client_cert_file and client_key_file:
            self.session.cert = (client_cert_file, client_key_file)
        if self.auth == 'cert' and not self.session.cert:
            raise ValueError('Certificate login needs a client certificate and key')
        self._token = token if self.auth == 'token' else ''
        self._expires_at = 0.0
        self._ttl = 0
        self._renewable = False
        self._lock = threading.Lock()
        self._current = 0
        if self.auth == 'token':
            self.enable_secrets_engine_if_need()

    # ------------------------------------------------------------ transport

    def _send(self, method, path, token=True, **kwargs):
        headers = kwargs.pop('headers', {})
        if self.namespace:
            headers['X-Vault-Namespace'] = self.namespace
        if token:
            headers['X-Vault-Token'] = self._get_token()
        last_error = None
        for i in range(len(self.urls)):
            index = (self._current + i) % len(self.urls)
            try:
                response = self.session.request(
                    method, f'{self.urls[index]}/v1/{path}', headers=headers, timeout=self.timeout, **kwargs
                )
            except (ConnectionError, Timeout) as e:
                last_error = e
                logger.warning(f'Vault {self.urls[index]} unreachable, trying the next one: {e}')
                continue
            self._current = index
            return response
        raise ConnectionError(f'No Vault server reachable: {last_error}')

    def _request(self, method, path, expected=(200, 204), retry_login=True, **kwargs):
        response = self._send(method, path, **kwargs)
        if response.status_code == 403 and self.auth == 'cert' and retry_login:
            # the token may have been revoked or expired early: one new login, then give up
            with self._lock:
                self._token = ''
            return self._request(method, path, expected, retry_login=False, **kwargs)
        if response.status_code not in expected:
            raise VaultRequestError(response.status_code, self._errors(response))
        if response.status_code == 204 or not response.content:
            return {}
        return response.json()

    @staticmethod
    def _errors(response):
        try:
            return [str(e) for e in response.json().get('errors', [])]
        except ValueError:
            return [response.text[:200]]

    # ------------------------------------------------------------ login and renewal

    def _get_token(self):
        if self.auth == 'token':
            return self._token
        with self._lock:
            now = time.time()
            if self._token and now < self._expires_at - 5:
                if self._renewable and self._expires_at - now < self._ttl * self.renew_when_left:
                    self._renew()
                return self._token
            self._login()
            return self._token

    def _login(self):
        response = self._send('POST', 'auth/cert/login', token=False, json={'name': self.cert_role})
        if response.status_code != 200:
            raise VaultRequestError(response.status_code, self._errors(response))
        self._take(response.json()['auth'])

    def _renew(self):
        try:
            response = self._send('POST', 'auth/token/renew-self', token=False,
                                  headers={'X-Vault-Token': self._token}, json={})
            if response.status_code == 200:
                auth = response.json()['auth']
                # renewal cannot go past the token's maximum lifetime: log in again when it stops growing
                if auth['lease_duration'] >= self._ttl * self.renew_when_left:
                    self._take(auth)
                    return
        except (ConnectionError, Timeout, KeyError, ValueError) as e:
            logger.warning(f'Vault token renewal failed: {e}')
        self._login()

    def _take(self, auth):
        self._token = auth['client_token']
        self._ttl = int(auth.get('lease_duration') or 0) or 3600
        self._renewable = bool(auth.get('renewable'))
        self._expires_at = time.time() + self._ttl

    def revoke(self):
        if self.auth == 'cert' and self._token:
            try:
                self._send('POST', 'auth/token/revoke-self', token=False, headers={'X-Vault-Token': self._token})
            finally:
                self._token = ''

    # ------------------------------------------------------------ status

    def is_active(self):
        try:
            response = self._send('GET', 'sys/health', token=False,
                                  params={'standbyok': 'true', 'perfstandbyok': 'true'})
            if response.status_code == 501:
                return False, 'Vault is not initialized'
            if response.status_code == 503:
                return False, 'Vault is sealed'
            # a real check of the rights XPAM needs: a token, and the store answering
            self._request('GET', 'auth/token/lookup-self')
            self._request('LIST', f'{self.mount_point}/metadata/orgs', expected=(200, 404))
        except (ConnectionError, Timeout) as e:
            logger.error(str(e))
            return False, f'Vault is not reachable: {e}'
        except VaultRequestError as e:
            return False, str(e)
        except requests.exceptions.SSLError as e:
            return False, f'TLS error (certificate or CA): {e}'
        return True, ''

    def enable_secrets_engine_if_need(self):
        """ token mode only (an administrative token); the hardened setup creates the mount itself """
        try:
            mounts = self._request('GET', 'sys/mounts')
        except VaultRequestError as e:
            logger.warning(f'Vault mounts cannot be listed with this token ({e}); assuming {self.mount_point} exists')
            return
        if f'{self.mount_point}/' in (mounts.get('data') or mounts):
            return
        self._request('POST', f'sys/mounts/{self.mount_point}', json={'type': 'kv', 'options': {'version': 2}})
        self._request('POST', f'{self.mount_point}/config', json={'max_versions': self.max_versions})

    def read_external(self, path, field=''):
        """ XPAM: an existing secret (API path after /v1/, e.g. secret/data/app/db; KV v1 or v2), not encrypted by XPAM """
        data = self._request('GET', path.strip('/')).get('data') or {}
        if isinstance(data.get('data'), dict) and 'metadata' in data:  # KV v2
            data = data['data']
        if field:
            return str(data.get(field, ''))
        return str(next(iter(data.values()), '')) if len(data) == 1 else ''

    # ------------------------------------------------------------ KV v2

    def get(self, path, version=None):
        params = {'version': version} if version else None
        try:
            response = self._request('GET', f'{self.mount_point}/data/{path}', params=params)
        except VaultRequestError as e:
            if e.status == 404:
                return {}
            raise
        return response.get('data', {}) or {}

    def create(self, path, data: dict):
        self._update_or_create(path=path, data=data)

    def update(self, path, data: dict):
        """ 未更新的数据会被删除 """
        self._update_or_create(path=path, data=data)

    def patch(self, path, data: dict):
        """ 未更新的数据不会被删除 """
        try:
            self._request('PATCH', f'{self.mount_point}/data/{path}', json={'data': data},
                          headers={'Content-Type': 'application/merge-patch+json'})
        except VaultRequestError as e:
            if e.status != 404:
                raise
            self._update_or_create(path, data)

    def delete(self, path):
        self._request('DELETE', f'{self.mount_point}/metadata/{path}', expected=(200, 204, 404))

    def _update_or_create(self, path, data: dict):
        self._request('POST', f'{self.mount_point}/data/{path}', json={'data': data})

    def update_metadata(self, path, metadata: dict):
        try:
            self._request('POST', f'{self.mount_point}/metadata/{path}', json={'custom_metadata': metadata})
        except VaultRequestError as e:
            logger.error('Update metadata error: {}'.format(e))
