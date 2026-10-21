"""
CyberArk Conjur (Conjur Open Source, Conjur Enterprise / Secrets Manager Self-Hosted, Conjur Cloud).

XPAM logs in as a Conjur host with its API key (POST /authn/{account}/{login}/authenticate; the access token
lasts 8 minutes and is renewed before it expires). Each secret is a Conjur variable under XPAM's own policy
branch (VAULT_CYBERARK_POLICY): a variable is declared there the first time (the host needs `create` on that
policy, and `update` to remove variables), then its value is set and read. Conjur keeps the previous values
of each variable itself.
"""
import base64
import threading
import time
from urllib.parse import quote

import requests

from common.utils import get_logger, random_string

logger = get_logger(__name__)

__all__ = ['ConjurClient']


class ConjurClient(object):
    token_lifetime = 8 * 60
    renew_before = 60

    def __init__(self, url, account, login, api_key, policy='xpam', ca_file='', timeout=10):
        self.url = (url or '').rstrip('/')
        if not self.url:
            raise ValueError('Conjur address is empty')
        self.account = account
        self.login = login
        self.api_key = api_key
        self.policy = (policy or 'xpam').strip('/')
        self.timeout = int(timeout or 10)
        self.session = requests.Session()
        self.session.verify = ca_file or True
        self._token = ''
        self._token_at = 0.0
        self._lock = threading.Lock()
        self.empty_secret = '#{empty}#'

    # ------------------------------------------------------------ transport

    def _auth_header(self):
        with self._lock:
            if not self._token or time.time() - self._token_at > self.token_lifetime - self.renew_before:
                response = self.session.post(
                    f'{self.url}/authn/{quote(self.account, safe="")}/{quote(self.login, safe="")}/authenticate',
                    data=self.api_key, headers={'Accept-Encoding': 'base64'}, timeout=self.timeout,
                )
                if response.status_code != 200:
                    raise PermissionError(f'Conjur login refused ({response.status_code})')
                token = response.text.strip()
                if token.startswith('{'):  # without base64 encoding the token is JSON
                    token = base64.b64encode(response.content).decode()
                self._token, self._token_at = token, time.time()
            return {'Authorization': f'Token token="{self._token}"'}

    def _request(self, method, path, **kwargs):
        headers = kwargs.pop('headers', {})
        headers.update(self._auth_header())
        response = self.session.request(method, f'{self.url}{path}', headers=headers, timeout=self.timeout, **kwargs)
        if response.status_code == 401:  # token expired early: one new login
            with self._lock:
                self._token = ''
            headers.update(self._auth_header())
            response = self.session.request(method, f'{self.url}{path}', headers=headers,
                                            timeout=self.timeout, **kwargs)
        return response

    def _variable_id(self, name):
        return f'{self.policy}/{name}'

    def _secret_path(self, name):
        return f'/secrets/{quote(self.account, safe="")}/variable/{quote(self._variable_id(name), safe="")}'

    def _policy_path(self):
        return f'/policies/{quote(self.account, safe="")}/policy/{quote(self.policy, safe="")}'

    @staticmethod
    def _yaml_id(name):
        # variable ids are plain path segments here (uuid, letters, digits, - and /)
        if not all(c.isalnum() or c in '-_/' for c in name):
            raise ValueError(f'Unsupported Conjur variable id: {name}')
        return name

    # ------------------------------------------------------------ contract

    def is_active(self):
        name = f'xpam-test-{random_string(12).lower()}'
        try:
            self.create(name, 'secret')
            if self.get(name, strict=True) != 'secret':
                return False, 'Conjur returned a different value'
            self.update(name, 'secret2')
            self.delete(name)
        except Exception as e:
            return False, f'Conjur is not usable: {e}'
        return True, ''

    def get(self, name, version='', strict=False):
        params = {'version': version} if version else None
        try:
            response = self._request('GET', self._secret_path(name), params=params)
        except Exception:
            if strict:
                raise
            return ''
        if response.status_code == 404:
            return None if strict else ''
        if response.status_code != 200:
            if strict:
                raise RuntimeError(f'Conjur read failed ({response.status_code})')
            return ''
        value = response.text
        return '' if value == self.empty_secret else value

    def create(self, name, secret):
        body = f'- !variable {self._yaml_id(name)}\n'
        response = self._request('POST', self._policy_path(), data=body.encode())
        if response.status_code not in (200, 201):
            raise RuntimeError(f'Conjur: declaring the variable failed ({response.status_code}): {response.text[:200]}')
        self.update(name, secret)

    def update(self, name, secret):
        response = self._request('POST', self._secret_path(name), data=(secret or self.empty_secret).encode())
        if response.status_code == 404:  # not declared yet (e.g. created before this backend was used)
            body = f'- !variable {self._yaml_id(name)}\n'
            self._request('POST', self._policy_path(), data=body.encode())
            response = self._request('POST', self._secret_path(name), data=(secret or self.empty_secret).encode())
        if response.status_code not in (200, 201, 204):
            raise RuntimeError(f'Conjur: setting the value failed ({response.status_code}): {response.text[:200]}')

    def delete(self, name):
        body = f'- !delete\n  record: !variable {self._yaml_id(name)}\n'
        response = self._request('PATCH', self._policy_path(), data=body.encode())
        if response.status_code not in (200, 201, 404):
            raise RuntimeError(f'Conjur: removing the variable failed ({response.status_code}): {response.text[:200]}')

    def update_metadata(self, name, metadata: dict):
        # annotations would need a policy update for every change: XPAM keeps metadata in its own database
        return
