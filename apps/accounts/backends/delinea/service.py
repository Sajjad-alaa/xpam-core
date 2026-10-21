"""
Delinea Secret Server (on-premises and Secret Server Cloud), REST API v1.

XPAM logs in with an application account (OAuth2 password grant, /oauth2/token; the access token is renewed
before it expires). Each secret is a Secret Server secret named after XPAM's path, in XPAM's own folder
(VAULT_DELINEA_FOLDER_ID), made from a template with a password field (VAULT_DELINEA_TEMPLATE_ID, field slug
VAULT_DELINEA_FIELD, default "password"). Secret Server keeps the history of each field itself.
"""
import threading
import time

import requests

from common.utils import get_logger, random_string

logger = get_logger(__name__)

__all__ = ['DelineaClient']


class DelineaClient(object):
    def __init__(self, url, username, password, folder_id, template_id, field='password', domain='',
                 site_id='', ca_file='', timeout=10):
        self.url = (url or '').rstrip('/')
        if not self.url:
            raise ValueError('Secret Server address is empty')
        self.username = username
        self.password = password
        self.domain = domain
        self.folder_id = int(folder_id)
        self.template_id = int(template_id)
        self.site_id = int(site_id) if str(site_id or '').strip() else None
        self.field = field or 'password'
        self.timeout = int(timeout or 10)
        self.session = requests.Session()
        self.session.verify = ca_file or True
        self._token = ''
        self._expires_at = 0.0
        self._lock = threading.Lock()
        self._ids = {}
        self.empty_secret = '#{empty}#'

    # ------------------------------------------------------------ transport

    def _auth_header(self):
        with self._lock:
            if not self._token or time.time() > self._expires_at - 60:
                data = {'grant_type': 'password', 'username': self.username, 'password': self.password}
                if self.domain:
                    data['domain'] = self.domain
                response = self.session.post(f'{self.url}/oauth2/token', data=data, timeout=self.timeout)
                if response.status_code != 200:
                    raise PermissionError(f'Secret Server login refused ({response.status_code})')
                body = response.json()
                self._token = body['access_token']
                self._expires_at = time.time() + int(body.get('expires_in') or 1200)
            return {'Authorization': f'Bearer {self._token}'}

    def _request(self, method, path, **kwargs):
        headers = kwargs.pop('headers', {})
        headers.update(self._auth_header())
        response = self.session.request(method, f'{self.url}/api/v1{path}', headers=headers,
                                        timeout=self.timeout, **kwargs)
        if response.status_code == 401:
            with self._lock:
                self._token = ''
            headers.update(self._auth_header())
            response = self.session.request(method, f'{self.url}/api/v1{path}', headers=headers,
                                            timeout=self.timeout, **kwargs)
        return response

    def _find(self, name):
        """ the secret's id (by exact name, in XPAM's folder), or None """
        if name in self._ids:
            return self._ids[name]
        response = self._request('GET', '/secrets', params={
            'filter.searchText': name, 'filter.folderId': self.folder_id, 'filter.includeInactive': 'false',
            'take': 50,
        })
        if response.status_code != 200:
            raise RuntimeError(f'Secret Server search failed ({response.status_code})')
        for record in response.json().get('records', []):
            if record.get('name') == name and int(record.get('folderId', self.folder_id)) == self.folder_id:
                self._ids[name] = record['id']
                return record['id']
        return None

    # ------------------------------------------------------------ contract

    def is_active(self):
        name = f'xpam-test-{random_string(12)}'
        try:
            self.create(name, 'secret')
            if self.get(name, strict=True) != 'secret':
                return False, 'Secret Server returned a different value'
            self.update(name, 'secret2')
            self.delete(name)
        except Exception as e:
            return False, f'Secret Server is not usable: {e}'
        return True, ''

    def get(self, name, version='', strict=False):
        try:
            secret_id = self._find(name)
            if secret_id is None:
                return None if strict else ''
            response = self._request('GET', f'/secrets/{secret_id}/fields/{self.field}')
            if response.status_code == 404:
                self._ids.pop(name, None)
                return None if strict else ''
            if response.status_code != 200:
                raise RuntimeError(f'Secret Server read failed ({response.status_code})')
            value = response.json() if response.headers.get('Content-Type', '').startswith('application/json') \
                else response.text
        except Exception:
            if strict:
                raise
            return ''
        return '' if value == self.empty_secret else value

    def create(self, name, secret):
        if self._find(name) is not None:
            return self.update(name, secret)
        body = {
            'name': name, 'folderId': self.folder_id, 'secretTemplateId': self.template_id,
            'items': [{'slug': self.field, 'itemValue': secret or self.empty_secret}],
        }
        if self.site_id:
            body['siteId'] = self.site_id
        response = self._request('POST', '/secrets', json=body)
        if response.status_code not in (200, 201):
            raise RuntimeError(f'Secret Server: creating the secret failed ({response.status_code}): {response.text[:200]}')
        self._ids[name] = response.json()['id']

    def update(self, name, secret):
        secret_id = self._find(name)
        if secret_id is None:
            return self.create(name, secret)
        response = self._request('PUT', f'/secrets/{secret_id}/fields/{self.field}',
                                 json={'value': secret or self.empty_secret})
        if response.status_code not in (200, 204):
            raise RuntimeError(f'Secret Server: updating the secret failed ({response.status_code}): {response.text[:200]}')

    def delete(self, name):
        secret_id = self._find(name)
        if secret_id is None:
            return
        response = self._request('DELETE', f'/secrets/{secret_id}')
        self._ids.pop(name, None)
        if response.status_code not in (200, 204, 404):
            raise RuntimeError(f'Secret Server: removing the secret failed ({response.status_code})')

    def read_external(self, path, field=''):
        """ XPAM: an existing Secret Server secret (its id) and field slug, not encrypted by XPAM """
        response = self._request('GET', f'/secrets/{int(path)}/fields/{field or self.field}')
        if response.status_code != 200:
            raise RuntimeError(f'Secret Server: reading secret {path} failed ({response.status_code})')
        return response.json() if response.headers.get('Content-Type', '').startswith('application/json') else response.text

    def update_metadata(self, name, metadata: dict):
        # template fields differ from one installation to the next: XPAM keeps metadata in its own database
        return
