"""
Google Cloud Secret Manager, REST API v1.

XPAM logs in as a service account (its JSON key, VAULT_GCP_CREDENTIALS): a signed JWT is exchanged for an access
token (renewed before it expires); the account needs roles/secretmanager.admin on the project, or a custom role
with secrets.create/get/update/delete and versions.add/access/destroy. Each secret is a Secret Manager secret
(automatic replication, or VAULT_GCP_LOCATIONS for user-managed replication); a new value is a new version and
the previous one is destroyed (XPAM's history lives in XPAM).
"""
import base64
import json
import threading
import time

import jwt
import requests

from common.utils import get_logger, random_string

logger = get_logger(__name__)

__all__ = ['GoogleSecretManagerClient']

SCOPE = 'https://www.googleapis.com/auth/cloud-platform'


class GoogleSecretManagerClient(object):
    api = 'https://secretmanager.googleapis.com/v1'

    def __init__(self, project, credentials, locations='', api_url='', timeout=10):
        self.project = project
        try:
            self.credentials = json.loads(credentials) if isinstance(credentials, str) else dict(credentials or {})
        except ValueError:
            raise ValueError('The service account key is not valid JSON')
        if not self.credentials.get('private_key') or not self.credentials.get('client_email'):
            raise ValueError('The service account key needs private_key and client_email')
        self.project = project or self.credentials.get('project_id')
        if not self.project:
            raise ValueError('Project is empty')
        self.locations = [loc.strip() for loc in str(locations or '').split(',') if loc.strip()]
        if api_url:
            self.api = api_url.rstrip('/')
        self.timeout = int(timeout or 10)
        self.session = requests.Session()
        self._token = ''
        self._expires_at = 0.0
        self._lock = threading.Lock()
        self.empty_secret = '#{empty}#'

    # ------------------------------------------------------------ transport

    def _auth_header(self):
        with self._lock:
            if not self._token or time.time() > self._expires_at - 120:
                now = int(time.time())
                token_uri = self.credentials.get('token_uri') or 'https://oauth2.googleapis.com/token'
                assertion = jwt.encode(
                    {'iss': self.credentials['client_email'], 'scope': SCOPE, 'aud': token_uri,
                     'iat': now, 'exp': now + 3600},
                    self.credentials['private_key'], algorithm='RS256',
                    headers={'kid': self.credentials.get('private_key_id', '')},
                )
                response = self.session.post(token_uri, data={
                    'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': assertion,
                }, timeout=self.timeout)
                if response.status_code != 200:
                    raise PermissionError(f'Google login refused ({response.status_code}): {response.text[:200]}')
                body = response.json()
                self._token = body['access_token']
                self._expires_at = time.time() + int(body.get('expires_in') or 3600)
            return {'Authorization': f'Bearer {self._token}'}

    def _request(self, method, path, **kwargs):
        headers = kwargs.pop('headers', {})
        headers.update(self._auth_header())
        response = self.session.request(method, f'{self.api}/{path}', headers=headers, timeout=self.timeout, **kwargs)
        if response.status_code == 401:
            with self._lock:
                self._token = ''
            headers.update(self._auth_header())
            response = self.session.request(method, f'{self.api}/{path}', headers=headers,
                                            timeout=self.timeout, **kwargs)
        return response

    def _secret(self, name):
        return f'projects/{self.project}/secrets/{name}'

    @staticmethod
    def _check(response, what, ok=(200,)):
        if response.status_code not in ok:
            raise RuntimeError(f'Google Secret Manager: {what} failed ({response.status_code}): {response.text[:200]}')

    def _add_version(self, name, secret):
        data = base64.b64encode((secret or self.empty_secret).encode()).decode()
        response = self._request('POST', f'{self._secret(name)}:addVersion', json={'payload': {'data': data}})
        self._check(response, 'adding a version')
        return response.json()['name']

    # ------------------------------------------------------------ contract

    def is_active(self):
        name = f'xpam-test-{random_string(12)}'
        try:
            self.create(name, 'secret')
            if self.get(name, strict=True) != 'secret':
                return False, 'Google Secret Manager returned a different value'
            self.update(name, 'secret2')
            self.delete(name)
        except Exception as e:
            return False, f'Google Secret Manager is not usable: {e}'
        return True, ''

    def get(self, name, version='', strict=False):
        try:
            response = self._request('GET', f'{self._secret(name)}/versions/{version or "latest"}:access')
            if response.status_code == 404:
                return None if strict else ''
            self._check(response, 'reading')
            value = base64.b64decode(response.json()['payload']['data']).decode()
        except Exception:
            if strict:
                raise
            return ''
        return '' if value == self.empty_secret else value

    def create(self, name, secret):
        replication = {'userManaged': {'replicas': [{'location': loc} for loc in self.locations]}} \
            if self.locations else {'automatic': {}}
        response = self._request('POST', f'projects/{self.project}/secrets', params={'secretId': name},
                                 json={'replication': replication, 'labels': {'managed-by': 'xpam'}})
        if response.status_code == 409:  # already exists: just a new value
            return self.update(name, secret)
        self._check(response, 'creating the secret')
        self._add_version(name, secret)

    def update(self, name, secret):
        previous = None
        response = self._request('GET', f'{self._secret(name)}/versions/latest')
        if response.status_code == 404:
            return self.create(name, secret)
        if response.status_code == 200:
            previous = response.json().get('name')
        added = self._add_version(name, secret)
        if previous and previous != added:
            destroyed = self._request('POST', f'{previous}:destroy', json={})
            if destroyed.status_code not in (200, 404):
                logger.warning(f'Google Secret Manager: the previous version stays ({destroyed.status_code})')

    def delete(self, name):
        response = self._request('DELETE', self._secret(name))
        self._check(response, 'removing the secret', ok=(200, 404))

    def read_external(self, path, field=''):
        """ XPAM: an existing secret (its name, or projects/../secrets/..; field = a version, default latest) """
        name = path if path.startswith('projects/') else self._secret(path)
        response = self._request('GET', f'{name}/versions/{field or "latest"}:access')
        self._check(response, f'reading {path}')
        return base64.b64decode(response.json()['payload']['data']).decode()

    def update_metadata(self, name, metadata: dict):
        annotations = {f'xpam-{k}'[:63]: str(v)[:1000] for k, v in metadata.items()}
        response = self._request('PATCH', self._secret(name), params={'updateMask': 'annotations'},
                                 json={'annotations': annotations})
        if response.status_code != 200:
            logger.error(f'update_metadata: {name} {response.status_code}')
