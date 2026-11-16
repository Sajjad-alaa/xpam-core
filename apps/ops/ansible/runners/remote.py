"""
XPAM: jobs written by users run on the runner service (xpam_runner, build/runner/server.py in the installer), not
in this container. The job is packed with ansible-runner's own streaming (transmit), sent to the runner, which runs
it under a user of its own and streams the events back; they are processed here as for a local run, so results,
logs and callbacks stay the same. Stop: a file `xpam.stop` in the job's folder (core and the worker share it)
closes the connection, and the runner kills the job.
"""
import os
import socket
import tempfile
import threading

import ansible_runner
import requests
from django.conf import settings

from ops.ansible.cleaner import cleanup_post_run
from ops.ansible.runners.base import BaseRunner

__all__ = ['AnsibleRemoteRunner', 'RunnerUnavailable', 'STOP_FILE', 'runner_enabled']

STOP_FILE = 'xpam.stop'
# what only makes sense for a local run (process isolation, a local executor image)
LOCAL_ONLY = (
    'process_isolation', 'process_isolation_executable', 'container_image', 'container_options',
    'container_volume_mounts', 'host_cwd', 'container_workdir',
)


class RunnerUnavailable(Exception):
    pass


def runner_enabled():
    return bool(settings.XPAM_RUNNER_ENABLED and settings.XPAM_RUNNER_URL and settings.XPAM_RUNNER_KEY)


class AnsibleRemoteRunner(BaseRunner):
    @classmethod
    def kill_precess(cls, pid):
        # (a remote job is stopped through its stop file, never by a process id of this container)
        return None

    @staticmethod
    def _without_pid(handler):
        # the events carry the runner's process ids: they must never be used to kill a process here
        def wrapped(data, *args, **kwargs):
            if isinstance(data, dict):
                data.pop('pid', None)
            return handler(data, *args, **kwargs) if handler else True
        return wrapped

    @cleanup_post_run
    def run(self):
        params = dict(self.runner_params)
        event_handler = self._without_pid(self.get_event_handler())
        status_handler = self.get_status_handler()
        private_data_dir = params.pop('private_data_dir')
        for key in LOCAL_ONLY:
            params.pop(key, None)
        params.pop('event_handler', None)
        params.pop('status_handler', None)
        params.pop('quiet', None)
        stop_path = os.path.join(private_data_dir, STOP_FILE)

        with tempfile.TemporaryFile() as bundle:
            ansible_runner.run(streamer='transmit', _output=bundle, private_data_dir=private_data_dir, **params)
            bundle.seek(0)
            try:
                response = requests.post(
                    settings.XPAM_RUNNER_URL.rstrip('/') + '/run', data=bundle, stream=True,
                    headers={'Authorization': 'Bearer ' + settings.XPAM_RUNNER_KEY, 'X-Job-Dir': private_data_dir},
                    timeout=(10, settings.XPAM_RUNNER_READ_TIMEOUT),
                )
            except requests.RequestException as e:
                raise RunnerUnavailable('The runner service cannot be reached: %s' % e)
        if response.status_code != 200:
            try:
                detail = response.json().get('error', '')
            except ValueError:
                detail = response.text[:200]
            response.close()
            raise RunnerUnavailable('The runner service refused the job (%s): %s' % (response.status_code, detail))

        finished = threading.Event()

        def watch_stop():
            while not finished.wait(1):
                if os.path.exists(stop_path):
                    try:
                        sock = response.raw._fp.fp.raw._sock
                        sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    response.close()
                    return

        watcher = threading.Thread(target=watch_stop, daemon=True)
        watcher.start()
        try:
            ansible_runner.run(
                streamer='process', _input=response.raw, private_data_dir=private_data_dir, quiet=True,
                event_handler=event_handler, status_handler=status_handler,
            )
        finally:
            finished.set()
            response.close()
