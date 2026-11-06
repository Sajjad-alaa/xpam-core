import os
import shutil
import tempfile
import time
import uuid
from collections import namedtuple
from unittest import mock

from django.test import TestCase, override_settings

from orgs.models import Organization

Usage = namedtuple('Usage', 'total used free')
GB = 1024 ** 3


class ReplayDiskLimitTest(TestCase):
    """ Recordings on this server's disk stay within the size limit and leave the disk free space asked for. """

    def setUp(self):
        self.media = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.media, True)
        override = override_settings(MEDIA_ROOT=self.media)
        override.enable()
        self.addCleanup(override.disable)
        self.org = Organization.default()

    def session(self, finished=True):
        from terminal.models import Session
        return Session.objects.create(user='u', asset='a', account='root', account_id=str(uuid.uuid4()), has_replay=True,
                                      replay_size=1, is_finished=finished, org_id=self.org.id)

    def write(self, rel, size, age):
        path = os.path.join(self.media, 'replay', rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(b'x' * size)
        os.utime(path, (time.time() - age, time.time() - age))
        return path

    def test_the_oldest_recordings_go_first_and_running_or_recent_ones_stay(self):
        from audits import tasks
        from audits.models import ActivityLog
        from terminal.models import Session
        running, oldest, parts, recent = self.session(False), self.session(), self.session(), self.session()
        kept_running = self.write(f'2026-10-01/{running.id}.cast.gz', 300, age=9000)
        a = self.write(f'2026-10-01/{oldest.id}.cast.gz', 300, age=8000)
        b1 = self.write(f'2026-10-02/{parts.id}/{parts.id}.replay.json', 200, age=7000)
        b2 = self.write(f'2026-10-02/{parts.id}/part-1.gz', 100, age=7000)
        kept_recent = self.write(f'2026-10-03/{recent.id}.replay.mp4', 300, age=60)
        with mock.patch.object(tasks, 'replay_bytes_to_free', return_value=400):
            deleted = tasks.enforce_replay_disk_limit()
        self.assertEqual(set(deleted), {str(oldest.id), str(parts.id)})
        self.assertFalse(any(os.path.exists(p) for p in (a, b1, b2)))
        self.assertFalse(os.path.exists(os.path.dirname(b1)))           # (the parts' folder too)
        self.assertTrue(os.path.exists(kept_running) and os.path.exists(kept_recent))
        self.assertEqual(set(Session.objects.filter(has_replay=False).values_list('id', flat=True)),
                         {oldest.id, parts.id})
        self.assertEqual(ActivityLog.objects.filter(resource_id__in=[str(oldest.id), str(parts.id)]).count(), 2)

    def test_nothing_is_deleted_within_the_limits(self):
        from audits import tasks
        s = self.session()
        path = self.write(f'2026-10-01/{s.id}.cast.gz', 300, age=9000)
        with mock.patch.object(tasks, 'replay_bytes_to_free', return_value=0):
            self.assertEqual(tasks.enforce_replay_disk_limit(), [])
        self.assertTrue(os.path.exists(path))

    def test_free_space_rule_deletes_nothing_when_recordings_cannot_cover_it(self):
        from audits import tasks
        s1, s2 = self.session(), self.session()
        p1 = self.write(f'2026-10-01/{s1.id}.cast.gz', 300, age=9000)
        p2 = self.write(f'2026-10-02/{s2.id}.cast.gz', 300, age=8000)
        with override_settings(TERMINAL_REPLAY_MAX_GB=0):
            with mock.patch.object(tasks, 'replay_bytes_to_free', return_value=10 * GB):
                with self.assertLogs(tasks.logger, 'WARNING'):
                    self.assertEqual(tasks.enforce_replay_disk_limit(), [])
        self.assertTrue(os.path.exists(p1) and os.path.exists(p2))

    def test_the_limits(self):
        from audits.tasks import replay_bytes_to_free
        disk = Usage(total=100 * GB, used=95 * GB, free=5 * GB)
        with mock.patch('shutil.disk_usage', return_value=disk):
            with override_settings(TERMINAL_REPLAY_MAX_GB=0, TERMINAL_REPLAY_MIN_FREE_PERCENT=10):
                self.assertEqual(replay_bytes_to_free(self.media, 30 * GB), 5 * GB)    # (10 GB free asked, 5 free)
            with override_settings(TERMINAL_REPLAY_MAX_GB=20, TERMINAL_REPLAY_MIN_FREE_PERCENT=0):
                self.assertEqual(replay_bytes_to_free(self.media, 30 * GB), 10 * GB)   # (30 GB used, 20 allowed)
            with override_settings(TERMINAL_REPLAY_MAX_GB=20, TERMINAL_REPLAY_MIN_FREE_PERCENT=10):
                self.assertEqual(replay_bytes_to_free(self.media, 30 * GB), 10 * GB)   # (the larger of both)
            with override_settings(TERMINAL_REPLAY_MAX_GB=0, TERMINAL_REPLAY_MIN_FREE_PERCENT=0):
                self.assertEqual(replay_bytes_to_free(self.media, 30 * GB), 0)         # (both off)
