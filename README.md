# XPAM core

The API and back end of XPAM, a privileged access management (PAM) platform: users, assets, accounts
and their secrets, access permissions, just-in-time access, approvals, session recording and audit.

XPAM is based on JumpServer and, like it, is licensed under the GNU General Public License v3
(see [LICENSE](LICENSE)).

## Layout

| Path | Contents |
|---|---|
| `apps/` | The Django application |
| `jms` | Start script used in the image |
| `pyproject.toml`, `requirements/` | Python dependencies and build helpers |
| `utils/` | Runtime helpers (Celery beat start, worker health check) and the Ansible executor image definition |

## Building and installing

Images are built and installed with the XPAM installer (`xpam-installer`): `build/build-all.sh` builds the
images, `xpamctl.sh` installs and upgrades a server.
