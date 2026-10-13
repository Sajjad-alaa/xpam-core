# XPAM WebLite

WebLite is the managed browser XPAM uses to open **Website** assets on a Windows publishing host
(RemoteApp machine). It replaces the older Chrome applet and needs no Chrome, ChromeDriver or
Python on the host.

## What it does

- Opens the asset's address automatically and shows it in a read-only address bar.
- Fills in the account and password for the user (autofill), including scripted logins, a
  success check, and an area the user can interact with for captchas or MFA.
- Keeps the user inside the allowed sites when the asset has an access allowlist.
- Accepts self-signed and private-CA certificates for the asset's own hosts only.

The session is displayed and recorded through the normal RemoteApp (RDP) session. WebLite
connects straight to the website, so the publishing host must be able to reach the asset and
any single sign-on site used during login.

## Requirements on the publishing host

- A Tinker version that supports applets with `exec_type: exe` and `stdin: true`.
- The WebLite installer, `XPAM-WebLite-5.0.0-x64.msi`. The host downloads it from this XPAM
  server at `/download/applets/`; place the file in `<data folder>/web/applets/` on the server.

It installs for all users into `%ProgramFiles%\JumpServer\WebLite` (the folder name is fixed,
because Tinker expects applets there) and contains a single `weblite.exe`.

## Not supported yet

- Login scripts that use `select_frame`, and logins that open in a separate pop-up window.
- Reaching the asset through an asset gateway: the publishing host needs a direct network path.

## Upgrading

Close all WebLite sessions, deploy the new installer and this applet together, then publish
the applet to the host again. The executable path does not change between versions.

Access allowlists, scripted login, the success selector and the interactive area need a valid
license. Basic autofill works without one.
