# YesCaptcha Assistant in v3.4 VNC browsers

The requested Chrome Web Store extension is `jiofmdifioeejeilfkpegipdjiopiekl`
(YesCaptcha Assistant). The pinned CRX is version `1.4.7`, SHA-256
`be6034d83592293703861dec68ac26bd62cc0f5d435022152d4abc9e5242c6f3`.
It was fetched from Google's `clients2.google.com/service/update2/crx`
endpoint for that exact extension ID. The CRX3 header contains the matching
signing identity. It is Manifest V3 and requests `<all_urls>` access.

The package is unpacked by `scripts/install_yescaptcha_extension.py` into
`extensions/main`, `extensions/slot1`, `extensions/slot2`, and
`extensions/slot3`. Extension contents are excluded from Git and the Docker
build context. Each runtime mount is read-only. Main VNC and the two normal
concurrent workers require a valid installed bundle before a visible browser
starts. Slot3 templates have the same requirement. Every future Profile
automatically uses the extension of its assigned login slot. Background
headless session checks remain on their existing browser flags.

The package is pinned; future Chrome Web Store updates require a reviewed CRX,
new checksum, and a deliberate rollout. The project YesCaptcha key is in
OpenBao KV v2 `projects/opencodex/prod/flow-vnc/yescaptcha` field `CLIENT_KEY`.
It is not in OpenBao login-account records or Google credentials. A restricted
runtime copy is mounted read-only into the VNC containers. Each visible browser
start writes the key into the extension's local configuration and verifies the
extension's balance API before navigating to Google/Flow.

An already open browser cannot gain a command-line extension without a new
browser context. Updating worker containers revokes their in-memory invitation
capabilities, so preserve and reconcile current invitations before a restart.
The extension's presence should be verified through the `chrome-extension://`
service worker in a headed Chromium context in each deployed worker.

## sgp011 deployment, 2026-09-25 UTC

The main v3.4 control container and login workers 1/2 run the new images with
read-only extension mounts. A disposable headed Chromium context in each of
the three running containers loaded the exact service worker
`chrome-extension://jiofmdifioeejeilfkpegipdjiopiekl/`. The optional slot3
standard and ID11 recovery images were also built and passed the same
disposable headed-browser check. The standard and recovery Compose templates
now select those images and mount the separate slot3 directory. Slot3 remains
stopped until requested.

Recovery point: `sgp011:/home/grey/backups/sgp011-yescaptcha-vnc-20260925T121147Z`.
The online Updater SQLite backup passed `integrity_check=ok`. After deployment,
the live SQLite also passed, all 15 Profiles remained, and the main container,
workers 1/2, and Flow2API were running with zero restart counts. The workers
were healthy, Updater `/health` returned 200, and anonymous public Updater and
raw-IP VNC requests returned 401. No Flow2API, NewAPI, or MySQL container was
recreated.

Profiles 18/19 were already quarantined before this deployment. They remain
inactive, logged out, sync_count 0 and error_count 0, with their saved Profile
data retained. This deployment does not reissue their old invitations. The
extension is installed for their slot's next valid browser launch, and for
all later Profiles prepared through those slots.

## Key configuration, 2026-09-25 UTC

The main VNC, slots 1/2, and both optional slot 3 images passed disposable
headed Chromium checks for extension loading, key storage, and the YesCaptcha
balance API. Production main and slots 1/2 now use the key-enabled images and
read-only runtime key mount; slot 3 remains stopped. See the project operations
workspace at `/home/grey/work/sgp_newapi_cliproxy_ops/docs/yescaptcha-vnc.md`.
