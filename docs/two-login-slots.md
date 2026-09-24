# Two concurrent owner-login slots

Status: **DEPLOYED FOR TWO OWNER LOGINS; ACCOUNTS NOT YET ACCEPTED**. On
2026-09-20 UTC sgp011 changed from the single root desktop to the isolated
release Compose. The control API remains loopback-only; the public Updater
vhost retains independent Basic Auth and now has an exact WebSocket Upgrade
route. Following restart-safe retirement of two lost invitations, two fresh
inactive candidates, Updater profiles12 and13, are currently open in slots1
and2 for the owners. Their capability URLs are short-lived and
must never be written to this repository. A completed visible login still is
not a Flow pool entry: real same-context provider ownership, serial extract /
deduplication, scoped backups, exactly one sync and isolated acceptance remain
mandatory for each identity.

The shared Basic Auth policy for concurrent owner-login slots uses the
non-secret username `flowlogin`. Its password is owner-supplied out of band;
only the irreversible hash is stored on sgp011 in the dedicated root-managed
file `/etc/nginx/sgp011-flow-updater-public.htpasswd`. Existing and later
slots inherit this vhost-level authentication automatically. Do not add a
plaintext password to Compose, environment files, this repository, logs or
Curator. The historical raw-IP VNC entrance remains on its separate
credential file and is not changed by slot credential rotation.

The workspace-approved `$send-personal-wecom` route may carry an explicitly
scoped short-lived invitation and the owner-supplied Basic Auth fields to its
allowlisted recipient. Keep those values only in the live command pipeline;
do not store capabilities, plaintext passwords or provider message IDs. Do
not put Basic Auth in URL userinfo. Send the username/password as separate
fields beside the invitation URLs in one exact notification.

## Operator workflow

1. Sign in to the administrator console and open `/account-import`.
2. Create a fresh Profile with an explicit source proxy and destination
   CAPTCHA proxy. The endpoint takes an online Updater SQLite backup under
   the private data volume before creating it inactive and stores no login
   account or password. Only Profiles carrying this prepare-generated,
   single-use onboarding state can enter a slot; migrated or manually created
   rows are rejected. Do not give teammates the administrator credential.
3. Start a slot and send its short-lived invitation URL to exactly one owner.
   A second operator may do the same for another Profile. Slot saturation or
   reuse of a Profile returns HTTP 409; no existing browser is closed.
4. Each owner performs only visible Google, Flow and Labs authorization in the
   assigned page and leaves it open. There is no completion button; the page
   has no sync, Cookie export, activation or account-administration controls.
5. The administrator runs one serialized `check-login` directly from `ready`
   against that exact
   context. It validates Labs session, credits and complete Cookies before it
   binds a project observed in the same context. A failed check returns the
   same private desktop to the same owner; a successful check closes it.
   If Google presents CAPTCHA, 2-Step Verification, device confirmation or
   account recovery, the check returns `manual_action_required`, keeps the
   same Profile/VNC open and performs no handoff, extraction or sync. The
   owner completes that challenge visibly before another no-cost check.
6. The administrator applies the rest of the accepted serial process: at most
   one `extract`, local identity/project deduplication, online Updater
   and Flow SQLite backups plus the read-only NewAPI boundary, exactly one
   supported sync, explicit pending-account enablement and one isolated image
   acceptance.
7. A successful no-cost check is not final success. Only the isolated image's
   unique Flow/NewAPI attribution and complete decode admit the account to the
   scheduling pool.

Visible login completion is never evidence that an account is schedulable.

New worker launches open two tabs in the same isolated Profile: the Flow tool
and the supported Labs OAuth entry. The owner must complete both layers in
that one Profile and enter a real Flow project. No completion button is needed.
The two tabs are convenience only; they do not weaken the same-context
project-response gate or prove pool acceptance. A modern Flow HTML 200 and
visible editor establish browser access but are not by themselves an
account-bound project-ownership response; validation must fail closed until
that separate proof is available.

## Isolation and access boundary

- Each worker has its own PID/mount/network namespace, Xvfb `:99`, and VNC
  `127.0.0.1:5900` *inside that worker only*. Slot1 runs UID11001, slot2
  UID11002; neither publishes a port or mounts `/app/data`, `/app/logs`,
  other Profiles, the Docker socket or administrator secrets. Their one RW
  persistent mount each is its own named Profile volume. Runtime control and
  fixed-proxy egress are separate Unix sockets; workers use `network:none`
  and keep the Chromium sandbox enabled. Chromium extensions are disabled;
  do not install a CAPTCHA-solving extension or inject a solver key into a
  login Profile. Server-side image CAPTCHA solving is an unrelated runtime
  boundary and cannot be reused for Google account login.
- The control plane alone publishes the management port on host loopback.
  Nginx must explicitly proxy Upgrade on
  `/login-slots/vnc/websockify?slot=N`; the FastAPI route binds the signed
  worker relay to the capability cookie and the requested slot number.
- Invitations carry 256-bit random capabilities in the URL fragment. The
  fragment is exchanged for an HttpOnly, Secure, SameSite=Strict cookie and is
  immediately removed from browser history. It is not sent in HTTP requests.
- Invitations expire after four hours. Successful administrator validation or
  cancellation closes that browser and desktop. A Profile is single-invite:
  once launched, a later colleague cannot inherit that browser even when its
  database has not yet been extracted. A failed or expired invitation needs
  operator review before creating a new fresh Profile for the owner.
- The worker requires the candidate UUID both in a URL from its own browser
  context and in an authenticated read-only Google Labs project JSON response
  observed by that context, with Labs session, credits, Cookie and identity
  checks immediately before and after. If the real provider response shape is
  not proven compatible, it fails closed; a visible URL is never enough.
- The worker closes its browser, and the control plane compares a snapshot
  manifest while copying into the central Profile directory, records the
  local identity/project, then cleans the worker's Profile. A persisted
  `login_slot_handoff_complete` marker is written only after cleanup. On
  restart all claimed-but-incomplete Profiles and nonempty worker volumes
  quarantine; in-memory invitations and generations cannot be recovered.
- Scheduler, extraction, sync, export, update and deletion operations reject
  a Profile while it is in a login slot. Batch sync excludes slot owners.
- The slot VNC servers need no second password because they are loopback-only
  and reachable only through the per-slot capability gate. Public deployments
  still require HTTPS and independent administrator authentication at the
  reverse proxy.

## Deployment boundary

The local release-Compose test `scripts/smoke_login_slot_compose.sh` passed
two concurrent `1365×768` RFB sessions, with slot1 input changing only slot1,
worker UID11001/11002, distinct Profile mounts, denied non-loopback network,
no management-secret mounts, no sandbox bypass, PID peaks at most133/320,
memory peaks under374 MiB/2 GiB, no OOM and no restart. The sgp011 parallel
test used the same container limits and image IDs, a separate loopback Nginx
TLS Basic-Auth route, an online SQLite copy, and two empty named Profile
volumes. It passed HTTP claim/Secure cookie, both simultaneous WebSocket/RFB
paths and restart reconciliation against disposable databases and volumes;
no test profile entered the live database. The original Profile6 and eight
accepted Flow rows stayed untouched. Synthetic-page worker peaks were146/320
PID and under364 MiB/2
GiB, OOM0. Real Flow entry pages later reached216 PID, so the reviewed hard
limit is320, retaining more than20% headroom without removing the PID fence.
The test route and containers were removed after the test. The smoke harness is
`scripts/smoke_login_slot_sgp011.sh` plus
`scripts/smoke_login_slot_https.py` and the loopback-only test vhost.

Predeployment online Updater/Flow SQLite backups, image-ID equality and
rollback files are under the root-only recovery point
`sgp011:/home/grey/backups/sgp011-two-login-slots-predeploy-20260920T181711Z`.
The tested control and worker IDs are respectively
`sha256:f7d705951be2d61748303f1c7e3fe190fa2582b5a69a55abcc05b741102d8804`
and
`sha256:adc5637431900aae833a338574931f063af1f65940872ea14287a87a86f1ae2c`.
At handoff both slots were ready, both candidates inactive/logged-out/sync0,
every new container was restart0/OOMfalse, Flow SQLite was `ok`, tasks0 and
the accepted token IDs remained5/7/10/11/12/13/14/15. The running candidate
pages used215 and208 PIDs under the320 limit and about1.09 GiB under2 GiB.

After an owner reports completion, run only the serialized no-cost project /
identity gate for that exact slot. If the real authenticated provider response
does not match the reviewed read-only path, keep the candidate quarantined and
do not import it. Do not copy browser Profiles, databases, Cookies,
credentials or runtime secrets into Git or a colleague's browser. Never sync
or enable a new Flow token from a login report alone.
