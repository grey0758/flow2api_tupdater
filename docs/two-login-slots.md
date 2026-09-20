# Two concurrent owner-login slots

This branch adds exactly two isolated, interactive login desktops. It does
not make account acceptance concurrent.

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
   assigned page, then selects **I completed login**. This leaves that exact
   desktop open in `awaiting_check`; the page has no sync, Cookie export,
   activation or account-administration controls.
5. The administrator runs one serialized `check-login` against that exact
   context. It validates Labs session, credits and complete Cookies before it
   binds a project observed in the same context. A failed check returns the
   same private desktop to the same owner; a successful check closes it.
6. The administrator applies the rest of the accepted serial process: at most
   one `extract`, local identity/project deduplication, online Updater
   and Flow SQLite backups plus the read-only NewAPI boundary, exactly one
   supported sync, explicit pending-account enablement and one isolated image
   acceptance.

Visible login completion is never evidence that an account is schedulable.

## Isolation and access boundary

- Slot 1 owns display `:101`, VNC `127.0.0.1:5901` and noVNC
  `127.0.0.1:6081`.
- Slot 2 owns display `:102`, VNC `127.0.0.1:5902` and noVNC
  `127.0.0.1:6082`.
- Neither slot port is published by Compose. The application proxies noVNC
  over its authenticated HTTPS origin.
- Invitations carry 256-bit random capabilities in the URL fragment. The
  fragment is exchanged for an HttpOnly, Secure, SameSite=Strict cookie and is
  immediately removed from browser history. It is not sent in HTTP requests.
- Invitations expire after four hours. Successful administrator validation or
  cancellation closes that browser and desktop. A Profile is single-invite:
  once launched, a later colleague cannot inherit that browser even when its
  database has not yet been extracted. A failed or expired invitation needs
  operator review before creating a new fresh Profile for the owner.
- The backend observes a same-Profile Flow project URL/anchor at completion,
  storing only its normalized UUID in the local Updater SQLite so an app
  restart cannot erase that context. This is not proof of project ownership:
  the administrator must still validate OAuth, identity and receiver collision
  before syncing. No browser Cookie or session value is stored by the slot.
- Scheduler, extraction, sync, export, update and deletion operations reject
  a Profile while it is in a login slot. Batch sync excludes slot owners.
- The slot VNC servers need no second password because they are loopback-only
  and reachable only through the per-slot capability gate. Public deployments
  still require HTTPS and independent administrator authentication at the
  reverse proxy.

## Deployment boundary

Do not deploy this branch over an active single-browser session. Build and
exercise it in an isolated staging instance with empty test Profiles, verify
both WebSocket/RFB sessions simultaneously and record peak memory/OOM status,
then schedule a separate reviewed
cutover. Do not copy browser profiles, databases, Cookies, credentials or
runtime secrets into Git or the test environment.
