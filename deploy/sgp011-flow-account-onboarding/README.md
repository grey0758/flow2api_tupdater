# sgp011 Flow account onboarding automation

The `batch` command runs the account import from code. It reads each selected
OpenBao record in memory, prepares a separate Profile and worker, enters the
password and a fresh Authenticator TOTP on recognized Google pages, opens Labs
and Flow, and checks the exact identity. An authenticated empty project list
permits one New project click. Unknown pages, CAPTCHA, SMS, device/recovery
checks and consent remain visible in the same VNC for owner review. A batch
failure never submits a second sync or paid image automatically.

The login workers launch headed Chromium with the pinned YesCaptcha Assistant
Manifest V3 extension from their separate read-only `/slot-extension` mounts.
The main VNC browser uses `/vnc-extension`. A missing extension fails closed
on deployed workers. Future Profiles inherit the extension when they launch
in a slot. The workers never read/inject a solver key from OpenBao.
The server-side image CAPTCHA provider is a separate runtime boundary and is
not a Google-login mechanism. When a Google challenge is detected, the check
returns only `manual_action_required`, retains the exact Profile and visible
VNC, and performs no handoff, extraction or sync. The owner completes the
challenge in that desktop, after which the same no-cost check can continue.

The reusable pipeline is:

1. Store each owner-supplied account as one versioned OpenBao KV v2 record.
2. Prepare an inactive, credential-empty Profile through the Updater
   `/api/login-slots/prepare` endpoint.
3. Start an isolated login worker, automate only the recognized Google forms,
   and validate the same browser's identity and provider project membership.
   Send the memory-only invitation through personal WeCom if intervention is
   needed.
4. After the supported Profile handoff, run exactly one guarded
   `sudo /usr/local/sbin/sgp011-flow-onboard-profile <PROFILE_ID>`.
5. For the returned disabled pending Flow token, run exactly one
   `sudo /usr/local/sbin/sgp011-flow-account-health-run --pending-token-id
   <FLOW_TOKEN_ID>`.
6. Enable the Flow token and Updater Profile through their supported APIs only
   after the pending image report passes unique Flow/NewAPI attribution and
   complete image decode.

The pending image checker resolves a newly inserted token to exactly one
Updater Profile by normalized identity. It therefore does not require a source
change for every future Profile/token number. Accepted tokens 19 and 20 are
also part of the ordinary health mapping.

`Dockerfile.control-reconcile` preserves the accepted Updater image and adds
the restart-reconciliation correction. A successful worker `abort` clears its
assignment before returning; the control plane accepts only the exact terminal
shape for that signed slot-specific request. All other worker operations still
require the original generation and Profile ID.

Never put an invitation capability, Google credential, TOTP seed, Cookie,
ST/AT, project UUID, service token or VNC plaintext password in this directory,
Git, command arguments, environment files, documentation or logs.

## Operator program

`sgp011_flow_account_pipeline.py` exposes the guarded stages without merging
their risk boundaries:

```text
sgp011_flow_account_pipeline.py status
sgp011_flow_account_pipeline.py batch --parallel 5 account-NNN account-MMM
sgp011_flow_account_pipeline.py prepare-invite --record-id account-NNN --profile-name <NAME>
sgp011_flow_account_pipeline.py onboard --record-id account-NNN --profile-id <PROFILE_ID>
sgp011_flow_account_pipeline.py accept --record-id account-NNN --profile-id <PROFILE_ID> --token-id <FLOW_TOKEN_ID>
sgp011_flow_account_pipeline.py enable --record-id account-NNN --profile-id <PROFILE_ID> --token-id <FLOW_TOKEN_ID>
```

`prepare-invite` sends a one-time token link directly to the approved sender.
The invitee enters the scoped VNC without a separate username or password.
`onboard` stops at a disabled
pending token. `accept` is the one explicitly selected paid image. `enable`
requires a unique completed pending-image evidence directory before changing
the token/Profile pair and compensates by disabling the token if Profile
enablement fails.

`batch` accepts only distinct owner-selected `pending` records. Its actual
concurrency is the smaller of `--parallel`, five, and the control plane's
currently free slots. Browser login and project checks run concurrently.
Guarded receiver sync, paid image acceptance, and activation run serially.
Record states mark `preparing`, `onboarding_running`,
`image_acceptance_running`, and `enable_running` before their external side
effects; an uncertain result is left for operator reconciliation. Inspect the
original root-only host report
and live token/Profile state before advancing `onboarding_review` or
`image_acceptance_review`. Never rerun a guarded sync or paid image because a
caller parser failed. Automatic challenge handling never bypasses Google's
manual checks.

The 2026-10-01 production deployment exposes five core slots. The
`docker-compose.login-slots-five.yml` overlay adds three isolated core slots,
each with its own browser volume, control/egress socket, UID, extension mount,
and resource limits. The extra core slots use `core3`–`core5` host paths so
the retained private slot3 sidecar is not touched. Stage those extension
bundles and verify the host's capacity before enabling the overlay. The
five-slot overlay is deployed with the production image override in this
directory. Always pass `-p sgp011-flow2api-token-updater-v34` to Compose so
the control plane and workers use the same named browser volumes. Read live
slot capacity before each batch; an earlier snapshot is not a reservation.
The first selected new record, account-038, ultimately completed with operator
intervention. A fully unattended five-account run has not been demonstrated.
An unfinished Profile claim quarantines only its own numbered core slot;
claims with no trustworthy slot binding still stop all new invitations.

## 2026-10-02 accepted account and current corrections

Account-038 / Profile58 / Flow token47 completed visible Google/Labs login,
one Flow project, same-context provider ownership validation, one guarded
sync, one paid fully decoded image acceptance, and explicit enablement. OpenBao
is `imported`; do not repeat its sync or image. Its temporary login slot and
main VNC browser were later closed at the owner's request. See
`/home/grey/work/sgp_newapi_cliproxy_ops/docs/flow-account038-review-20261002.md`
for the sanitized case report and root-only report references.

The live core3–5 workers use distinct `auto-five-r4-20261002` images. Commit
`b4455c1` fixed the Labs Google sign-in entry. Commit `d149d67` prevents an
embedded Flow/Labs reCAPTCHA frame from masquerading as a Google login
challenge. The guarded host script from commit `7a9a55a` accepts unrelated
NewAPI log growth while requiring unchanged control flags and zero
nonterminal tasks; its installed SHA-256 is
`ab28bc1cf1c37eb5482734d1b1e19170bf06882dd548216719c4285acd17aa13`.
Commit `76a0677` fixes the pipeline acceptance parser: the host checker
already selects one relevant paid NewAPI request, while `newapi_log_rows`
counts all concurrent rows in the window. The original complete report is
the acceptance evidence. The four focused test files passed 98 tests on
2026-10-02. These corrections remove observed false review states; a fresh
fully unattended batch still needs its own live acceptance evidence.

Every mutating stage first requires the exact OpenBao state transition and
record-to-Profile-to-Token binding. `onboard` additionally passes the expected
inventory identity only over stdin to the guarded host command; the host
compares it in memory after the no-cost browser check/extraction and before
backup or receiver sync. A wrong Google identity therefore stops without
creating a Flow token, while neither expected nor observed identity is logged.
