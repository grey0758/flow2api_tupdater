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
4. Stop at `ready_for_pro_redemption`. Redeem the account's own PRO link in
   its authenticated Profile. Verify the exact identity has Google One AI Pro
   and Flow PRO; if the VNC site fails, use a separate local Chrome Profile
   with the same extension and approved egress for that identity, then return
   to the retained Updater Profile. Record both observed gates with
   `confirm-pro`. Never infer PRO from a successful login or an empty popup.
5. After the supported Profile handoff and PRO verification, run exactly one guarded
   `sudo /usr/local/sbin/sgp011-flow-onboard-profile <PROFILE_ID>`.
6. For the returned disabled pending Flow token, run exactly one
   `sudo /usr/local/sbin/sgp011-flow-account-health-run --pending-token-id
   <FLOW_TOKEN_ID>`.
7. Enable the Flow token and Updater Profile through their supported APIs only
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
sgp011_flow_account_pipeline.py resume-login --record-id account-NNN --profile-id <PROFILE_ID>
sgp011_flow_account_pipeline.py recover-login --record-id account-NNN --profile-id <PROFILE_ID>
sgp011_flow_account_pipeline.py confirm-pro --record-id account-NNN --profile-id <PROFILE_ID> --google-one-confirmed --flow-pro-confirmed
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

`batch` accepts only distinct owner-selected `pending` records. It stops after
visible login, project validation and supported handoff, before PRO redemption,
receiver sync, paid image or activation. `resume-login` continues a retained
`login_invited` Profile without rotating its owner invitation. `onboard` only
accepts `pro_verified`; `confirm-pro` records the two operator-observed gates
after real redemption. Its actual
concurrency is the smaller of `--parallel`, five, and the control plane's
currently free slots. Browser login and project checks run concurrently.
Run guarded receiver sync, paid image acceptance, and activation serially.
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

## 2026-10-04 PRO redemption batch

The ten owner-selected records are account-039 through account-048. Records
039/040 and 045 completed Google One AI Pro and Flow PRO verification, one
guarded sync, one decoded paid image each, enablement, and OpenBao `imported`.
Account-045 is Profile64 / Flow token50, with its single accepted image at
Flow log35630 / NewAPI log67950, 1376×768. The account-039 and account-040
accepted reports are retained separately under the root-only backup tree.

Records 041–044 completed their own Google/Labs login and no-cost Flow project
handoff in Profiles65/61/63/62. Their links reported `Subscription already in
use`; each exact Google One account still showed free 15 GB and Upgrade.
Records 046–048 likewise completed no-cost handoff in Profiles66/68/67, but
the redemption service reported `Failed to fetch fresh link`, and Google's
old link said `You need a new activation link`. All seven are
`ready_for_pro_redemption`, with no Flow token, receiver sync, paid image or
scheduler enablement. The short error classification is stored in OpenBao
without persisting a private link. Provide fresh links before `confirm-pro`;
never interpret a used link as evidence that the current Google identity has
PRO.

One valid offer, account-045, rendered its `Activate plan` button in the DOM
below the VNC viewport. The empty `span.UTNHae` was unrelated. The protected
operator helper can trigger the exact control on the official
`one.google.com/activate-plan/` page in that same visible Profile; the final
Google One member confirmation and Flow PRO/credits must still be observed.
The local Chrome147/YesCaptcha fallback remains isolated under
`/home/grey/backups/flow-account039-local-chrome-20261004`, using a separate
Chrome Profile per identity and the in-memory OpenBao key. Do not copy its
private browser data or screenshots into Git.

The Google email field now accepts `input[name="identifier"]` as well as
`input[type="email"]`. The five production workers were layered from their
distinct original images, retaining each validator, and use 512 PIDs/4 GiB
memory to avoid the observed 320 PID and 2 GiB Chromium crashes. The source
overlay is `compose.pro-redemption-workers.yaml`; production copy is under
`/opt/flow2api-token-updater-v34`. Continue passing the full Compose stack
and the exact project name. A crashed browser must be recovered through its
original quarantined slot after checking the claimed Profile and owner
session; a control restart revokes all live invitations and is only safe
after every other active slot has completed.

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
