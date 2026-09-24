# sgp011 Flow account onboarding automation

This directory preserves the non-secret, production-safe part of the account
onboarding workflow. It deliberately does not automate Google account choice,
password entry, TOTP/MFA, CAPTCHA, device confirmation, recovery challenges or
consent. Those actions remain visible owner actions in the dedicated isolated
VNC desktop.

The login workers always launch Chromium with extensions disabled. They never
install a CAPTCHA-solving extension or read/inject a solver key from OpenBao.
The server-side image CAPTCHA provider is a separate runtime boundary and is
not a Google-login mechanism. When a Google challenge is detected, the check
returns only `manual_action_required`, retains the exact Profile and visible
VNC, and performs no handoff, extraction or sync. The owner completes the
challenge in that desktop, after which the same no-cost check can continue.

The reusable pipeline is:

1. Store each owner-supplied account as one versioned OpenBao KV v2 record.
2. Prepare an inactive, credential-empty Profile through the Updater
   `/api/login-slots/prepare` endpoint.
3. Start one of the two isolated login workers and send its memory-only
   invitation directly through the approved personal WeCom sender.
4. After the owner completes Google/Flow and Labs authorization, run exactly
   one `sudo /usr/local/sbin/sgp011-flow-onboard-profile <PROFILE_ID>`.
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
sgp011_flow_account_pipeline.py prepare-invite --record-id account-NNN --profile-name <NAME> --basic-password-stdin
sgp011_flow_account_pipeline.py onboard --record-id account-NNN --profile-id <PROFILE_ID>
sgp011_flow_account_pipeline.py accept --record-id account-NNN --profile-id <PROFILE_ID> --token-id <FLOW_TOKEN_ID>
sgp011_flow_account_pipeline.py enable --record-id account-NNN --profile-id <PROFILE_ID> --token-id <FLOW_TOKEN_ID>
```

`prepare-invite` reads the established VNC Basic Auth password from a hidden
prompt or stdin and pipes the complete notification directly to the approved
sender. It does not accept a password argument. `onboard` stops at a disabled
pending token. `accept` is the one explicitly selected paid image. `enable`
requires a unique completed pending-image evidence directory before changing
the token/Profile pair and compensates by disabling the token if Profile
enablement fails.

Every mutating stage first requires the exact OpenBao state transition and
record-to-Profile-to-Token binding. `onboard` additionally passes the expected
inventory identity only over stdin to the guarded host command; the host
compares it in memory after the no-cost browser check/extraction and before
backup or receiver sync. A wrong Google identity therefore stops without
creating a Flow token, while neither expected nor observed identity is logged.
