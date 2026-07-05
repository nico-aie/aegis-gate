# Admin Accounts & Two-Factor Authentication (TOTP)

> How to create admin accounts and how mandatory 2FA works.
> Feature branch: `feat/2fa` · Plan: `plans/issues/FEAT-totp-google-authenticator-2026-07.md`

Every admin account authenticates with a **password + a 6-digit TOTP code**
from a standard authenticator app (Google Authenticator, Authy, 1Password,
FreeOTP, …). 2FA is **enforced by default** (`require_totp: true`): a password
alone never grants dashboard access. All accounts are equal-privilege admins
(no RBAC yet — that is a separate track).

---

## 1. Create an account (recommended: one command)

```bash
./deploy/create-admin.sh <username>
```

The script prompts for the password twice (silent input — never echoed, never
in shell history or `ps`), then:

1. mints an argon2id hash via `waf admin create-account`,
2. inserts the entry under `admin.dashboard_auth.accounts:` in the config
   (re-indented to match the file),
3. runs `waf validate` — on any failure the config is **restored from backup**.

```text
$ ./deploy/create-admin.sh alice
Password for alice:
Confirm password:

✔ account 'alice' added to config/dev.yaml (config validates)
  → restart the WAF (make run-dev) to load it
  → first web login shows the Google Authenticator QR setup
```

Variants:

```bash
./deploy/create-admin.sh alice config/prod.yaml   # target another config file
./deploy/create-admin.sh alice --print            # print the YAML fragment only, don't edit
WAF_BIN=./waf ./deploy/create-admin.sh alice      # binary at a non-default path
```

Guard rails: duplicate usernames are refused before the password prompt;
mismatched or empty passwords are refused; if the edited config fails
validation the original is restored and the fragment is printed for a manual
paste.

**Restart the WAF afterwards** — the account set is read at boot:

```bash
# Ctrl+C the running instance, then:
make run-dev
```

## 2. First login — the admin enrolls their own authenticator

Hand the username + password to the new admin. On their first login at
`http://<host>:9443/admin/login`:

1. They enter **username + password** (no code yet) and sign in.
2. The server issues an *enrollment-only* session: the **"Set up two-factor"**
   page appears with a QR code. Until enrollment is confirmed, this session
   can reach nothing else — every other admin API answers
   `403 totp_enrollment_required`.
3. They scan the QR with Google Authenticator on **their own phone**
   (or expand *"Can't scan?"* and type the setup key manually — choose
   "time-based").
4. They enter the 6-digit code the app shows and press **Verify & activate**.
   Only a correct code activates the factor; an unconfirmed secret never
   counts. Pending (unconfirmed) enrollments expire after **15 minutes** —
   reload the login page to restart.
5. Done — they land on the dashboard. Every subsequent login requires
   password **and** the current app code (entered in the two-step
   verification dialog).

This flow is deliberate: the TOTP secret only ever exists between the server
and the admin's phone — it never passes through the operator's terminal.

### Where enrollment state lives

| Deployment | Backend | Behaviour |
|---|---|---|
| Cluster / standalone with Redis | `state.backend: redis` | Fleet-wide + restart-durable (hash `control:waf:admin:totp`). Enroll on node A, log in via node B. |
| Standalone in-memory | `state.backend: in_memory` | Process-lifetime only — after a restart, un-enrolled accounts re-enroll at next login. Pre-provision via YAML/CLI if you need durability without Redis. |

## 3. Alternative: pre-enroll from the CLI

If you want the secret minted up front (e.g. provisioning your own account on
a headless box), skip the web flow:

```bash
./target/release/waf admin create-account --username alice --with-totp
```

This prints the `accounts:` fragment **including** `totp_secret_b32` +
`totp_enabled: true`, the `otpauth://` URI, an ASCII QR you can scan straight
off the terminal, and 10 single-use recovery codes. Paste the fragment into
the config yourself and restart.

Related low-level commands:

```bash
waf admin set-password             # hash a password only
waf admin enroll-totp [--issuer I --account A]   # mint a TOTP secret + QR only
```

## 4. Config reference

```yaml
admin:
  dashboard_auth:
    require_totp: true          # default — password alone never grants access
    accounts:
      - username: "alice"
        password_hash_ref: "$argon2id$..."   # or a ${secret:...} ref in prod
        # no totp fields → alice enrolls via QR at first login
      - username: "bob"
        password_hash_ref: "$argon2id$..."
        totp_secret_b32: "JBSW..."           # pre-enrolled (CLI --with-totp)
        totp_enabled: true
```

Rules worth knowing:

- The legacy top-level `password_hash_ref` / `totp_*` fields remain a
  single-admin shorthand (folded into one account named `admin`). Setting
  **both** the legacy fields and `accounts:` is rejected at validation —
  migrate the legacy admin into an `accounts:` entry.
- `require_totp` is a global policy. `require_totp: false` (dev/CI opt-out)
  logs a loud boot warning — and an account that **has** enrolled still needs
  its code even then.
- Duplicate or empty usernames are rejected at validation.
- Lockout / rate-limit counters are per `(ip, user)` — locking out one admin
  never locks another.
- Full key reference: [`config/REFERENCE.md`](../config/REFERENCE.md) §`admin`.

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `user or password incorrect` although the password is right | The account has TOTP enrolled — the code is required with every login. By design the server never reveals *which* factor failed (anti-oracle, F-CRITICAL-003). Enter the current app code in the two-step dialog. |
| Login succeeds but every page answers `403 totp_enrollment_required` | Enrollment-only session (password OK, factor not confirmed). Go to `/admin/login` — browser navigations redirect there automatically — and finish the QR setup. |
| `no pending enrollment (expired or never started)` on confirm | The 15-minute pending window lapsed. Reload the login page and sign in again to get a fresh QR. |
| Codes from the app never match | Check the phone's clock (TOTP is time-based, ±30 s skew tolerated). The QR encodes SHA-1 / 6 digits / 30 s — the Google-Authenticator baseline; don't change algorithm parameters. |
| Admin lost their phone | Remove their runtime enrollment so the next login re-enrolls: `redis-cli hdel control:waf:admin:totp <username>` (or the docker equivalent). Recovery-code login and `waf admin disable-totp` are tracked separately (TF-2 / AA-P1b) and not shipped yet. |
| New account rejected at boot | Run `./target/release/waf validate --config <file>` — most common: both legacy fields and `accounts:` set, or a duplicate username. |

## 6. Security notes

- Passwords are stored as **argon2id** hashes; TOTP verification is
  constant-time with per-account replay protection (each code counter is
  accepted at most once).
- Unknown usernames run a dummy password verification so response timing
  doesn't leak account existence.
- Enroll/confirm emit audit events (`totp_enroll_started`,
  `totp_enroll_confirmed`, `login_enrollment_required`) carrying the acting
  username — never the secret or codes.
- For production, keep hashes and secrets behind `${secret:...}` references
  rather than inline YAML, and create accounts on a trusted machine.
