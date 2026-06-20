# Security audit — aegis-gate hackathon preprod (2026-06-19)

**Trigger:** Redis hijack incident discovered at 2026-06-19 06:53 UTC.
**Scope:** This deployment host + the WAF process running on it, plus
generalisable items that apply to any aegis-gate single-node deployment.
**State:** Findings only. No mitigations applied to items below except:
**Redis re-bound to `127.0.0.1:6379`** (fix already shipped — see
[deploy/docker-compose.dev.yml](../../../deploy/docker-compose.dev.yml)).

## The incident, in brief

```
when:    2026-06-18 23:25:34 UTC (first read-only error)
attacker IP: 175.24.232.83:24551
action:  REPLICAOF 175.24.232.83 24551 against our exposed Redis on 0.0.0.0:6379
impact:  - Redis flipped to read-only replica
         - initial replication sync WIPED our data
         - 95 shared-config versions (config:waf:v:1..95) gone
         - cluster lease renewal failed → 1,231 retries in WAF logs
         - dashboard mutations from operator silently lost durability
exploited because:
         - aegis-redis container published port 6379 on 0.0.0.0
         - AWS Security Group `ht-hackathon-13-sg` allowed inbound :6379 (or
           wide-CIDR allowed it)
         - Redis had no `requirepass` and `protected-mode` was effectively off
           because we bound to a non-loopback interface
forensics:
         - no Redis module loaded (no RCE attempted via module-load attack)
         - no ~/.ssh/authorized_keys tampering (3 keys = NICO + SHU + LIUD,
           all legitimate)
         - no dropped files in /tmp, /var/tmp during the window
         - no cron persistence created
         - shell history clean
         - conclusion: attacker only ran REPLICAOF (destructive prank or
           failed exploit chain); no follow-on compromise observed
```

## Severity legend
- **CRITICAL** — exploitable from the internet right now, fix immediately.
- **HIGH** — known weakness, attacker would need more steps but path is clear.
- **MEDIUM** — defense-in-depth gap that doesn't yield direct compromise but
  weakens the overall posture.
- **LOW** — observation or accepted tradeoff, document for completeness.

---

## 🔴 CRITICAL

### C-1 — No host firewall (`iptables` empty, `nftables` not running)

**Risk.** Anything bound to `0.0.0.0` is reachable from the internet if AWS
Security Group allows it. We rely entirely on AWS SG, which is controlled by
the SA team — outside our change window. The Redis incident proves the SG was
at least once permissive enough to admit the attack.

**Currently 0.0.0.0:**
```
0.0.0.0:22000  sshd
0.0.0.0:80     waf  (force-https redirect)
0.0.0.0:443    waf  (TLS data plane)
0.0.0.0:9443   waf  (admin dashboard)
```

**Fix.**
```sh
sudo dnf install -y firewalld
sudo systemctl enable --now firewalld
# allow only the ports we publish
for p in 22000/tcp 80/tcp 443/tcp 9443/tcp; do
  sudo firewall-cmd --permanent --add-port=$p
done
sudo firewall-cmd --permanent --set-target=DROP
sudo firewall-cmd --reload
# verify
sudo firewall-cmd --list-all
```

Alternative (lighter): plain iptables INPUT default DROP + ACCEPT for the four
ports above, persisted via `iptables-save > /etc/sysconfig/iptables`.

Belt-and-suspenders with AWS SG. Coordinate with SA team to also tighten the
SG to only allow :22000 from your team's IP and :80/:443/:9443 from the
committee's CIDRs.

---

### C-2 — SSH `PermitRootLogin yes`

```
$ sudo grep PermitRootLogin /etc/ssh/sshd_config
PermitRootLogin yes
```

**Risk.** Combined with the absence of bruteforce protection (see H-1), a
single key or password compromise gives full root. Even though
`PasswordAuthentication no` is set, key compromise is the more realistic
vector.

**Fix.**
```sh
sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
# verify there's a working `ssm-user` login + sudo before reloading sshd
sudo sshd -t                         # validates the config
sudo systemctl reload sshd
```

Test in a SECOND ssh session before closing your existing one, in case it
breaks the only path in.

---

### C-3 — Admin dashboard exposed wide-open + HTTP

| field | value |
|---|---|
| `listeners.admin.bind` | `0.0.0.0:9443` |
| `admin.dashboard_auth.ip_allowlist` | `["0.0.0.0/0", "::/0"]` |
| protocol | HTTP (no TLS) |
| `AEGIS_INSECURE_COOKIES` | `1` (session cookie issued without `Secure` flag) |
| password | shared known value `aegis-hackathon-2026`, known to committee |
| `totp_enabled` | `false` |
| login rate-limit | 100/min/IP — only barrier against bruteforce |

**Risk.**
- **Cookie theft on the wire.** Any router between the committee/attacker and
  our box sees the `aegis_session` cookie in cleartext on every request. Once
  stolen, the cookie grants full admin until TTL (30 m idle / 8 h absolute).
- **Bruteforce.** 100 attempts/min/IP × number of distinct IPs an attacker
  rents = realistic dictionary attack on `aegis-hackathon-2026` and other
  weak passwords. Argon2id slows offline cracking once the hash leaks, but
  online attacks aren't slowed by argon2id.
- **CSRF replay.** `csrf_secret_ref` is in `waf.yaml` plain (`9oVHX…`). Anyone
  who reads that file (or finds it in a backup) can forge CSRF tokens.

**Fix options (pick one or layer them):**

Track A — strongest, slight friction:
```yaml
listeners:
  admin:
    bind: "127.0.0.1:9443"
admin:
  dashboard_auth:
    ip_allowlist: ["127.0.0.1/32", "::1/128"]
```
Committee SSH-tunnels: `ssh -L 9443:127.0.0.1:9443 ssm-user@18.140.47.62`.

Track B — keep public, but TLS + 2FA:
- Add `:9443` to the `tls.certificates` block (pin one of the existing LE
  certs or add a third SNI).
- Set `AEGIS_INSECURE_COOKIES=` (empty) so the `Secure` flag is restored.
- `admin.dashboard_auth.totp_enabled: true` — enroll TOTP per operator.
- Optionally tighten `ip_allowlist` to the committee's known CIDRs.

Either track: rotate `csrf_secret_ref` to `${secret:env:AEGIS_CSRF_SECRET}`
and store the value in `/etc/aegis-gate.env` (chmod 600, root:root) instead
of the YAML.

---

## 🟠 HIGH

### H-1 — No bruteforce protection (no fail2ban / sshguard)

Both SSH and the WAF admin dashboard are exposed to the internet with no IP
banning layer. SSH is key-only (good) so SSH bruteforce is mostly a noise
problem, but the dashboard's 100/min/IP rate-limit can be amortised across
many source IPs.

**Fix.**
```sh
sudo dnf install -y fail2ban
sudo systemctl enable --now fail2ban
# Add a jail for our :22000 sshd
sudo tee /etc/fail2ban/jail.d/sshd.conf >/dev/null <<'EOF'
[sshd]
enabled  = true
port     = 22000
filter   = sshd
logpath  = /var/log/secure
maxretry = 5
findtime = 600
bantime  = 3600
EOF
# Optional jail for /admin/login 401s — write a filter that parses
# `waf_audit.log` for repeated invalid_credentials from same IP.
sudo systemctl restart fail2ban
sudo fail2ban-client status sshd
```

---

### H-2 — WAF process has `NoNewPrivs: 0`

```
$ grep NoNewPrivs /proc/$(pgrep -x waf)/status
NoNewPrivs: 0
```

A future RCE in the WAF (improbable but the threat surface is wide — TLS,
HTTP, JSON parsing, ONNX, gRPC, MaxMindDB) could exec a setuid binary and
escalate. Setting `NoNewPrivileges=yes` makes that impossible regardless of
binary discovery.

**Fix.** Add to the launcher (or a systemd unit if you re-enable
`aegis-gate.service`):
```
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/ssm-user/workspace/aegis-gate
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
```

For the current `setsid nohup ./waf …` model, the simplest equivalent:
prepend `setpriv --no-new-privs --reuid=$(id -u) --regid=$(id -g) --inh-caps=-all`
in `cmd_start` of `run-staging.cmd`.

---

### H-3 — journald is volatile, no persistent OS logs

```
$ ls /var/log/journal
ls: cannot access '/var/log/journal': No such file or directory
```

Storage=auto → journal writes to tmpfs at `/run/log/journal/`. Reboot wipes
it. We've already lost forensic data once (the 3-hour conntrack watchdog
reboot in Round 1).

**Fix.**
```sh
sudo mkdir -p /var/log/journal
sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
journalctl --disk-usage  # confirms it's now persistent
```

---

### H-4 — `logs/audit/` is 4.9 GB; chain retention not enforcing

```
$ du -sh logs/audit/
4.9G
```

`audit.retention: "7d"` in `waf.yaml` is set, but disk usage suggests
files older than 7d aren't being deleted, or each daily file is multi-GB
under load.

**Risk.** Disk fill → host stops accepting writes → WAF crash. The benchmark
host has 99 GB partition with ~38 GB free as of this morning; on a sustained
high-RPS bench this could fill in <24 h.

**Fix.**
1. Verify the retention sweeper is running:
   ```
   grep -iE 'audit.*retention|sweep|prune' logs/waf.json | tail
   ```
2. Add `logrotate` for the same files as belt-and-suspenders:
   ```
   sudo tee /etc/logrotate.d/aegis-audit >/dev/null <<'EOF'
   /home/ssm-user/workspace/aegis-gate/logs/audit/*.ndjson {
     daily
     rotate 7
     compress
     delaycompress
     missingok
     notifempty
     nocreate
     su ssm-user ssm-user
   }
   EOF
   ```
3. Consider lowering retention to `"2d"` for hackathon density.
4. **Trim now** to recover disk:
   ```sh
   find logs/audit -name 'audit-*.ndjson' -mtime +2 -delete
   ```

---

### H-5 — No `cargo audit` in the build pipeline

No automated check for known-vulnerable Rust dependencies. The WAF links
TLS (rustls), HTTP/2 (h2), ONNX (ort), Redis client, instant-acme, etc. —
each can ship a CVE.

**Fix.**
```sh
cargo install cargo-audit
cargo audit                       # run weekly + on every PR
```

Add to CI: fail the build on `RUSTSEC-*` findings without an explicit waiver.

---

## 🟡 MEDIUM

### M-1 — stale `/etc/aegis-gate.env` from Round 1

Not used by Round 2 (`./run-staging.cmd start` sources `./.env` from CWD
instead). Still contains `AEGIS_BENCHMARK_SECRET`, `AEGIS_CSRF_SECRET`,
`AEGIS_VIPTALK_BOT_TOKEN`. Permissions are `root:root`/`chmod 600` so a
regular user can't read it. Secret sprawl is the risk: leaks tend to come
from forgotten files.

**Fix:** either delete (`sudo rm /etc/aegis-gate.env`) or rotate every
secret in it and document the rotation.

### M-2 — No Redis backup / point-in-time recovery

The incident wiped 95 shared-config versions with no recovery option
(`appendonly no`, `--save` empty in compose). For the hackathon this
is acceptable (we re-publish on dashboard mutate), but in any longer-lived
deployment a daily `BGSAVE` + offsite copy is table stakes.

**Fix:** in compose, change `--save ""` to `--save 900 1` + a cron job
copying `dump.rdb` off the docker volume.

### M-3 — CSRF secret + argon2id hash in `waf.yaml` plain

Both currently inline:
```yaml
password_hash_ref: '$argon2id$v=19$m=19456,t=2,p=1$qeAZH...'
csrf_secret_ref:   "9oVHXj4tgJjgSmjwMs/Px8qf3oBQosKjqdjDNkQxJew="
```

`waf.yaml` is `chmod 644` and **not in git** (verified), so the risk is
limited to anyone who reads the file (root or `ssm-user`). The argon2id
hash is moderately bruteforce-resistant offline. The CSRF secret reveal
lets an attacker forge tokens.

**Fix:** rotate both to env refs:
```yaml
password_hash_ref: "${secret:env:AEGIS_ADMIN_PASSWORD_HASH}"
csrf_secret_ref:   "${secret:env:AEGIS_CSRF_SECRET}"
```
and put the values in `./.env` (already `chmod 600`) or systemd
`EnvironmentFile=` with `root:0 0600`.

### M-4 — `aegis_session` cookie has `SameSite=Strict` but no `Secure`

Because `AEGIS_INSECURE_COOKIES=1`. Required while admin is on HTTP. Fixed
the moment admin is on TLS (see C-3 Track B).

---

## 🟢 LOW / observations (already in good shape)

| | |
|---|---|
| L-1 | SSH on `:22000` — non-standard port, fewer dumb scanners. ✓ |
| L-2 | `PasswordAuthentication no` — key-only SSH. ✓ |
| L-3 | WAF runs as `ssm-user` (uid 1002), not root. ✓ |
| L-4 | `CapEff = 0x400` = `CAP_NET_BIND_SERVICE` only — minimal. ✓ |
| L-5 | `./.env` is `chmod 600` and **not in git**. ✓ |
| L-6 | `waf.yaml` not in git. ✓ |
| L-7 | TLS 1.2+ on data plane, HSTS 1y. ✓ |
| L-8 | LE certs valid through Aug 22 2026 (renew before). ✓ |
| L-9 | `/__waf_control/*` is peer-IP-gated to loopback in code regardless of bind. ✓ |
| L-10 | Strikes `block_at: 1_000_000` — single FP can't perm-block. ✓ |
| L-11 | Bot classifier + GeoIP + ASN signals wired. ✓ |
| L-12 | Hash-chained audit log on disk (tamper-evidence, even if 4.9 GB — see H-4). ✓ |

---

## Suggested order if you fix one a day

1. **Day 0 (today, already done):** Redis loopback bind, container cleanup.
2. **Day 1:** C-1 (firewall) + C-2 (sshd PermitRootLogin no) + H-1 (fail2ban). All on the OS layer, cheap, high-impact.
3. **Day 2:** C-3 (admin lockdown — pick a track) + M-3 (secrets to env refs).
4. **Day 3:** H-2 (NoNewPrivs + systemd hardening) + H-3 (journal persistence).
5. **Day 4:** H-4 (audit log rotate + retention sweeper) + H-5 (`cargo audit`).
6. **Day 5:** M-1 (kill /etc/aegis-gate.env) + M-2 (Redis backup) + M-4 (auto-resolves after C-3 Track B).

Each step is reversible. Each leaves the WAF running. Apply, verify with the
smoke + conformance helpers, move on.

## Cross-team coordination

| owner | ask |
|---|---|
| **SA team** | Tighten AWS Security Group `ht-hackathon-13-sg`: inbound `:22000` only from your team's IP range; inbound `:80`/`:443`/`:9443` only from the committee's known CIDRs (ask committee for theirs). |
| **Committee** | Their source CIDRs for the `:9443` admin allowlist + `:80`/`:443` data plane. |
| **Dev team** | The hot-flippable gate-toggle apply-on-rehydrate bug ([plans/issues/runtime_gate_toggles_not_durable.md](../runtime_gate_toggles_not_durable.md)) — still half-fixed. |

---

## What got fixed in this session (for the record)

- ✓ Redis container re-bound to `127.0.0.1:6379` (was `0.0.0.0:6379`).
- ✓ `REPLICAOF NO ONE` to restore master role.
- ✓ Six unused containers removed: `aegis-grafana`, `aegis-prometheus`, `aegis-redis-exporter`, `aegis-etcd`, `aegis-httpbin`, `aegis-jaeger`.
- ✓ ~1.5 GB disk reclaimed (1.21 GB images + 292 MB orphan volumes).
- ✓ WAF restarted; healthz/ready 200; zero read-only errors after restart.
- ✓ Forensic checks: no follow-on compromise observed.
