# Operations (day-2)

Day-2 concerns: HA topology, compliance modes, residency, DR.
Implementation lives in `crates/aegis-control/src/{ha,compliance,residency,…}`;
per-feature plans are tracked in [`../../plans/`](../../plans/).

| Doc | Summary |
|---|---|
| [ha-clustering.md](./ha-clustering.md) | etcd (config) + optional Redis (counters), split-brain safety |
| [compliance.md](./compliance.md) | FIPS, PCI, HIPAA, SOC 2, GDPR modes |
| [data-residency-retention.md](./data-residency-retention.md) | Region pin + retention + GDPR erasure |
| [dr-backup.md](./dr-backup.md) | RPO/RTO, snapshots, restore drills |

For the runbook side of these (alert → page → fix), see
[`../observability/slo-sli-alerting.md`](../observability/slo-sli-alerting.md).
