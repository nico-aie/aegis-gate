# Operations (day-2)

Day-2 concerns: HA topology, compliance modes, residency, DR. Owner:
**M3** ([`../../plans/member-3-control-plane.md`](../../plans/member-3-control-plane.md)).

| Doc | Summary |
|---|---|
| [ha-clustering.md](./ha-clustering.md) | etcd (config) + optional Redis (counters), split-brain safety |
| [compliance.md](./compliance.md) | FIPS, PCI, HIPAA, SOC 2, GDPR modes |
| [data-residency-retention.md](./data-residency-retention.md) | Region pin + retention + GDPR erasure |
| [dr-backup.md](./dr-backup.md) | RPO/RTO, snapshots, restore drills |

For the runbook side of these (alert → page → fix), see
[`../observability/slo-sli-alerting.md`](../observability/slo-sli-alerting.md).
