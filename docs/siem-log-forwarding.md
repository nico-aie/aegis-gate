# SIEM Log Forwarding (v2, enterprise)

> **Enterprise addendum.** Forward audit events to Splunk, Elastic,
> Chronicle, QRadar, Sentinel, Sumo, Datadog, and any generic collector
> via syslog RFC 5424, CEF, LEEF, OCSF, or Kafka. Formatters and
> transports are pluggable.

## Purpose

Audit events are the raw material for SOC detection, compliance
evidence, and incident response. The WAF must deliver them in the
format each downstream tool expects, reliably and with bounded loss.

## Formats

| Format | Spec | Typical sink |
|---|---|---|
| JSON Lines | own schema v2 | generic collectors, Elastic |
| Syslog RFC 5424 | IETF 5424 | rsyslog, syslog-ng, Splunk HEC syslog |
| CEF | ArcSight CEF 0.1 | Splunk, QRadar, ArcSight |
| LEEF | QRadar LEEF 2.0 | QRadar |
| OCSF | OCSF 1.1 category-specific | Chronicle, AWS Security Lake |
| Splunk HEC | HTTP Event Collector | Splunk Cloud |
| Elastic ECS | ECS 8.x | Elastic |
| Kafka | JSON / OCSF on topic | any stream consumer |

## Transports

- **TCP + TLS** (recommended for syslog)
- **UDP** (not recommended; only for lossy dev)
- **HTTPS POST** (batch, compressed)
- **Kafka** via `rdkafka` with SASL/PLAIN, SASL/SCRAM, mTLS
- **Local file** with rotation (`tracing-appender`)
- **stdout/stderr** for containerized deployments

## Reliability

Each sink is a dedicated tokio task with:

- Bounded input channel (default 100 000 events)
- Disk spool (bounded, default 1 GiB) when the channel is full
- Priority drop policy: when the spool is full, the lowest-severity
  event in memory is dropped first; admin + critical events are never
  dropped without paging

Metrics: `waf_audit_events_total{sink,class}`,
`waf_audit_drops_total{sink,reason}`,
`waf_audit_spool_bytes{sink}`.

## Delivery semantics

- At-least-once by default (spool + retry)
- Exactly-once is unreachable across arbitrary sinks; deduplication
  is the downstream's responsibility via `event_id`
- Every event has a monotonic `event_id` (ULID) and `hash` from the
  tamper chain

## Backpressure vs data plane

The data plane never blocks on a slow sink. `emit()` is a non-blocking
push into a bounded channel. Slow sinks incur drops; fast sinks drain
normally. Alerting is configured on `waf_audit_drops_total`.

## Format examples

### CEF

```
CEF:0|Acme|WAF|2.0|BLOCK_SQLI|SQL injection blocked|8|src=203.0.113.4 suser= act=block request=/v1/login cs1Label=rule cs1=block_sqlmap_ua
```

### OCSF (Network Activity category)

JSON payload with OCSF `class_uid=4001`, `activity_id`, `severity_id`,
`src_endpoint`, `dst_endpoint`, `http_request`, and WAF-specific
metadata under `enrichments`.

### Splunk HEC

```json
{ "time": 1744540530.123, "source": "waf", "sourcetype": "waf:audit:v2",
  "event": { /* full event */ } }
```

## Configuration

```yaml
observability:
  audit:
    sinks:
      - name: siem_syslog
        type: syslog
        format: cef
        endpoint: "siem.internal:6514"
        tls: true
        ca_bundle: "/etc/waf/certs/siem-ca.pem"
        queue_size: 100000
        spool_dir: /var/spool/waf/siem
        spool_max_bytes: 1Gi

      - name: chronicle
        type: http
        format: ocsf
        endpoint: "https://chronicle.example.com/ingest"
        auth: { type: bearer, token: "${secret:vault:kv/data/waf#chronicle}" }
        batch_max: 500
        flush_interval_ms: 1000

      - name: lake
        type: kafka
        format: ocsf
        brokers: ["kafka-0:9093","kafka-1:9093"]
        topic: "waf-events"
        sasl: { mechanism: SCRAM-SHA-512, username: waf, password: "${secret:env:KAFKA_PW}" }
        tls: true
```

## Implementation

- `src/audit/sinks/{syslog,cef,leef,ocsf,http,kafka,file,stdout}.rs`
- `src/audit/formatter/{json,cef,leef,ocsf,ecs,hec}.rs`
- `src/audit/spool.rs` — bounded on-disk queue
- `src/audit/backpressure.rs` — drop policy + metrics

## Performance notes

- Formatters run on the sink task, not the request task
- CEF / LEEF / syslog formatters are zero-copy where possible
- Kafka sink batches with linger to amortize TLS cost
- File sink uses `tracing-appender` with per-hour rotation
