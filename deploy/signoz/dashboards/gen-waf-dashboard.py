#!/usr/bin/env python3
"""Generate the SigNoz v0.126 (schema v4) WAF Overview dashboard from the
WAF's real OTLP trace attributes.

Run: `python3 gen-waf-dashboard.py > waf-overview.json`

Latency note (2026-06-04): `waf.handle_data_request` span duration is
*end-to-end* — it wraps the upstream forward (`waf.forward_upstream`), so
for allowed requests it's dominated by upstream RTT, NOT the WAF's own
decision cost. The WAF decision cost is sub-millisecond and is what
blocked/challenged requests (which never forward) measure — so the
"WAF decision latency" panel filters to `action != allow`. The
end-to-end panel keeps the full span. (True per-stage WAF overhead lives
in the Prometheus `waf_request_duration_ms` histogram; surface it here
once the metrics pipeline reaches SigNoz.)"""
import json, uuid

HANDLE = "waf.handle_data_request"
FORWARD = "waf.forward_upstream"

def uid():
    return str(uuid.uuid4())

def tag(key, dtype="string", is_col=False):
    return {
        "key": key, "dataType": dtype, "type": "tag",
        "isColumn": is_col, "isJSON": False,
        "id": f"{key}--{dtype}--tag--{'true' if is_col else 'false'}",
    }

EMPTY_AGG = {"dataType": "", "id": "------false", "isColumn": False,
             "isJSON": False, "key": "", "type": ""}
DURATION = {"key": "durationNano", "dataType": "float64", "type": "tag",
            "isColumn": True, "isJSON": False,
            "id": "durationNano--float64--tag--true"}

def name_filter(span_name):
    return {"id": uid(), "key": tag("name", "string", True), "op": "=",
            "value": span_name}

def kv_filter(key, value):
    return {"id": uid(), "key": tag(key), "op": "=", "value": value}

def kv_filter_ne(key, value):
    return {"id": uid(), "key": tag(key), "op": "!=", "value": value}

def qdata(query_name, span_name, op="count", agg=None, group=None,
          extra_filters=None, legend="", order_desc_count=False, limit=None):
    items = [name_filter(span_name)] + (extra_filters or [])
    order = []
    if order_desc_count:
        order = [{"columnName": "#SIGNOZ_VALUE", "order": "desc"}]
    return {
        "aggregateAttribute": agg or EMPTY_AGG,
        "aggregateOperator": op,
        "dataSource": "traces",
        "disabled": False,
        "expression": query_name,
        "filters": {"items": items, "op": "AND"},
        "functions": [],
        "groupBy": group or [],
        "having": [],
        "legend": legend,
        "limit": limit,
        "orderBy": order,
        "queryName": query_name,
        "reduceTo": "sum",
        "stepInterval": 60,
        "spaceAggregation": "sum",
        "timeAggregation": "rate",
    }

def widget(title, desc, panel, qdatas, yunit="none", cols=None):
    return {
        "id": uid(),
        "title": title,
        "description": desc,
        "panelTypes": panel,
        "bucketCount": 30, "bucketWidth": 0, "columnUnits": cols or {},
        "fillSpans": False, "isStacked": panel == "graph",
        "mergeAllActiveQueries": False, "nullZeroValues": "zero",
        "opacity": "1", "softMax": None, "softMin": None,
        "stackedBarChart": False, "thresholds": [],
        "timePreferance": "GLOBAL_TIME", "yAxisUnit": yunit,
        "selectedLogFields": [], "selectedTracesFields": [],
        "query": {
            "builder": {"queryData": qdatas, "queryFormulas": []},
            "clickhouse_sql": [{"disabled": False, "legend": "", "name": "A", "query": ""}],
            "promql": [{"disabled": False, "legend": "", "name": "A", "query": ""}],
            "id": uid(), "queryType": "builder",
        },
    }

widgets = []

# --- Value row: Total / Blocked / Challenged (last window) ---
widgets.append(widget(
    "Total requests", "All WAF decisions (waf.handle_data_request) in the window.",
    "value", [qdata("A", HANDLE, legend="total")]))
widgets.append(widget(
    "Blocked", "Requests the WAF blocked (action=block).", "value",
    [qdata("A", HANDLE, extra_filters=[kv_filter("action", "block")], legend="blocked")]))
widgets.append(widget(
    "Challenged", "Requests sent a challenge (action=challenge).", "value",
    [qdata("A", HANDLE, extra_filters=[kv_filter("action", "challenge")], legend="challenged")]))

# --- Request rate by action (time series) ---
widgets.append(widget(
    "Request rate by action",
    "WAF decisions per interval, split by action (allow / block / challenge / circuit_breaker / risk_reset).",
    "graph", [qdata("A", HANDLE, group=[tag("action")], legend="{{action}}")]))

# --- Request latency end-to-end (handle_data_request span; incl. upstream) ---
widgets.append(widget(
    "Request latency (end-to-end · incl. upstream)",
    "Full per-request span duration (waf.handle_data_request) — this WRAPS the "
    "upstream forward, so for allowed requests it's dominated by upstream RTT, "
    "not WAF decision cost. For the WAF's own cost see the next panel.",
    "graph", [
        qdata("A", HANDLE, op="p50", agg=DURATION, legend="p50"),
        qdata("B", HANDLE, op="p95", agg=DURATION, legend="p95"),
        qdata("C", HANDLE, op="p99", agg=DURATION, legend="p99"),
    ], yunit="ns"))

# --- WAF decision latency (blocked / challenged — never forward upstream) ---
widgets.append(widget(
    "WAF decision latency (excl. upstream)",
    "WAF's own decision cost: span duration of requests that did NOT forward "
    "upstream (action != allow — block/challenge/circuit_breaker), so the "
    "upstream RTT is excluded. This is the true sub-millisecond WAF overhead "
    "(matches the waf_overhead Prometheus stage).",
    "graph", [
        qdata("A", HANDLE, op="p50", agg=DURATION, legend="p50", extra_filters=[kv_filter_ne("action", "allow")]),
        qdata("B", HANDLE, op="p95", agg=DURATION, legend="p95", extra_filters=[kv_filter_ne("action", "allow")]),
        qdata("C", HANDLE, op="p99", agg=DURATION, legend="p99", extra_filters=[kv_filter_ne("action", "allow")]),
    ], yunit="ns"))

# --- Requests by tier (time series) ---
widgets.append(widget(
    "Requests by tier", "WAF decisions split by protection tier.",
    "graph", [qdata("A", HANDLE, group=[tag("tier")], legend="{{tier}}")]))

# --- Top targeted paths (table) ---
widgets.append(widget(
    "Top targeted paths", "Most-requested paths (by decision count).",
    "table", [qdata("A", HANDLE, group=[tag("path")], legend="{{path}}",
                    order_desc_count=True, limit=10)]))

# --- Top peers / client IPs (table) ---
widgets.append(widget(
    "Top clients (peer)", "Busiest client IPs seen by the data plane.",
    "table", [qdata("A", HANDLE, group=[tag("peer")], legend="{{peer}}",
                    order_desc_count=True, limit=10)]))

# --- Upstream forward outcome (time series) ---
widgets.append(widget(
    "Upstream forward outcome",
    "Outcome of upstream forwards (waf.forward_upstream), split by outcome.",
    "graph", [qdata("A", FORWARD, group=[tag("outcome")], legend="{{outcome}}")]))

# --- Upstream forward latency p95 (time series) ---
widgets.append(widget(
    "Upstream forward latency (p95)",
    "Upstream round-trip time (span duration of waf.forward_upstream), per upstream.",
    "graph", [qdata("A", FORWARD, op="p95", agg=DURATION,
                    group=[tag("upstream")], legend="{{upstream}}")], yunit="ns"))

# --- Layout (12-col grid) ---
layout = []
def place(i, x, y, w, h):
    layout.append({"i": widgets[i]["id"], "x": x, "y": y, "w": w, "h": h})

place(0, 0, 0, 4, 4)    # Total
place(1, 4, 0, 4, 4)    # Blocked
place(2, 8, 0, 4, 4)    # Challenged
place(3, 0, 4, 12, 6)   # Request rate by action
place(4, 0, 10, 6, 6)   # Request latency end-to-end
place(5, 6, 10, 6, 6)   # WAF decision latency (excl. upstream)
place(6, 0, 16, 6, 6)   # by tier
place(7, 6, 16, 6, 6)   # top paths
place(8, 0, 22, 6, 6)   # top clients
place(9, 6, 22, 6, 6)   # upstream outcome
place(10, 0, 28, 6, 6)  # upstream latency

dashboard = {
    "title": "Aegis-Gate — WAF Overview",
    "description": "WAF traffic, decisions, latency and upstream health from OTLP traces (service.name=aegis-gate). Generated by gen-waf-dashboard.py from real span attributes; edit panels freely in the UI.",
    "tags": ["aegis-gate", "waf", "traces"],
    "layout": layout,
    "widgets": widgets,
    "variables": {},
    "version": "v4",
}

print(json.dumps(dashboard, indent=2))
