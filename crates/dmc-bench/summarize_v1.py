#!/usr/bin/env python3
"""Summarize Benchmark V1 results.jsonl into Markdown tables (stdout).

    python3 crates/dmc-bench/summarize_v1.py bench-results/v1/<run>/results.jsonl
"""
import json
import sys
from collections import defaultdict

recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]


def f(x, nd=1):
    if x is None:
        return "—"
    if isinstance(x, (int, float)):
        if abs(x) >= 1000:
            return f"{x:,.0f}"
        return f"{x:.{nd}f}"
    return str(x)


def us(x):
    if x is None:
        return "—"
    if x >= 1000:
        return f"{x/1000:.2f} ms"
    return f"{x:.1f} µs"


def lat(r, k="latency"):
    l = r.get(k) or {}
    return us(l.get("p50_us")), us(l.get("p95_us")), us(l.get("p99_us"))


def res(r, k="resources"):
    x = r.get(k) or {}
    return f(x.get("cpu_pct")), f(x.get("peak_rss_mb")), f(x.get("disk_write_mb_s"))


print("## Storage (closed loop)\n")
by = defaultdict(list)
for r in recs:
    if r.get("suite") == "storage" and "latency" in r and r.get("scenario") not in ("preload_sequential",):
        by[r["system"]].append(r)
for sysname, rows in by.items():
    print(f"\n### {sysname}\n")
    print("| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | err | CPU % | peak RSS MB | disk write MB/s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        p = r.get("params", {})
        print(f"| {p.get('size')} | {r['scenario']} | {p.get('workers')} | {f(r.get('ops_per_s'))} | {f(r.get('mb_per_s'),2)} | "
              + " | ".join(lat(r)) + f" | {r.get('errors')} | " + " | ".join(res(r)) + " |")

print("\n## Preload (sequential single-row writes)\n")
print("| system | size | rows | rows/s | MB/s |")
print("|---|---|---|---|---|")
for r in recs:
    if r.get("scenario") in ("preload_sequential", "preload_insert"):
        p = r.get("params", {})
        print(f"| {r['system']} | {p.get('size')} | {p.get('rows')} | {f(r.get('ops_per_s'))} | {f(r.get('mb_per_s'),2)} |")

for r in recs:
    if r.get("scenario") in ("write_scaling_vs_keys", "insert_degradation_1KB"):
        print(f"\n## {r['system']} {r['scenario']}\n")
        pts = r["points"]
        keys = list(pts[0].keys())
        print("| " + " | ".join(keys) + " |")
        print("|" + "---|" * len(keys))
        for pt in pts:
            print("| " + " | ".join(f(pt[k], 2) for k in keys) + " |")

print("\n## Stress: concurrency ramp\n")
print("| kind | workers | records/s | p50 | p95 | p99 | CPU % |")
print("|---|---|---|---|---|---|---|")
for r in recs:
    if r.get("suite") == "stress":
        print(f"| {r['scenario']} | {r['params']['workers']} | {f(r['ops_per_s'])} | " + " | ".join(lat(r)) + f" | {f(r['resources']['cpu_pct'])} |")

print("\n## SQL\n")
print("| system | size | scenario | workers | rows/s | p50 | p95 | p99 | err | server CPU % |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in recs:
    if r.get("suite") == "sql" and "latency" in r:
        p = r.get("params", {})
        print(f"| {r['system']} | {p.get('size')} | {r['scenario']} | {p.get('workers')} | {f(r.get('ops_per_s'))} | "
              + " | ".join(lat(r)) + f" | {r.get('errors')} | {res(r)[0]} |")
for r in recs:
    if r.get("scenario") in ("request_limit_probe", "persistent_concurrency_probe", "size_unsupported"):
        print(f"\n- `{r['scenario']}`: {json.dumps({k: v for k, v in r.items() if k not in ('suite', 'system')}, ensure_ascii=False)}")

print("\n## Channels\n")
print("| scenario | P | C | size | produce msg/s | produce MB/s | delivered msg/s (all C) | ack/s | prod p99 | e2e p50 | e2e p95 | e2e p99 | backlog@stop | drain s | produced | uniq recv | lost | dup | retried | dlq | order viol | CPU % | RSS MB |")
print("|" + "---|" * 23)
for r in recs:
    if r.get("suite") == "channel" and "correctness" in r:
        p, c = r["params"], r["correctness"]
        e = r["e2e_latency"]
        print(f"| {r['scenario']} | {p['producers']} | {p['consumers']} | {p['size']} | {f(r['produce_msgs_per_s'])} | {f(r['produce_mb_per_s'],3)} | "
              f"{f(r['delivered_msgs_per_s_all_consumers'])} | {f(r['ack_per_s'])} | {us(r['producer_latency'].get('p99_us'))} | "
              f"{us(e.get('p50_us'))} | {us(e.get('p95_us'))} | {us(e.get('p99_us'))} | {r['backlog_at_producer_stop']} | {f(r['drain_s'])} | "
              f"{c['produced']} | {c['received_unique']} | {c['lost_or_undelivered']} | {c['duplicated_non_retry']} | {c['retried']} | {c['dlq']} | "
              f"{c['sequence_order_violations'] + c['producer_order_violations']} | {f(r['resources']['cpu_pct'])} | {f(r['resources']['peak_rss_mb'])} |")
for r in recs:
    if r.get("scenario") in ("ramp_verdict", "MAX_STABLE", "backpressure_inflight_probe"):
        print(f"\n- `{r['scenario']}`: {json.dumps({k: v for k, v in r.items() if k not in ('suite', 'system')}, ensure_ascii=False)}")

print("\n## Triggers\n")
print("| scenario | writes/s | write p50 | write p95 | write p99 | trigger deliv/s | trig p50 | trig p99 | expected | received | lagged | lost | CPU % |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
for r in recs:
    if r.get("suite") == "trigger":
        t = r["trigger_correctness"]
        tl = r["trigger_delivery_latency"]
        print(f"| {r['scenario']} | {f(r['ops_per_s'])} | " + " | ".join(lat(r)) + f" | {f(r['trigger_deliveries_per_s'])} | {us(tl.get('p50_us'))} | {us(tl.get('p99_us'))} | "
              f"{t['expected_trigger_deliveries']} | {t['received']} | {t['lagged_dropped']} | {t['lost']} | {res(r)[0]} |")

print("\n## Connections\n")
print("| system | conns | connected | failed | setup p50 | setup p99 | req/s | errors/s | p50 | p95 | p99 | server CPU % | server RSS MB | client CPU % | stable |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
for r in recs:
    if r.get("suite") == "connections" and r.get("scenario") == "ramp_step":
        s = r["connection_setup_latency"]
        print(f"| {r['system']} | {r['params']['connections']} | {r['connected']} | {r['failed_connections']} | {us(s.get('p50_us'))} | {us(s.get('p99_us'))} | "
              f"{f(r['ops_per_s'])} | {f(r['errors_per_s'])} | " + " | ".join(lat(r)) + f" | {res(r)[0]} | {res(r)[1]} | {res(r, 'client_resources')[0]} | {r['stable']} |")
        if r.get("connect_failure_samples") or r.get("error_samples"):
            print(f"|  | ↳ samples | {r.get('connect_failure_samples')} {r.get('error_samples')} |" + " |" * 12)

print("\n## Security\n")
print("| system | scenario | size | ops/s | MB/s | p50 | p95 | p99 | err |")
print("|---|---|---|---|---|---|---|---|---|")
for r in recs:
    if r.get("suite") == "security":
        p = r.get("params", {})
        print(f"| {r['system']} | {r['scenario']} | {p.get('size', '')} | {f(r.get('ops_per_s'))} | {f(r.get('mb_per_s'),2)} | " + " | ".join(lat(r)) + f" | {r.get('errors')} |")

print("\n## Correctness\n")
for r in recs:
    if r.get("suite") == "correctness":
        d = {k: v for k, v in r.items() if k not in ("suite", "system", "cycle_reports")}
        print(f"- **{r['scenario']}** → {r.get('result')}: `{json.dumps(d, ensure_ascii=False)}`")
        if r.get("cycle_reports"):
            print(f"  - cycles: `{json.dumps(r['cycle_reports'])}`")

print("\n## PostgreSQL settings\n")
seen = set()
for r in recs:
    if r.get("scenario") == "settings" and r["system"] not in seen:
        seen.add(r["system"])
        print(f"- {r['system']}: `{json.dumps(r['settings'])}`")
