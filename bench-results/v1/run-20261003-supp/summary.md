## Storage (closed loop)


## Preload (sequential single-row writes)

| system | size | rows | rows/s | MB/s |
|---|---|---|---|---|

## Stress: concurrency ramp

| kind | workers | records/s | p50 | p95 | p99 | CPU % |
|---|---|---|---|---|---|---|

## SQL

| system | size | scenario | workers | rows/s | p50 | p95 | p99 | err | server CPU % |
|---|---|---|---|---|---|---|---|---|---|

## Channels

| scenario | P | C | size | produce msg/s | produce MB/s | delivered msg/s (all C) | ack/s | prod p99 | e2e p50 | e2e p95 | e2e p99 | backlog@stop | drain s | produced | uniq recv | lost | dup | retried | dlq | order viol | CPU % | RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 10P_1C | 10 | 1 | 1024 | 70.8 | 0.070 | 15.2 | 15.2 | 194.16 ms | 103208.73 ms | 135552.42 ms | 137764.90 ms | 2430 | 138.1 | 2558 | 2558 | 0 | 0 | 0 | 0 | 0 | 66.0 | 381.5 |

## Triggers

| scenario | writes/s | write p50 | write p95 | write p99 | trigger deliv/s | trig p50 | trig p99 | expected | received | lagged | lost | CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0_triggers_1_writers | 82.3 | 12.03 ms | 14.00 ms | 14.90 ms | 0.0 | — | — | 0 | 0 | 0 | 0 | 35.1 |
| 1_triggers_1_writers | 81.1 | 12.08 ms | 14.01 ms | 14.13 ms | 83.4 | 763.06 ms | 1586.00 ms | 2918 | 2918 | 0 | 0 | 35.5 |
| 5_triggers_1_writers | 81.8 | 12.06 ms | 14.00 ms | 14.19 ms | 421.0 | 12.11 ms | 26.99 ms | 14735 | 14735 | 0 | 0 | 35.7 |
| 0_triggers_8_writers | 80.5 | 99.89 ms | 107.01 ms | 114.93 ms | 0.0 | — | — | 0 | 0 | 0 | 0 | 36.1 |
| 1_triggers_8_writers | 80.4 | 99.86 ms | 107.90 ms | 111.03 ms | 83.3 | 98.90 ms | 111.02 ms | 2917 | 2917 | 0 | 0 | 35.5 |
| 5_triggers_8_writers | 80.4 | 99.99 ms | 106.07 ms | 111.93 ms | 412.0 | 98.97 ms | 111.07 ms | 14420 | 14420 | 0 | 0 | 37.1 |

## Connections

| system | conns | connected | failed | setup p50 | setup p99 | req/s | errors/s | p50 | p95 | p99 | server CPU % | server RSS MB | client CPU % | stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| postgres_default_tcp | 10 | 10 | 0 | 8.48 ms | 14.77 ms | 163,783 | 0.0 | 58.9 µs | 99.3 µs | 126.9 µs | 334.5 | 178.2 | 235.0 | True |
| postgres_default_tcp | 50 | 50 | 0 | 13.21 ms | 21.25 ms | 204,004 | 0.0 | 226.8 µs | 428.2 µs | 680.5 µs | 436.9 | 580.0 | 312.8 | True |
| postgres_default_tcp | 100 | 100 | 0 | 24.70 ms | 66.16 ms | 202,428 | 0.0 | 463.7 µs | 903.0 µs | 1.40 ms | 439.4 | 1,096 | 296.2 | True |
| postgres_default_tcp | 250 | 250 | 0 | 121.83 ms | 212.81 ms | 190,223 | 0.0 | 1.14 ms | 2.76 ms | 4.38 ms | 494.0 | 2,628 | 246.6 | True |
| postgres_default_tcp | 500 | 500 | 0 | 78.44 ms | 280.40 ms | 171,614 | 0.0 | 2.25 ms | 7.24 ms | 13.28 ms | 530.1 | 5,202 | 214.5 | True |
| postgres_default_tcp | 1000 | 1000 | 0 | 85.37 ms | 626.12 ms | 160,225 | 0.0 | 4.46 ms | 18.24 ms | 34.16 ms | 529.4 | 10,076 | 200.7 | True |

## Security

| system | scenario | size | ops/s | MB/s | p50 | p95 | p99 | err |
|---|---|---|---|---|---|---|---|---|

## Correctness


## PostgreSQL settings

