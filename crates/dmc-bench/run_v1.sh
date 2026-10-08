#!/usr/bin/env bash
# Avrora Benchmark V1 — full reproducible run.
#
#   crates/dmc-bench/run_v1.sh [OUT_DIR]
#
# Builds release binaries, then runs every suite sequentially (never in parallel, so suites
# do not compete for CPU/disk). Results: OUT_DIR/{env.json,results.jsonl,results.csv,run.log}.
# Requires: PostgreSQL binaries (initdb, postgres, pg_ctl) on PATH; port 55432 free.
set -u
cd "$(dirname "$0")/../.."
OUT="${1:-bench-results/v1/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$OUT"
LOG="$OUT/run.log"
B=target/release/avrora-bench-v1

echo "== build" | tee -a "$LOG"
cargo build --release -p dmc-bench --bin avrora-bench-v1 -p dmc-cli --bin dmc >>"$LOG" 2>&1 || { echo "build failed" | tee -a "$LOG"; exit 1; }

# Matrix timing: warmup 5 s + measurement 30 s per closed-loop scenario.
W=5; M=30
step() {
  local name="$1"; shift
  local t0=$(date +%s)
  echo "== $name: $*" | tee -a "$LOG"
  "$B" --out "$OUT" "$@" >>"$LOG" 2>&1
  local rc=$?
  echo "== $name exit=$rc elapsed=$(( $(date +%s) - t0 ))s" | tee -a "$LOG"
}

step env            env
step correctness    --warmup $W --measure $M correctness --crash-cycles 5
step security       --warmup $W --measure 15 security
step storage        --warmup $W --measure $M storage
step pg_default     --warmup $W --measure $M pg
step pg_writethru   --warmup $W --measure $M pg --wal-sync-method fsync_writethrough
step sqlcore        --warmup $W --measure $M --sizes 100,1024,10240,102400,1048576 sql
step channel_1KB    --warmup $W --measure $M channel --size 1024 --ramp
step channel_100KB  --warmup $W --measure $M channel --size 102400
step trigger        --warmup $W --measure $M trigger --size 1024
step conn_avrora    --warmup $W --measure 15 connections --steps 10,50,100,250,500,1000,2500,5000,10000,15000
step conn_pg        --warmup $W --measure 15 pg --connections --max-conns 1000
step csv            csv
echo "== done: $OUT" | tee -a "$LOG"
