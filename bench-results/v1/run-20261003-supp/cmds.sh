#!/usr/bin/env bash
# Supplementary runs after the main run (see BENCHMARK_REPORT_V1.md §Methodology).
cd "$(dirname "$0")/../../.."
O=bench-results/v1/run-20261003-supp
B=target/release/avrora-bench-v1
run(){ echo "== $*" >> $O/run.log; "$B" --out $O "$@" >> $O/run.log 2>&1; echo "== exit=$?" >> $O/run.log; }
run env
run --warmup 5 --measure 15 pg --connections --max-conns 1000
run --warmup 5 --measure 30 trigger --size 1024
run --warmup 5 --measure 30 --only 10P_1C channel --size 1024 --drain-timeout 1800
run csv
echo "== done" >> $O/run.log
