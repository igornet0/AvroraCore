## Storage (closed loop)


### avrora_kv_inproc

| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | err | CPU % | peak RSS MB | disk write MB/s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 100B | write | 1 | 41.1 | 0.00 | 24.00 ms | 27.04 ms | 32.97 ms | 0 | 67.6 | 22.3 | 0.9 |
| 100B | read | 1 | 584,370 | 55.73 | 1.5 µs | 2.0 µs | 3.1 µs | 0 | 99.3 | 53.3 | 0.0 |
| 100B | random_read | 1 | 544,077 | 51.89 | 1.7 µs | 2.2 µs | 3.0 µs | 0 | 100.2 | 101.6 | 0.0 |
| 100B | random_rw | 1 | 79.0 | 0.01 | 32.5 µs | 27.96 ms | 40.39 ms | 0 | 67.8 | 106.1 | 0.8 |
| 100B | batch_write | 1 | 40.0 | 0.00 | 2573.13 ms | 2620.09 ms | 2627.98 ms | 0 | 69.4 | 26.3 | 0.8 |
| 100B | batch_read | 1 | 655,368 | 62.50 | 150.0 µs | 170.5 µs | 195.5 µs | 0 | 100.8 | 28.2 | 0.0 |
| 100B | concurrent_read | 16 | 439,147 | 41.88 | 35.6 µs | 41.8 µs | 51.7 µs | 0 | 121.3 | 103.0 | 0.0 |
| 100B | concurrent_write | 16 | 36.4 | 0.00 | 442.81 ms | 460.98 ms | 465.96 ms | 0 | 72.0 | 184.3 | 0.8 |
| 100B | mixed_80r_20w | 16 | 174.9 | 0.02 | 86.80 ms | 173.00 ms | 204.94 ms | 0 | 72.7 | 48.4 | 0.7 |
| 1KB | write | 1 | 42.0 | 0.04 | 23.96 ms | 25.93 ms | 29.11 ms | 0 | 66.5 | 34.7 | 1.0 |
| 1KB | read | 1 | 601,350 | 587.26 | 1.5 µs | 2.0 µs | 2.5 µs | 0 | 99.6 | 40.4 | 0.0 |
| 1KB | random_read | 1 | 550,358 | 537.46 | 1.7 µs | 2.2 µs | 2.8 µs | 0 | 100.6 | 45.0 | 0.0 |
| 1KB | random_rw | 1 | 80.0 | 0.08 | 21.94 ms | 26.00 ms | 26.64 ms | 0 | 68.3 | 44.6 | 0.9 |
| 1KB | batch_write | 1 | 36.7 | 0.04 | 2568.09 ms | 2704.98 ms | 2704.98 ms | 0 | 69.4 | 46.0 | 0.9 |
| 1KB | batch_read | 1 | 621,181 | 606.62 | 158.6 µs | 179.7 µs | 203.8 µs | 0 | 100.9 | 45.7 | 0.0 |
| 1KB | concurrent_read | 16 | 422,694 | 412.79 | 36.9 µs | 44.0 µs | 58.8 µs | 0 | 120.6 | 47.0 | 0.0 |
| 1KB | concurrent_write | 16 | 34.2 | 0.03 | 454.15 ms | 564.83 ms | 700.24 ms | 0 | 71.2 | 60.1 | 0.8 |
| 1KB | mixed_80r_20w | 16 | 162.6 | 0.16 | 89.02 ms | 193.96 ms | 268.12 ms | 0 | 71.3 | 41.7 | 0.8 |
| 10KB | write | 1 | 42.1 | 0.41 | 23.92 ms | 25.88 ms | 27.47 ms | 0 | 67.7 | 74.0 | 1.7 |
| 10KB | read | 1 | 479,093 | 4,679 | 2.0 µs | 2.5 µs | 3.2 µs | 0 | 98.9 | 149.6 | 0.0 |
| 10KB | random_read | 1 | 419,484 | 4,097 | 2.2 µs | 2.9 µs | 3.7 µs | 0 | 100.4 | 134.1 | 0.0 |
| 10KB | random_rw | 1 | 80.4 | 0.79 | 31.7 µs | 26.93 ms | 29.06 ms | 0 | 69.2 | 142.4 | 1.6 |
| 10KB | batch_write | 1 | 36.7 | 0.36 | 2559.85 ms | 2713.02 ms | 2713.02 ms | 0 | 69.7 | 83.1 | 1.5 |
| 10KB | batch_read | 1 | 507,854 | 4,960 | 193.2 µs | 222.0 µs | 245.0 µs | 0 | 100.7 | 153.9 | 0.0 |
| 10KB | concurrent_read | 16 | 382,161 | 3,732 | 41.6 µs | 44.6 µs | 46.5 µs | 0 | 118.0 | 154.2 | 0.0 |
| 10KB | concurrent_write | 16 | 36.0 | 0.35 | 446.04 ms | 465.07 ms | 505.02 ms | 0 | 72.0 | 160.0 | 1.4 |
| 10KB | mixed_80r_20w | 16 | 179.0 | 1.75 | 85.14 ms | 172.87 ms | 224.92 ms | 0 | 73.4 | 159.4 | 1.4 |
| 100KB | write | 1 | 63.4 | 6.19 | 15.84 ms | 18.03 ms | 21.53 ms | 0 | 51.4 | 348.3 | 13.2 |
| 100KB | read | 1 | 229,867 | 22,448 | 4.1 µs | 5.4 µs | 6.9 µs | 0 | 100.0 | 380.2 | 0.0 |
| 100KB | random_read | 1 | 246,881 | 24,110 | 3.9 µs | 4.6 µs | 5.3 µs | 0 | 100.2 | 371.5 | 0.0 |
| 100KB | random_rw | 1 | 116.7 | 11.40 | 18.5 µs | 18.13 ms | 19.72 ms | 0 | 54.6 | 380.4 | 12.0 |
| 100KB | batch_write | 1 | 56.7 | 5.53 | 1862.01 ms | 2000.65 ms | 2094.11 ms | 0 | 58.7 | 394.6 | 11.2 |
| 100KB | batch_read | 1 | 230,601 | 22,520 | 410.8 µs | 507.0 µs | 516.6 µs | 0 | 99.8 | 412.4 | 0.0 |
| 100KB | concurrent_read | 16 | 191,105 | 18,663 | 81.0 µs | 100.6 µs | 118.6 µs | 0 | 110.3 | 361.3 | 0.0 |
| 100KB | concurrent_write | 16 | 45.9 | 4.49 | 345.77 ms | 367.04 ms | 568.04 ms | 0 | 63.7 | 425.9 | 9.6 |
| 100KB | mixed_80r_20w | 16 | 228.1 | 22.27 | 67.16 ms | 135.94 ms | 162.56 ms | 0 | 66.2 | 353.1 | 9.2 |
| 1MB | write | 1 | 27.9 | 27.89 | 35.04 ms | 40.51 ms | 51.03 ms | 0 | 74.6 | 1,088 | 54.0 |
| 1MB | read | 1 | 47,006 | 47,006 | 19.8 µs | 28.8 µs | 41.5 µs | 0 | 99.6 | 909.4 | 0.0 |
| 1MB | random_read | 1 | 45,866 | 45,866 | 20.4 µs | 30.3 µs | 41.1 µs | 0 | 99.7 | 807.3 | 0.0 |
| 1MB | random_rw | 1 | 55.2 | 55.22 | 32.85 ms | 36.78 ms | 45.86 ms | 0 | 75.3 | 761.8 | 53.7 |
| 1MB | batch_write | 1 | 24.6 | 24.58 | 3735.16 ms | 3805.86 ms | 3805.86 ms | 0 | 74.9 | 979.4 | 52.3 |
| 1MB | batch_read | 1 | 42,292 | 42,292 | 2.28 ms | 2.55 ms | 2.55 ms | 0 | 99.8 | 681.8 | 0.0 |
| 1MB | concurrent_read | 16 | 47,339 | 47,339 | 320.2 µs | 420.8 µs | 593.2 µs | 0 | 101.7 | 619.0 | 0.0 |
| 1MB | concurrent_write | 16 | 26.4 | 26.39 | 603.79 ms | 641.81 ms | 677.48 ms | 0 | 76.0 | 893.8 | 51.1 |
| 1MB | mixed_80r_20w | 16 | 132.5 | 132.51 | 113.13 ms | 251.77 ms | 297.84 ms | 0 | 76.6 | 882.0 | 50.3 |

### postgres_default

| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | err | CPU % | peak RSS MB | disk write MB/s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 100B | write | 1 | 33,307 | 3.18 | 27.8 µs | 36.8 µs | 51.2 µs | 0 | 45.8 | 361.9 | 546.7 |
| 100B | read | 1 | 80,995 | 7.72 | 11.8 µs | 16.7 µs | 28.3 µs | 0 | 63.1 | 465.4 | 0.5 |
| 100B | random_read | 1 | 79,400 | 7.57 | 12.0 µs | 16.0 µs | 25.8 µs | 0 | 64.6 | 333.4 | 0.0 |
| 100B | random_rw | 1 | 46,225 | 4.41 | 25.3 µs | 38.5 µs | 45.2 µs | 0 | 55.3 | 365.5 | 372.6 |
| 100B | batch_write | 1 | 376,548 | 35.91 | 230.6 µs | 387.6 µs | 528.1 µs | 0 | 57.2 | 397.2 | 248.6 |
| 100B | batch_read | 1 | 1,196,648 | 114.12 | 82.2 µs | 95.1 µs | 111.3 µs | 0 | 88.6 | 401.9 | 0.0 |
| 100B | concurrent_read | 16 | 285,245 | 27.20 | 47.0 µs | 108.8 µs | 185.8 µs | 0 | 399.4 | 512.6 | 16.7 |
| 100B | concurrent_write | 16 | 98,504 | 9.39 | 131.5 µs | 286.2 µs | 1.18 ms | 0 | 393.3 | 2,177 | 368.1 |
| 100B | mixed_80r_20w | 16 | 224,264 | 21.39 | 54.8 µs | 164.8 µs | 269.5 µs | 0 | 479.4 | 2,274 | 343.6 |
| 1KB | write | 1 | 31,547 | 30.81 | 29.5 µs | 37.2 µs | 48.1 µs | 0 | 45.6 | 388.6 | 574.1 |
| 1KB | read | 1 | 80,411 | 78.53 | 12.0 µs | 14.5 µs | 24.9 µs | 0 | 64.6 | 405.9 | 0.0 |
| 1KB | random_read | 1 | 79,367 | 77.51 | 12.1 µs | 14.8 µs | 25.2 µs | 0 | 65.0 | 413.3 | 0.0 |
| 1KB | random_rw | 1 | 47,096 | 45.99 | 27.0 µs | 35.0 µs | 42.8 µs | 0 | 54.5 | 447.2 | 381.6 |
| 1KB | batch_write | 1 | 144,777 | 141.38 | 598.0 µs | 852.2 µs | 1.42 ms | 0 | 44.7 | 452.7 | 445.3 |
| 1KB | batch_read | 1 | 956,934 | 934.51 | 108.0 µs | 121.4 µs | 133.5 µs | 0 | 87.7 | 426.2 | 30.1 |
| 1KB | concurrent_read | 16 | 318,227 | 310.77 | 46.4 µs | 92.6 µs | 126.8 µs | 0 | 425.5 | 664.5 | 29.4 |
| 1KB | concurrent_write | 16 | 56,789 | 55.46 | 222.4 µs | 579.2 µs | 1.32 ms | 0 | 222.3 | 2,314 | 327.4 |
| 1KB | mixed_80r_20w | 16 | 234,031 | 228.55 | 53.1 µs | 159.5 µs | 239.3 µs | 0 | 467.8 | 2,343 | 334.3 |
| 10KB | write | 1 | 7,715 | 75.35 | 109.5 µs | 216.4 µs | 336.8 µs | 0 | 63.5 | 480.9 | 345.3 |
| 10KB | read | 1 | 43,407 | 423.90 | 22.4 µs | 26.2 µs | 36.5 µs | 0 | 65.9 | 488.3 | 0.0 |
| 10KB | random_read | 1 | 41,779 | 407.99 | 23.4 µs | 27.0 µs | 37.0 µs | 0 | 66.4 | 488.3 | 0.0 |
| 10KB | random_rw | 1 | 9,415 | 91.94 | 106.5 µs | 262.8 µs | 380.8 µs | 0 | 50.8 | 505.0 | 209.0 |
| 10KB | batch_write | 1 | 11,053 | 107.94 | 8.48 ms | 9.41 ms | 10.86 ms | 0 | 71.1 | 533.1 | 230.2 |
| 10KB | batch_read | 1 | 101,385 | 990.09 | 975.6 µs | 1.06 ms | 1.16 ms | 0 | 85.3 | 534.4 | 0.1 |
| 10KB | concurrent_read | 16 | 152,620 | 1,490 | 92.0 µs | 201.3 µs | 384.0 µs | 0 | 458.8 | 2,496 | 0.0 |
| 10KB | concurrent_write | 16 | 23,700 | 231.44 | 534.5 µs | 1.36 ms | 2.12 ms | 0 | 356.3 | 2,615 | 705.8 |
| 10KB | mixed_80r_20w | 16 | 61,322 | 598.85 | 96.1 µs | 721.1 µs | 1.38 ms | 0 | 396.5 | 2,635 | 574.4 |
| 100KB | write | 1 | 875.0 | 85.45 | 1.01 ms | 1.32 ms | 2.10 ms | 0 | 74.1 | 492.9 | 276.5 |
| 100KB | read | 1 | 8,932 | 872.29 | 111.3 µs | 126.3 µs | 133.8 µs | 0 | 66.5 | 494.9 | 0.0 |
| 100KB | random_read | 1 | 9,118 | 890.40 | 108.4 µs | 127.9 µs | 155.2 µs | 0 | 65.6 | 494.9 | 0.0 |
| 100KB | random_rw | 1 | 1,496 | 146.14 | 399.2 µs | 1.35 ms | 1.73 ms | 0 | 71.1 | 509.7 | 283.9 |
| 100KB | batch_write | 1 | 626.7 | 61.20 | 157.35 ms | 165.26 ms | 191.32 ms | 0 | 54.4 | 563.8 | 192.9 |
| 100KB | batch_read | 1 | 9,278 | 906.04 | 10.53 ms | 11.56 ms | 11.97 ms | 0 | 66.5 | 564.5 | 0.0 |
| 100KB | concurrent_read | 16 | 31,655 | 3,091 | 467.2 µs | 840.3 µs | 1.44 ms | 0 | 444.2 | 2,535 | 0.0 |
| 100KB | concurrent_write | 16 | 3,354 | 327.50 | 3.03 ms | 9.12 ms | 21.96 ms | 0 | 460.9 | 2,653 | 917.2 |
| 100KB | mixed_80r_20w | 16 | 8,396 | 819.90 | 720.5 µs | 3.62 ms | 7.05 ms | 0 | 496.2 | 2,633 | 887.8 |
| 1MB | write | 1 | 92.1 | 92.07 | 10.08 ms | 11.65 ms | 14.18 ms | 0 | 76.3 | 502.6 | 275.8 |
| 1MB | read | 1 | 972.0 | 972.04 | 1.03 ms | 1.13 ms | 1.19 ms | 0 | 64.5 | 504.8 | 0.0 |
| 1MB | random_read | 1 | 1,030 | 1,030 | 972.8 µs | 1.11 ms | 1.13 ms | 0 | 62.0 | 504.8 | 0.0 |
| 1MB | random_rw | 1 | 174.6 | 174.62 | 1.61 ms | 11.44 ms | 11.83 ms | 0 | 76.4 | 530.5 | 238.9 |
| 1MB | batch_write | 1 | 27.6 | 27.57 | 2634.58 ms | 7697.13 ms | 7697.13 ms | 0 | 31.6 | 928.1 | 112.6 |
| 1MB | batch_read | 1 | 1,250 | 1,250 | 73.25 ms | 74.69 ms | 74.69 ms | 0 | 72.2 | 940.1 | 2.1 |
| 1MB | concurrent_read | 16 | 3,094 | 3,094 | 5.12 ms | 6.32 ms | 7.21 ms | 0 | 412.2 | 2,602 | 1.4 |
| 1MB | concurrent_write | 16 | 230.2 | 230.16 | 45.13 ms | 189.55 ms | 385.26 ms | 0 | 322.4 | 2,725 | 706.5 |
| 1MB | mixed_80r_20w | 16 | 417.2 | 417.19 | 5.63 ms | 366.03 ms | 420.14 ms | 0 | 141.7 | 2,760 | 262.0 |

### postgres_fsync_writethrough

| size | scenario | workers | records/s | MB/s | p50 | p95 | p99 | err | CPU % | peak RSS MB | disk write MB/s |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 100B | write | 1 | 255.2 | 0.02 | 3.99 ms | 4.12 ms | 4.71 ms | 0 | 5.0 | 187.5 | 4.0 |
| 100B | read | 1 | 82,344 | 7.85 | 11.7 µs | 14.0 µs | 24.6 µs | 0 | 63.0 | 189.9 | 0.0 |
| 100B | random_read | 1 | 82,400 | 7.86 | 11.8 µs | 13.9 µs | 24.4 µs | 0 | 63.3 | 190.0 | 0.0 |
| 100B | random_rw | 1 | 542.7 | 0.05 | 2.74 ms | 4.02 ms | 4.39 ms | 0 | 6.4 | 191.8 | 4.3 |
| 100B | batch_write | 1 | 23,553 | 2.25 | 4.02 ms | 5.04 ms | 5.97 ms | 0 | 14.7 | 324.4 | 17.5 |
| 100B | batch_read | 1 | 1,603,291 | 152.90 | 62.2 µs | 68.9 µs | 76.8 µs | 0 | 87.2 | 343.0 | 0.0 |
| 100B | concurrent_read | 16 | 323,674 | 30.87 | 45.0 µs | 93.3 µs | 132.8 µs | 0 | 424.1 | 558.8 | 0.0 |
| 100B | concurrent_write | 16 | 2,202 | 0.21 | 7.09 ms | 8.17 ms | 9.48 ms | 0 | 30.5 | 667.3 | 5.3 |
| 100B | mixed_80r_20w | 16 | 11,312 | 1.08 | 76.8 µs | 7.11 ms | 7.97 ms | 0 | 56.9 | 810.0 | 5.9 |
| 1KB | write | 1 | 258.8 | 0.25 | 3.98 ms | 4.08 ms | 4.33 ms | 0 | 5.4 | 224.6 | 4.6 |
| 1KB | read | 1 | 79,939 | 78.07 | 12.1 µs | 14.6 µs | 25.0 µs | 0 | 63.6 | 221.9 | 0.0 |
| 1KB | random_read | 1 | 80,082 | 78.20 | 12.0 µs | 14.5 µs | 24.9 µs | 0 | 64.1 | 222.0 | 0.0 |
| 1KB | random_rw | 1 | 497.9 | 0.49 | 500.2 µs | 4.05 ms | 4.68 ms | 0 | 6.4 | 260.8 | 4.5 |
| 1KB | batch_write | 1 | 17,871 | 17.45 | 5.04 ms | 6.85 ms | 12.62 ms | 0 | 19.2 | 398.2 | 45.8 |
| 1KB | batch_read | 1 | 933,643 | 911.76 | 108.2 µs | 120.9 µs | 131.8 µs | 0 | 84.0 | 372.0 | 0.9 |
| 1KB | concurrent_read | 16 | 316,234 | 308.82 | 45.3 µs | 99.6 µs | 140.5 µs | 0 | 429.1 | 636.1 | 0.0 |
| 1KB | concurrent_write | 16 | 2,224 | 2.17 | 6.95 ms | 8.13 ms | 14.11 ms | 0 | 31.8 | 1,198 | 9.8 |
| 1KB | mixed_80r_20w | 16 | 11,985 | 11.70 | 83.8 µs | 6.77 ms | 7.70 ms | 0 | 61.0 | 1,459 | 6.0 |
| 10KB | write | 1 | 241.5 | 2.36 | 4.01 ms | 5.03 ms | 6.10 ms | 0 | 11.3 | 412.1 | 8.9 |
| 10KB | read | 1 | 41,882 | 409.01 | 23.3 µs | 29.5 µs | 39.0 µs | 0 | 62.2 | 426.3 | 0.0 |
| 10KB | random_read | 1 | 39,617 | 386.88 | 24.7 µs | 31.0 µs | 40.1 µs | 0 | 65.1 | 426.3 | 0.0 |
| 10KB | random_rw | 1 | 433.9 | 4.24 | 2.10 ms | 5.11 ms | 9.03 ms | 0 | 10.6 | 434.0 | 8.9 |
| 10KB | batch_write | 1 | 3,876 | 37.85 | 19.49 ms | 58.64 ms | 107.83 ms | 0 | 31.6 | 394.1 | 104.4 |
| 10KB | batch_read | 1 | 63,272 | 617.89 | 1.22 ms | 3.35 ms | 5.88 ms | 0 | 72.5 | 310.9 | 0.1 |
| 10KB | concurrent_read | 16 | 143,486 | 1,401 | 98.9 µs | 193.8 µs | 349.5 µs | 0 | 412.6 | 2,276 | 0.0 |
| 10KB | concurrent_write | 16 | 956.8 | 9.34 | 8.49 ms | 67.07 ms | 139.08 ms | 0 | 42.4 | 2,400 | 18.4 |
| 10KB | mixed_80r_20w | 16 | 3,383 | 33.03 | 119.2 µs | 15.36 ms | 78.98 ms | 0 | 45.1 | 2,329 | 47.4 |
| 100KB | write | 1 | 165.4 | 16.16 | 5.97 ms | 6.99 ms | 11.34 ms | 0 | 25.3 | 544.9 | 37.3 |
| 100KB | read | 1 | 8,036 | 784.78 | 115.9 µs | 131.7 µs | 292.4 µs | 0 | 65.4 | 546.7 | 0.0 |
| 100KB | random_read | 1 | 8,932 | 872.28 | 112.6 µs | 129.5 µs | 138.4 µs | 0 | 66.5 | 595.7 | 0.1 |
| 100KB | random_rw | 1 | 332.2 | 32.44 | 1.10 ms | 6.80 ms | 9.41 ms | 0 | 26.2 | 669.0 | 51.1 |
| 100KB | batch_write | 1 | 711.1 | 69.44 | 126.16 ms | 139.07 ms | 240.73 ms | 0 | 58.0 | 720.3 | 188.3 |
| 100KB | batch_read | 1 | 9,132 | 891.77 | 10.81 ms | 11.01 ms | 11.03 ms | 0 | 58.9 | 595.0 | 0.0 |
| 100KB | concurrent_read | 16 | 32,628 | 3,186 | 424.2 µs | 924.2 µs | 1.21 ms | 0 | 456.4 | 2,563 | 0.0 |
| 100KB | concurrent_write | 16 | 682.7 | 66.67 | 15.07 ms | 46.16 ms | 96.87 ms | 0 | 130.5 | 2,652 | 186.5 |
| 100KB | mixed_80r_20w | 16 | 4,016 | 392.23 | 547.5 µs | 18.41 ms | 31.65 ms | 0 | 151.5 | 2,696 | 249.0 |
| 1MB | write | 1 | 59.1 | 59.14 | 13.98 ms | 37.97 ms | 46.02 ms | 0 | 50.3 | 509.4 | 148.5 |
| 1MB | read | 1 | 724.5 | 724.49 | 1.12 ms | 3.32 ms | 5.74 ms | 0 | 61.4 | 511.2 | 0.0 |
| 1MB | random_read | 1 | 992.2 | 992.23 | 1.01 ms | 1.13 ms | 1.15 ms | 0 | 61.9 | 511.2 | 0.0 |
| 1MB | random_rw | 1 | 117.5 | 117.49 | 1.50 ms | 18.28 ms | 29.97 ms | 0 | 54.2 | 535.7 | 227.7 |
| 1MB | batch_write | 1 | 53.7 | 53.67 | 1713.22 ms | 2106.66 ms | 2106.66 ms | 0 | 55.8 | 935.3 | 112.9 |
| 1MB | batch_read | 1 | 1,101 | 1,101 | 88.06 ms | 96.15 ms | 96.15 ms | 0 | 65.7 | 949.5 | 0.7 |
| 1MB | concurrent_read | 16 | 3,242 | 3,242 | 4.55 ms | 8.15 ms | 9.82 ms | 0 | 440.2 | 2,992 | 1.5 |
| 1MB | concurrent_write | 16 | 105.4 | 105.41 | 126.08 ms | 356.03 ms | 1004.19 ms | 0 | 172.0 | 3,158 | 320.5 |
| 1MB | mixed_80r_20w | 16 | 675.8 | 675.82 | 7.39 ms | 107.71 ms | 137.51 ms | 0 | 213.4 | 2,765 | 333.9 |

## Preload (sequential single-row writes)

| system | size | rows | rows/s | MB/s |
|---|---|---|---|---|
| avrora_kv_inproc | 100B | 10000 | 60.9 | 0.01 |
| avrora_kv_inproc | 1KB | 10000 | 63.9 | 0.06 |
| avrora_kv_inproc | 10KB | 10000 | 64.2 | 0.63 |
| avrora_kv_inproc | 100KB | 2621 | 77.3 | 7.55 |
| avrora_kv_inproc | 1MB | 256 | 29.0 | 28.97 |
| postgres_default | 100B | 10000 | 28,852 | 2.75 |
| postgres_default | 1KB | 10000 | 26,666 | 26.04 |
| postgres_default | 10KB | 10000 | 8,153 | 79.62 |
| postgres_default | 100KB | 2621 | 942.5 | 92.04 |
| postgres_default | 1MB | 256 | 94.8 | 94.83 |
| postgres_fsync_writethrough | 100B | 10000 | 249.2 | 0.02 |
| postgres_fsync_writethrough | 1KB | 10000 | 252.3 | 0.25 |
| postgres_fsync_writethrough | 10KB | 10000 | 238.2 | 2.33 |
| postgres_fsync_writethrough | 100KB | 2621 | 172.6 | 16.86 |
| postgres_fsync_writethrough | 1MB | 256 | 63.3 | 63.33 |
| avrora_sqlcore_ipc | 100B | 2000 | 18.2 | — |
| avrora_sqlcore_ipc | 1KB | 2000 | 17.4 | — |
| avrora_sqlcore_ipc | 10KB | 1638 | 15.2 | — |
| avrora_sqlcore_ipc | 100KB | 163 | 20.3 | — |
| avrora_sqlcore_ipc | 1MB | 50 | 585.7 | — |

## avrora_kv_inproc write_scaling_vs_keys

| avg_latency_ms | cpu_pct | disk_write_mb_s | keys_before | rss_mb | writes_per_s |
|---|---|---|---|---|---|
| 10.37 | 22.26 | 2.10 | 0.00 | 13.88 | 96.46 |
| 12.14 | 31.28 | 1.86 | 1,000 | 15.44 | 82.38 |
| 12.66 | 37.36 | 1.78 | 2,000 | 17.69 | 79.01 |
| 13.87 | 42.52 | 1.63 | 3,000 | 20.89 | 72.07 |
| 14.70 | 46.35 | 1.54 | 4,000 | 24.25 | 68.02 |
| 15.87 | 50.31 | 1.42 | 5,000 | 26.05 | 63.02 |
| 17.01 | 54.02 | 1.33 | 6,000 | 27.55 | 58.77 |
| 18.84 | 57.36 | 1.20 | 7,000 | 31.89 | 53.07 |
| 20.27 | 60.51 | 1.11 | 8,000 | 31.95 | 49.33 |
| 21.73 | 63.15 | 1.04 | 9,000 | 32.56 | 46.02 |
| 23.23 | 64.83 | 0.97 | 10,000 | 32.80 | 43.05 |
| 24.61 | 67.05 | 0.92 | 11,000 | 31.17 | 40.64 |
| 25.84 | 69.07 | 0.87 | 12,000 | 32.14 | 38.71 |
| 27.50 | 70.47 | 0.82 | 13,000 | 31.38 | 36.37 |
| 28.81 | 72.05 | 0.78 | 14,000 | 38.72 | 34.71 |
| 31.53 | 73.14 | 0.72 | 15,000 | 40.33 | 31.72 |
| 34.22 | 73.08 | 0.66 | 16,000 | 36.28 | 29.22 |
| 34.14 | 73.76 | 0.66 | 17,000 | 34.88 | 29.29 |
| 37.05 | 75.45 | 0.61 | 18,000 | 34.59 | 26.99 |

## avrora_sqlcore_ipc insert_degradation_1KB

| avg_latency_ms | disk_write_mb_s | inserts_per_s | rows_before | server_cpu_pct | state_events_mb |
|---|---|---|---|---|---|
| 42.36 | 10.86 | 23.61 | 0.00 | 30.62 | 0.78 |
| 50.91 | 25.81 | 19.64 | 500.00 | 38.60 | 1.56 |
| 58.29 | 37.22 | 17.16 | 1,000 | 46.38 | 2.34 |
| 65.83 | 45.95 | 15.19 | 1,500 | 52.86 | 3.12 |
| 76.34 | 50.83 | 13.10 | 2,000 | 57.76 | 3.90 |
| 86.88 | 54.51 | 11.51 | 2,500 | 61.43 | 4.68 |
| 96.52 | 57.94 | 10.36 | 3,000 | 65.33 | 5.46 |
| 107.11 | 60.20 | 9.34 | 3,500 | 67.96 | 6.24 |

## Stress: concurrency ramp

| kind | workers | records/s | p50 | p95 | p99 | CPU % |
|---|---|---|---|---|---|---|
| concurrency_ramp_write | 1 | 75.7 | 13.02 ms | 15.08 ms | 17.02 ms | 40.0 |
| concurrency_ramp_write | 2 | 69.9 | 28.11 ms | 31.89 ms | 35.04 ms | 44.4 |
| concurrency_ramp_write | 4 | 66.1 | 60.12 ms | 65.00 ms | 67.02 ms | 46.2 |
| concurrency_ramp_write | 8 | 64.1 | 124.05 ms | 135.15 ms | 141.98 ms | 48.8 |
| concurrency_ramp_write | 16 | 58.1 | 259.95 ms | 391.95 ms | 560.99 ms | 49.4 |
| concurrency_ramp_write | 32 | 57.3 | 559.09 ms | 572.89 ms | 576.96 ms | 53.2 |
| concurrency_ramp_write | 64 | 53.3 | 1193.96 ms | 1259.98 ms | 1273.96 ms | 55.5 |
| concurrency_ramp_read | 1 | 528,089 | 1.6 µs | 2.1 µs | 4.4 µs | 98.5 |
| concurrency_ramp_read | 2 | 476,551 | 4.0 µs | 4.8 µs | 5.3 µs | 123.6 |
| concurrency_ramp_read | 4 | 452,693 | 8.4 µs | 9.3 µs | 15.8 µs | 120.8 |
| concurrency_ramp_read | 8 | 478,181 | 16.6 µs | 17.9 µs | 20.8 µs | 122.2 |
| concurrency_ramp_read | 16 | 470,840 | 33.6 µs | 37.5 µs | 43.5 µs | 123.1 |
| concurrency_ramp_read | 32 | 447,561 | 68.2 µs | 89.4 µs | 148.5 µs | 119.8 |
| concurrency_ramp_read | 64 | 439,460 | 137.8 µs | 194.9 µs | 315.0 µs | 117.2 |

## SQL

| system | size | scenario | workers | rows/s | p50 | p95 | p99 | err | server CPU % |
|---|---|---|---|---|---|---|---|---|---|
| postgres_default_simple_query | 100B | insert | 1 | 22,657 | 30.2 µs | 40.4 µs | 247.3 µs | 0 | 39.2 |
| postgres_default_simple_query | 100B | select_pk | 1 | 57,228 | 16.4 µs | 20.7 µs | 31.2 µs | 0 | 73.2 |
| postgres_default_simple_query | 100B | batch_insert | 1 | 307,910 | 333.8 µs | 454.8 µs | 614.1 µs | 0 | 62.3 |
| postgres_default_simple_query | 100B | select_scan_limit100 | 1 | 2,766,427 | 35.5 µs | 41.1 µs | 50.9 µs | 0 | 69.0 |
| postgres_default_simple_query | 1KB | insert | 1 | 20,019 | 35.3 µs | 126.6 µs | 201.1 µs | 0 | 43.2 |
| postgres_default_simple_query | 1KB | select_pk | 1 | 58,186 | 16.5 µs | 20.9 µs | 30.4 µs | 0 | 74.8 |
| postgres_default_simple_query | 1KB | batch_insert | 1 | 103,333 | 883.2 µs | 1.14 ms | 1.93 ms | 0 | 60.2 |
| postgres_default_simple_query | 1KB | select_scan_limit100 | 1 | 1,517,513 | 62.5 µs | 94.1 µs | 123.0 µs | 0 | 75.8 |
| postgres_default_simple_query | 10KB | insert | 1 | 3,503 | 196.0 µs | 436.2 µs | 1.45 ms | 0 | 45.2 |
| postgres_default_simple_query | 10KB | select_pk | 1 | 42,632 | 19.9 µs | 32.6 µs | 43.0 µs | 0 | 79.5 |
| postgres_default_simple_query | 10KB | batch_insert | 1 | 6,840 | 6.01 ms | 8.13 ms | 14.62 ms | 0 | 68.7 |
| postgres_default_simple_query | 10KB | select_scan_limit100 | 1 | 163,580 | 607.3 µs | 712.2 µs | 904.6 µs | 0 | 83.6 |
| postgres_default_simple_query | 100KB | insert | 1 | 498.3 | 1.75 ms | 2.64 ms | 4.96 ms | 0 | 58.8 |
| postgres_default_simple_query | 100KB | select_pk | 1 | 11,561 | 83.5 µs | 113.5 µs | 135.3 µs | 0 | 74.5 |
| postgres_default_simple_query | 100KB | batch_insert | 1 | 645.0 | 6.56 ms | 9.22 ms | 12.36 ms | 0 | 71.9 |
| postgres_default_simple_query | 100KB | select_scan_limit100 | 1 | 11,040 | 9.52 ms | 9.81 ms | 9.93 ms | 0 | 65.0 |
| postgres_fsync_writethrough_simple_query | 100B | insert | 1 | 302.4 | 3.05 ms | 4.02 ms | 4.19 ms | 0 | 7.0 |
| postgres_fsync_writethrough_simple_query | 100B | select_pk | 1 | 58,993 | 16.2 µs | 20.4 µs | 29.9 µs | 0 | 73.3 |
| postgres_fsync_writethrough_simple_query | 100B | batch_insert | 1 | 22,383 | 4.11 ms | 5.08 ms | 6.05 ms | 0 | 17.6 |
| postgres_fsync_writethrough_simple_query | 100B | select_scan_limit100 | 1 | 2,774,157 | 35.7 µs | 40.9 µs | 50.5 µs | 0 | 67.1 |
| postgres_fsync_writethrough_simple_query | 1KB | insert | 1 | 282.8 | 3.61 ms | 4.07 ms | 4.95 ms | 0 | 7.0 |
| postgres_fsync_writethrough_simple_query | 1KB | select_pk | 1 | 56,867 | 16.7 µs | 21.1 µs | 30.9 µs | 0 | 73.2 |
| postgres_fsync_writethrough_simple_query | 1KB | batch_insert | 1 | 17,030 | 5.92 ms | 7.03 ms | 11.97 ms | 0 | 22.0 |
| postgres_fsync_writethrough_simple_query | 1KB | select_scan_limit100 | 1 | 1,360,960 | 68.9 µs | 103.0 µs | 158.8 µs | 0 | 71.8 |
| postgres_fsync_writethrough_simple_query | 10KB | insert | 1 | 219.5 | 4.42 ms | 5.65 ms | 8.00 ms | 0 | 13.3 |
| postgres_fsync_writethrough_simple_query | 10KB | select_pk | 1 | 33,548 | 29.5 µs | 33.5 µs | 43.2 µs | 0 | 70.2 |
| postgres_fsync_writethrough_simple_query | 10KB | batch_insert | 1 | 4,773 | 9.88 ms | 13.05 ms | 17.81 ms | 0 | 45.5 |
| postgres_fsync_writethrough_simple_query | 10KB | select_scan_limit100 | 1 | 166,513 | 594.8 µs | 700.3 µs | 793.0 µs | 0 | 82.0 |
| postgres_fsync_writethrough_simple_query | 100KB | insert | 1 | 159.9 | 6.03 ms | 8.06 ms | 12.01 ms | 0 | 28.8 |
| postgres_fsync_writethrough_simple_query | 100KB | select_pk | 1 | 9,879 | 91.8 µs | 131.7 µs | 144.5 µs | 0 | 69.0 |
| postgres_fsync_writethrough_simple_query | 100KB | batch_insert | 1 | 413.2 | 10.93 ms | 17.03 ms | 29.96 ms | 0 | 47.6 |
| postgres_fsync_writethrough_simple_query | 100KB | select_scan_limit100 | 1 | 11,690 | 9.51 ms | 10.11 ms | 10.27 ms | 0 | 67.4 |
| avrora_sqlcore_ipc | 100B | insert | 1 | 13.3 | 74.95 ms | 80.00 ms | 85.89 ms | 0 | 55.5 |
| avrora_sqlcore_ipc | 100B | select_pk | 1 | 46.7 | 21.31 ms | 22.09 ms | 25.72 ms | 0 | 99.4 |
| avrora_sqlcore_ipc | 100B | batch_insert | 1 | 13.3 | 8790.16 ms | 8828.92 ms | 8828.92 ms | 0 | 59.8 |
| avrora_sqlcore_ipc | 100B | select_scan_limit100 | 1 | 10,867 | 8.99 ms | 10.06 ms | 11.38 ms | 0 | 99.0 |
| avrora_sqlcore_ipc | 100B | concurrent_insert_conn_per_op | 4 | 10.7 | 376.02 ms | 388.91 ms | 394.05 ms | 0 | 63.5 |
| avrora_sqlcore_ipc | 100B | concurrent_select_conn_per_op | 4 | 32.9 | 115.22 ms | 138.51 ms | 264.68 ms | 0 | 97.2 |
| avrora_sqlcore_ipc | 1KB | insert | 1 | 12.5 | 78.11 ms | 90.98 ms | 123.00 ms | 0 | 57.2 |
| avrora_sqlcore_ipc | 1KB | select_pk | 1 | 41.8 | 22.51 ms | 28.46 ms | 50.67 ms | 0 | 97.1 |
| avrora_sqlcore_ipc | 1KB | batch_insert | 1 | 10.0 | 8935.10 ms | 9487.10 ms | 9487.10 ms | 0 | 60.6 |
| avrora_sqlcore_ipc | 1KB | select_scan_limit100 | 1 | 9,837 | 9.66 ms | 12.01 ms | 15.56 ms | 0 | 97.1 |
| avrora_sqlcore_ipc | 1KB | concurrent_insert_conn_per_op | 4 | 10.6 | 378.98 ms | 401.99 ms | 408.84 ms | 0 | 63.1 |
| avrora_sqlcore_ipc | 1KB | concurrent_select_conn_per_op | 4 | 34.3 | 114.72 ms | 123.66 ms | 138.97 ms | 0 | 98.5 |
| avrora_sqlcore_ipc | 10KB | insert | 1 | 8.3 | 114.14 ms | 139.56 ms | 195.74 ms | 0 | 46.5 |
| avrora_sqlcore_ipc | 10KB | select_pk | 1 | 40.7 | 24.23 ms | 26.57 ms | 32.15 ms | 0 | 98.8 |
| avrora_sqlcore_ipc | 10KB | batch_insert | 1 | 8.3 | 5079.96 ms | 5261.12 ms | 5261.12 ms | 0 | 61.1 |
| avrora_sqlcore_ipc | 10KB | select_scan_limit100 | 1 | 5,807 | 15.88 ms | 21.13 ms | 45.93 ms | 0 | 94.3 |
| avrora_sqlcore_ipc | 10KB | concurrent_insert_conn_per_op | 4 | 7.3 | 456.87 ms | 788.47 ms | 1888.97 ms | 0 | 58.9 |
| avrora_sqlcore_ipc | 10KB | concurrent_select_conn_per_op | 4 | 27.2 | 143.20 ms | 171.09 ms | 194.94 ms | 0 | 97.1 |
| avrora_sqlcore_ipc | 100KB | insert | 1 | 8.6 | 110.81 ms | 191.76 ms | 290.47 ms | 0 | 47.4 |
| avrora_sqlcore_ipc | 100KB | select_pk | 1 | 44.2 | 20.73 ms | 29.55 ms | 58.86 ms | 0 | 94.7 |
| avrora_sqlcore_ipc | 100KB | batch_insert | 1 | 6.2 | 667.04 ms | 1142.02 ms | 1321.96 ms | 0 | 53.6 |
| avrora_sqlcore_ipc | 100KB | select_scan_limit100 | 1 | 0.0 | — | — | — | 0 | 76.3 |
| avrora_sqlcore_ipc | 100KB | concurrent_insert_conn_per_op | 4 | 0.0 | — | — | — | 0 | 0.0 |
| avrora_sqlcore_ipc | 100KB | concurrent_select_conn_per_op | 4 | 0.0 | — | — | — | 0 | 0.0 |

- `request_limit_probe`: {"after_limit": "new client failed: io: Connection refused (os error 61)", "first_error": "at request 9999: io: Broken pipe (os error 32)", "requests_served_on_one_connection": 9999, "scenario": "request_limit_probe", "server_process_alive": true}

- `persistent_concurrency_probe`: {"clients": 4, "clients_making_progress": 1, "duration_s": 15, "requests_per_client": [4000, 0, 0, 0], "scenario": "persistent_concurrency_probe"}

- `size_unsupported`: {"note": "preload failed; remaining SQL scenarios skipped for this size", "params": {"size": "1MB"}, "scenario": "size_unsupported"}

## Channels

| scenario | P | C | size | produce msg/s | produce MB/s | delivered msg/s (all C) | ack/s | prod p99 | e2e p50 | e2e p95 | e2e p99 | backlog@stop | drain s | produced | uniq recv | lost | dup | retried | dlq | order viol | CPU % | RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1P_1C | 1 | 1 | 1024 | 38.5 | 0.040 | 25.9 | 25.9 | 42.09 ms | 20838.11 ms | 23432.05 ms | 23472.04 ms | 696 | 23.4 | 1392 | 1392 | 0 | 0 | 0 | 0 | 0 | 44.5 | 263.5 |
| 10P_1C | 10 | 1 | 1024 | 72.2 | 0.070 | 14.1 | 14.1 | 187.99 ms | 94499.04 ms | 124422.99 ms | 126776.93 ms | 2473 | 120.1 | 2603 | 2126 | 477 | 0 | 0 | 0 | 0 | 66.0 | 367.9 |
| 1P_10C | 1 | 10 | 1024 | 8.1 | 0.010 | 45.8 | 45.8 | 171.03 ms | 20772.98 ms | 31927.52 ms | 32921.86 ms | 1450 | 33.1 | 290 | 2900 | 0 | 0 | 0 | 0 | 0 | 32.0 | 38.9 |
| 10P_10C | 10 | 10 | 1024 | 36.6 | 0.040 | 22.9 | 22.9 | 476.06 ms | 129343.25 ms | 146627.18 ms | 148145.06 ms | 12800 | 120.6 | 1347 | 3460 | 10010 | 0 | 0 | 0 | 0 | 59.9 | 176.9 |
| 1P_1C_same_path | 1 | 1 | 1024 | 42.8 | 0.040 | 28.2 | 28.2 | 38.05 ms | 20346.16 ms | 23956.14 ms | 24068.94 ms | 766 | 24.1 | 1532 | 1532 | 0 | 0 | 0 | 0 | 0 | 41.4 | 93.2 |
| 1P_1C_ack_batch | 1 | 1 | 1024 | 38.9 | 0.040 | 26.2 | 26.2 | 42.96 ms | 20606.11 ms | 23274.02 ms | 23295.02 ms | 699 | 23.3 | 1398 | 1398 | 0 | 0 | 0 | 0 | 0 | 44.7 | 93.3 |
| 1P_1C_retry_ack_on_2nd | 1 | 1 | 1024 | 36.1 | 0.040 | 32.2 | 16.1 | 43.02 ms | 38257.18 ms | 50447.98 ms | 51103.98 ms | 437 | 51.2 | 1311 | 1311 | 0 | 0 | 1311 | 0 | 0 | 52.9 | 64.7 |
| 1P_1C_dlq_max3 | 1 | 1 | 1024 | 21.6 | 0.020 | 17.2 | 0.0 | 99.03 ms | 55991.11 ms | 105776.42 ms | 110722.91 ms | 1 | 112.0 | 815 | 815 | 0 | 0 | 1630 | 815 | 0 | 74.0 | 497.4 |
| ramp_1P_1C_5 | 1 | 1 | 1024 | 5.0 | 0.000 | 5.8 | 5.8 | 13.30 ms | 20.72 ms | 24.12 ms | 24.87 ms | 1 | 0.0 | 176 | 176 | 0 | 0 | 0 | 0 | 0 | 52.9 | 304.9 |
| ramp_1P_1C_10 | 1 | 1 | 1024 | 10.0 | 0.010 | 11.6 | 11.6 | 13.36 ms | 20.59 ms | 24.58 ms | 26.53 ms | 1 | 0.0 | 351 | 351 | 0 | 0 | 0 | 0 | 0 | 51.0 | 87.0 |
| ramp_1P_1C_20 | 1 | 1 | 1024 | 20.0 | 0.020 | 23.3 | 23.3 | 16.01 ms | 22.31 ms | 27.97 ms | 30.17 ms | 1 | 0.0 | 701 | 701 | 0 | 0 | 0 | 0 | 0 | 44.0 | 110.0 |
| ramp_1P_1C_30 | 1 | 1 | 1024 | 30.0 | 0.030 | 32.6 | 32.6 | 29.36 ms | 644.93 ms | 2468.03 ms | 2581.60 ms | 78 | 2.2 | 1051 | 1051 | 0 | 0 | 0 | 0 | 0 | 34.9 | 235.4 |
| ramp_1P_1C_40 | 1 | 1 | 1024 | 38.4 | 0.040 | 27.4 | 27.4 | 40.05 ms | 16160.92 ms | 19183.78 ms | 19237.99 ms | 591 | 19.2 | 1352 | 1352 | 0 | 0 | 0 | 0 | 0 | 42.7 | 294.1 |
| ramp_1P_10C_5 | 1 | 10 | 1024 | 5.0 | 0.000 | 51.5 | 51.5 | 141.11 ms | 1885.01 ms | 3775.55 ms | 3888.21 ms | 180 | 3.9 | 176 | 1760 | 0 | 0 | 0 | 0 | 0 | 30.5 | 198.7 |
| ramp_1P_10C_10 | 1 | 10 | 1024 | 8.1 | 0.010 | 45.8 | 45.8 | 159.78 ms | 20133.94 ms | 30584.26 ms | 31482.10 ms | 1440 | 30.3 | 288 | 2771 | 109 | 0 | 0 | 0 | 0 | 32.0 | 88.0 |
| 1P_1C | 1 | 1 | 102400 | 10.1 | 0.990 | 6.8 | 6.8 | 251.76 ms | 32827.37 ms | 36094.44 ms | 36183.38 ms | 217 | 33.1 | 434 | 434 | 0 | 0 | 0 | 0 | 0 | 84.0 | 2,565 |
| 10P_1C | 10 | 1 | 102400 | 23.2 | 2.260 | 1.2 | 1.2 | 1054.04 ms | — | — | — | 918 | 121.1 | 966 | 187 | 779 | 0 | 0 | 0 | 0 | 93.0 | 729.2 |
| 1P_10C | 1 | 10 | 102400 | 3.1 | 0.310 | 19.1 | 19.1 | 792.14 ms | 31638.12 ms | 38218.80 ms | 38426.18 ms | 640 | 36.7 | 128 | 1280 | 0 | 0 | 0 | 0 | 0 | 71.0 | 641.4 |
| 10P_10C | 10 | 10 | 102400 | 8.0 | 0.780 | 3.5 | 3.5 | 3507.58 ms | — | — | — | 3350 | 121.0 | 353 | 540 | 2990 | 0 | 0 | 0 | 0 | 92.9 | 1,045 |
| 1P_1C_same_path | 1 | 1 | 102400 | 10.4 | 1.020 | 6.9 | 6.9 | 255.27 ms | 33522.23 ms | 37688.14 ms | 37789.28 ms | 222 | 34.5 | 444 | 444 | 0 | 0 | 0 | 0 | 0 | 84.9 | 764.2 |
| 1P_1C_ack_batch | 1 | 1 | 102400 | 10.3 | 1.010 | 6.9 | 6.9 | 255.54 ms | 33113.23 ms | 37063.06 ms | 37158.33 ms | 220 | 34.0 | 440 | 440 | 0 | 0 | 0 | 0 | 0 | 84.7 | 1,606 |
| 1P_1C_retry_ack_on_2nd | 1 | 1 | 102400 | 7.8 | 0.760 | 7.0 | 3.5 | 266.20 ms | 63902.60 ms | 69889.16 ms | 70011.40 ms | 115 | 67.5 | 344 | 344 | 0 | 0 | 344 | 0 | 0 | 88.8 | 2,861 |
| 1P_1C_dlq_max3 | 1 | 1 | 102400 | 3.3 | 0.320 | 2.5 | 0.0 | 714.54 ms | 78262.79 ms | 125195.22 ms | 130032.20 ms | 1 | 121.4 | 152 | 127 | 25 | 0 | 252 | 126 | 0 | 95.5 | 2,974 |

- `backpressure_inflight_probe`: {"consume_again_without_ack": {"attempt": 2, "same_sequence": true}, "consume_batch_max_events_10_returned": 1, "consume_limit_10_returned": 1, "producer_side_backpressure": "none in API: put_data never rejects due to consumer lag (see backlog timelines)", "scenario": "backpressure_inflight_probe", "second_consume_batch_while_pending": "Err(backpressure for subscription 'c6893cfb-3eed-4335-acbf-17b8b1d779ac': in_flight=1 max=1)"}

- `ramp_verdict`: {"achieved_rate": 5.03, "backlog_at_stop": 1.0, "e2e_p99_us": 24873.92, "lost_or_undelivered": 0, "params": {"consumers": 1, "size": 1024, "target_rate": 5.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": true}

- `ramp_verdict`: {"achieved_rate": 10.03, "backlog_at_stop": 1.0, "e2e_p99_us": 26534.42, "lost_or_undelivered": 0, "params": {"consumers": 1, "size": 1024, "target_rate": 10.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": true}

- `ramp_verdict`: {"achieved_rate": 20.03, "backlog_at_stop": 1.0, "e2e_p99_us": 30174.83, "lost_or_undelivered": 0, "params": {"consumers": 1, "size": 1024, "target_rate": 20.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": true}

- `ramp_verdict`: {"achieved_rate": 30.03, "backlog_at_stop": 78.0, "e2e_p99_us": 2581602.88, "lost_or_undelivered": 0, "params": {"consumers": 1, "size": 1024, "target_rate": 30.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": false}

- `ramp_verdict`: {"achieved_rate": 38.4, "backlog_at_stop": 591.0, "e2e_p99_us": 19237994.96, "lost_or_undelivered": 0, "params": {"consumers": 1, "size": 1024, "target_rate": 40.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": false}

- `MAX_STABLE`: {"max_stable_delivered_msgs_per_s": 20.0, "max_stable_mb_per_s": 0.02, "max_stable_msgs_per_s": 20.0, "params": {"consumers": 1, "producers": 1, "size": 1024}, "scenario": "MAX_STABLE"}

- `ramp_verdict`: {"achieved_rate": 5.03, "backlog_at_stop": 180.0, "e2e_p99_us": 3888207.13, "lost_or_undelivered": 0, "params": {"consumers": 10, "size": 1024, "target_rate": 5.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": false}

- `ramp_verdict`: {"achieved_rate": 8.07, "backlog_at_stop": 1440.0, "e2e_p99_us": 31482095.58, "lost_or_undelivered": 109, "params": {"consumers": 10, "size": 1024, "target_rate": 10.0}, "scenario": "ramp_verdict", "stability_rule": "achieved >= 95% target AND backlog at producer stop <= 1 s of fan-out traffic AND e2e p99 < 1 s AND 0 undelivered after drain", "stable": false}

- `MAX_STABLE`: {"max_stable_delivered_msgs_per_s": null, "max_stable_mb_per_s": null, "max_stable_msgs_per_s": null, "params": {"consumers": 10, "producers": 1, "size": 1024}, "scenario": "MAX_STABLE"}

- `backpressure_inflight_probe`: {"consume_again_without_ack": {"attempt": 2, "same_sequence": true}, "consume_batch_max_events_10_returned": 1, "consume_limit_10_returned": 1, "producer_side_backpressure": "none in API: put_data never rejects due to consumer lag (see backlog timelines)", "scenario": "backpressure_inflight_probe", "second_consume_batch_while_pending": "Err(backpressure for subscription '520634bf-1dc9-4902-b553-ff0b58bc2620': in_flight=1 max=1)"}

## Triggers

| scenario | writes/s | write p50 | write p95 | write p99 | trigger deliv/s | trig p50 | trig p99 | expected | received | lagged | lost | CPU % |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0_triggers_1_writers | 79.6 | 12.93 ms | 14.02 ms | 14.12 ms | 0.0 | — | — | 0 | 0 | 0 | 0 | 36.0 |
| 1_triggers_1_writers | 81.6 | 12.05 ms | 13.99 ms | 14.08 ms | 83.6 | 766.11 ms | 1570.02 ms | 2925 | 2925 | 0 | 0 | 35.8 |
| 5_triggers_1_writers | 79.9 | 12.84 ms | 14.05 ms | 15.15 ms | 408.0 | 12.93 ms | 27.93 ms | 14280 | 14280 | 0 | 0 | 35.6 |
| 0_triggers_8_writers | 81.2 | 99.91 ms | 107.04 ms | 113.03 ms | 0.0 | — | — | 0 | 0 | 0 | 0 | 35.9 |
| 1_triggers_8_writers | 79.7 | 100.98 ms | 107.03 ms | 110.00 ms | 82.0 | 99.90 ms | 109.99 ms | 2871 | 2871 | 0 | 0 | 36.3 |
| 5_triggers_8_writers | 80.6 | 99.86 ms | 106.88 ms | 109.00 ms | 413.7 | 98.22 ms | 109.18 ms | 14480 | 14480 | 0 | 0 | 36.0 |

## Connections

| system | conns | connected | failed | setup p50 | setup p99 | req/s | errors/s | p50 | p95 | p99 | server CPU % | server RSS MB | client CPU % | stable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| avrora_control_tls13_mtls | 10 | 10 | 0 | 1.33 ms | 1.39 ms | 95,217 | 0.0 | 102.8 µs | 152.3 µs | 179.2 µs | 197.9 | 17.0 | 243.8 | True |
| avrora_control_tls13_mtls | 50 | 50 | 0 | 5.84 ms | 11.00 ms | 99,025 | 0.0 | 502.5 µs | 579.1 µs | 627.9 µs | 207.2 | 17.7 | 265.5 | True |
| avrora_control_tls13_mtls | 100 | 100 | 0 | 11.51 ms | 14.52 ms | 99,279 | 0.0 | 1.00 ms | 1.11 ms | 1.17 ms | 207.6 | 18.6 | 264.6 | True |
| avrora_control_tls13_mtls | 250 | 250 | 0 | 19.41 ms | 78.45 ms | 99,123 | 0.0 | 2.51 ms | 2.70 ms | 3.01 ms | 206.7 | 20.5 | 267.1 | True |
| avrora_control_tls13_mtls | 500 | 500 | 0 | 13.64 ms | 72.16 ms | 97,930 | 0.0 | 5.08 ms | 5.40 ms | 5.68 ms | 205.9 | 23.7 | 259.7 | True |
| avrora_control_tls13_mtls | 1000 | 1000 | 0 | 11.71 ms | 53.09 ms | 94,262 | 0.0 | 10.58 ms | 11.09 ms | 11.48 ms | 203.6 | 30.2 | 249.6 | True |
| avrora_control_tls13_mtls | 2500 | 2500 | 0 | 11.13 ms | 52.73 ms | 91,981 | 0.0 | 26.99 ms | 28.52 ms | 31.13 ms | 201.2 | 48.9 | 244.6 | True |
| avrora_control_tls13_mtls | 5000 | 5000 | 0 | 11.53 ms | 85.48 ms | 91,500 | 0.0 | 54.36 ms | 57.39 ms | 61.76 ms | 201.6 | 80.0 | 241.2 | True |
| avrora_control_tls13_mtls | 10000 | 10000 | 0 | 12.29 ms | 50.98 ms | 88,712 | 0.0 | 111.33 ms | 121.97 ms | 129.71 ms | 199.9 | 142.3 | 240.0 | True |
| avrora_control_tls13_mtls | 15000 | 15000 | 0 | 12.93 ms | 43.30 ms | 88,275 | 0.0 | 168.10 ms | 187.60 ms | 208.22 ms | 199.4 | 204.8 | 237.5 | True |
| postgres_default_tcp | 10 | 10 | 0 | 3.67 ms | 4.15 ms | 164,488 | 0.0 | 58.3 µs | 101.0 µs | 129.6 µs | 0.0 | 178.5 | 231.2 | True |
| postgres_default_tcp | 50 | 50 | 0 | 11.17 ms | 19.30 ms | 204,716 | 0.0 | 226.8 µs | 429.1 µs | 658.9 µs | 0.1 | 580.8 | 315.2 | True |
| postgres_default_tcp | 100 | 100 | 0 | 20.84 ms | 50.94 ms | 202,789 | 0.0 | 467.5 µs | 887.3 µs | 1.33 ms | 0.3 | 1,097 | 301.6 | True |
| postgres_default_tcp | 250 | 250 | 0 | 64.91 ms | 141.95 ms | 186,593 | 0.0 | 1.16 ms | 2.78 ms | 4.45 ms | 0.8 | 2,628 | 249.7 | True |
| postgres_default_tcp | 500 | 500 | 0 | 42.05 ms | 270.66 ms | 171,248 | 0.0 | 2.24 ms | 7.37 ms | 13.51 ms | 1.6 | 5,251 | 213.2 | True |
| postgres_default_tcp | 1000 | 1000 | 0 | 71.98 ms | 737.53 ms | 155,548 | 0.0 | 4.84 ms | 18.43 ms | 32.74 ms | 3.2 | 10,533 | 193.2 | True |

## Security

| system | scenario | size | ops/s | MB/s | p50 | p95 | p99 | err |
|---|---|---|---|---|---|---|---|---|
| primitive | aes256gcm_encrypt | 100B | 245,028 | 23.37 | 2.0 µs | 2.2 µs | 2.6 µs | 0 |
| primitive | aes256gcm_decrypt | 100B | 245,028 | 23.37 | 2.0 µs | 2.2 µs | 2.5 µs | 0 |
| primitive | aes256gcm_encrypt | 1KB | 83,599 | 81.64 | 5.6 µs | 7.0 µs | 13.1 µs | 0 |
| primitive | aes256gcm_decrypt | 1KB | 83,599 | 81.64 | 5.6 µs | 7.0 µs | 13.1 µs | 0 |
| primitive | aes256gcm_encrypt | 10KB | 10,002 | 97.68 | 47.6 µs | 53.0 µs | 105.5 µs | 0 |
| primitive | aes256gcm_decrypt | 10KB | 10,002 | 97.68 | 47.6 µs | 52.9 µs | 94.9 µs | 0 |
| primitive | aes256gcm_encrypt | 100KB | 1,062 | 103.75 | 469.8 µs | 484.6 µs | 494.8 µs | 0 |
| primitive | aes256gcm_decrypt | 100KB | 1,062 | 103.75 | 469.1 µs | 483.6 µs | 492.0 µs | 0 |
| primitive | aes256gcm_encrypt | 1MB | 104.1 | 104.09 | 4.81 ms | 4.85 ms | 4.90 ms | 0 |
| primitive | aes256gcm_decrypt | 1MB | 104.1 | 104.09 | 4.82 ms | 4.87 ms | 4.90 ms | 0 |
| primitive | append_no_sync | 100B | 1,012,880 | 96.60 | 0.9 µs | 1.1 µs | 2.9 µs | 0 |
| primitive | append_fsync_libc | 100B | 55,335 | 5.28 | 17.2 µs | 23.4 µs | 31.2 µs | 0 |
| primitive | append_sync_all_F_FULLFSYNC | 100B | 260.6 | 0.02 | 3.98 ms | 4.21 ms | 5.98 ms | 0 |
| primitive | append_aes_sync_all | 100B | 264.5 | 0.03 | 3.98 ms | 4.09 ms | 5.02 ms | 0 |
| primitive | append_no_sync | 1KB | 236,048 | 230.52 | 2.6 µs | 9.6 µs | 16.4 µs | 0 |
| primitive | append_fsync_libc | 1KB | 31,170 | 30.44 | 28.8 µs | 49.9 µs | 56.5 µs | 0 |
| primitive | append_sync_all_F_FULLFSYNC | 1KB | 250.0 | 0.24 | 3.97 ms | 5.00 ms | 9.91 ms | 0 |
| primitive | append_aes_sync_all | 1KB | 257.2 | 0.25 | 3.98 ms | 5.00 ms | 5.21 ms | 0 |
| primitive | append_no_sync | 10KB | 67,539 | 659.56 | 4.8 µs | 11.6 µs | 15.7 µs | 0 |
| primitive | append_fsync_libc | 10KB | 27,417 | 267.74 | 31.4 µs | 39.0 µs | 53.8 µs | 0 |
| primitive | append_sync_all_F_FULLFSYNC | 10KB | 241.9 | 2.36 | 4.00 ms | 5.03 ms | 6.03 ms | 0 |
| primitive | append_aes_sync_all | 10KB | 231.2 | 2.26 | 4.12 ms | 5.03 ms | 5.14 ms | 0 |
| primitive | append_no_sync | 100KB | 11,114 | 1,085 | 12.5 µs | 39.8 µs | 4.25 ms | 0 |
| primitive | append_fsync_libc | 100KB | 9,975 | 974.14 | 56.5 µs | 238.4 µs | 1.20 ms | 0 |
| primitive | append_sync_all_F_FULLFSYNC | 100KB | 235.8 | 23.03 | 4.00 ms | 5.06 ms | 7.02 ms | 0 |
| primitive | append_aes_sync_all | 100KB | 175.2 | 17.11 | 5.88 ms | 7.06 ms | 8.88 ms | 0 |
| primitive | append_no_sync | 1MB | 1,252 | 1,252 | 93.5 µs | 5.85 ms | 8.04 ms | 0 |
| primitive | append_fsync_libc | 1MB | 968.1 | 968.07 | 1.05 ms | 1.63 ms | 2.84 ms | 0 |
| primitive | append_sync_all_F_FULLFSYNC | 1MB | 208.3 | 208.28 | 4.93 ms | 5.98 ms | 8.01 ms | 0 |
| primitive | append_aes_sync_all | 1MB | 110.7 | 110.73 | 8.97 ms | 10.12 ms | 14.34 ms | 0 |
| echo_plain_tcp | echo_roundtrip | 100B | 55,010 | 10.49 | 18.0 µs | 23.1 µs | 31.8 µs | 0 |
| echo_tls13 | echo_roundtrip | 100B | 52,895 | 10.09 | 18.8 µs | 23.8 µs | 32.1 µs | 0 |
| echo_plain_tcp | echo_roundtrip | 1KB | 53,215 | 103.94 | 18.5 µs | 23.3 µs | 32.0 µs | 0 |
| echo_tls13 | echo_roundtrip | 1KB | 47,609 | 92.99 | 21.0 µs | 25.5 µs | 34.0 µs | 0 |
| echo_plain_tcp | echo_roundtrip | 10KB | 49,566 | 968.09 | 19.5 µs | 24.5 µs | 33.4 µs | 0 |
| echo_tls13 | echo_roundtrip | 10KB | 30,538 | 596.44 | 32.2 µs | 36.2 µs | 46.1 µs | 0 |
| echo_plain_tcp | echo_roundtrip | 100KB | 29,382 | 5,739 | 33.0 µs | 41.4 µs | 47.5 µs | 0 |
| echo_tls13 | echo_roundtrip | 100KB | 8,270 | 1,615 | 119.9 µs | 127.3 µs | 136.8 µs | 0 |
| primitive | connect_tcp_only |  | — | — | 33.7 µs | 49.4 µs | 109.8 µs | None |
| primitive | tls13_handshake_after_tcp |  | — | — | 182.5 µs | 240.7 µs | 276.6 µs | None |
| avrora_inproc | kv_put | 100B | 96.6 | 0.01 | 10.06 ms | 12.00 ms | 13.02 ms | 0 |
| avrora_inproc | kv_get | 100B | 668,712 | 63.77 | 1.4 µs | 1.8 µs | 1.9 µs | 0 |
| avrora_remote_tls13_mtls | kv_put | 100B | 83.3 | 0.01 | 11.99 ms | 13.60 ms | 15.17 ms | 0 |
| avrora_remote_tls13_mtls | kv_get | 100B | 43,478 | 4.15 | 22.5 µs | 27.4 µs | 37.0 µs | 0 |
| avrora_inproc | kv_put | 1KB | 94.9 | 0.09 | 10.13 ms | 12.05 ms | 14.12 ms | 0 |
| avrora_inproc | kv_get | 1KB | 665,215 | 649.62 | 1.4 µs | 1.8 µs | 1.9 µs | 0 |
| avrora_remote_tls13_mtls | kv_put | 1KB | 82.6 | 0.08 | 12.00 ms | 13.98 ms | 15.78 ms | 0 |
| avrora_remote_tls13_mtls | kv_get | 1KB | 25,108 | 24.52 | 36.7 µs | 53.8 µs | 94.5 µs | 0 |
| avrora_inproc | kv_put | 10KB | 104.5 | 1.02 | 9.16 ms | 11.93 ms | 13.97 ms | 0 |
| avrora_inproc | kv_get | 10KB | 499,338 | 4,876 | 1.8 µs | 2.3 µs | 4.2 µs | 0 |
| avrora_remote_tls13_mtls | kv_put | 10KB | 83.4 | 0.81 | 11.14 ms | 15.41 ms | 26.22 ms | 0 |
| avrora_remote_tls13_mtls | kv_get | 10KB | 5,508 | 53.79 | 178.0 µs | 202.5 µs | 246.6 µs | 0 |
| avrora_inproc | kv_put | 100KB | 79.3 | 7.75 | 12.27 ms | 14.10 ms | 17.15 ms | 0 |
| avrora_inproc | kv_get | 100KB | 170,169 | 16,618 | 5.6 µs | 6.9 µs | 9.9 µs | 0 |
| avrora_remote_tls13_mtls | kv_put | 100KB | 72.1 | 7.04 | 13.95 ms | 15.15 ms | 17.67 ms | 0 |
| avrora_remote_tls13_mtls | kv_get | 100KB | 623.6 | 60.90 | 1.60 ms | 1.72 ms | 1.79 ms | 0 |
| avrora_inproc | kv_put | 300KB | 66.5 | 19.47 | 14.98 ms | 16.80 ms | 21.40 ms | 0 |
| avrora_inproc | kv_get | 300KB | 88,038 | 25,792 | 11.1 µs | 12.3 µs | 14.4 µs | 0 |
| avrora_remote_tls13_mtls | kv_put | 300KB | — | — | — | — | — | 1 |

## Correctness

- **idempotent_producer** → PASS: `{"acked": 500, "duplicated": 0, "journal_entries_added": 500, "lock_before_restart": "Ok(())", "lost": 0, "new_entries_after_restart": 0, "produced_attempts": 1000, "received": 500, "received_unique": 500, "replay_flags": 500, "replays_after_restart": 100, "restart_unlock_ok": true, "result": "PASS", "scenario": "idempotent_producer", "sequence_mismatch_between_duplicates": 0, "unique_keys": 500}`
- **retry_ack_on_3rd_attempt** → PASS: `{"acked": 200, "deliveries": 600, "dlq": 0, "duplicated": 0, "ids_with_attempts_exactly_1_2_3": 200, "lost": 0, "produced": 200, "received_unique": 200, "result": "PASS", "retried": 400, "scenario": "retry_ack_on_3rd_attempt"}`
- **dlq_max_attempts_3** → PASS: `{"acked": 0, "deliveries": 300, "dlq": 100, "dlq_entries_attempts_all_3": true, "dlq_sequences_match_delivered": true, "duplicated": 0, "final_lag_events": 204, "final_pending": false, "lag_dlq_count": 100, "list_dlq_admin_session": "Ok(100)", "list_dlq_error_consumer_session": "access denied: missing READ on '/_system/dlq/815ae782-5bf4-4a01-89b3-0a81535722ed'", "lost": 0, "produced": 100, "received_unique": 100, "result": "PASS", "retried": 200, "scenario": "dlq_max_attempts_3"}`
- **graceful_restart** → PASS: `{"acked_before_restart": 400, "acked_redelivered": 0, "duplicated": 0, "error": null, "lost": 0, "pending_at_restart": 400, "pending_redelivered_after_restart": true, "produced": 1000, "received_after_restart": 600, "received_unique_total": 1000, "result": "PASS", "scenario": "graceful_restart"}`
- **sigkill_crash_recovery** → PASS: `{"acked": 361, "acked_then_redelivered_after_recovery": 0, "corrupt_payloads": 0, "cycles": 5, "deliveries_after_recovery": 251, "deliveries_before_crashes": 361, "duplicated_acks": 0, "lost_acknowledged_writes": 0, "lost_sample": [], "never_delivered": 0, "produced_acknowledged": 610, "received_unique": 612, "recovery_unlock": "ok", "result": "PASS", "scenario": "sigkill_crash_recovery"}`
  - cycles: `[{"acknowledged_writes": 155, "acks": 92, "cycle": 0, "deliveries": 92, "ran_ms": 3617, "ready": true}, {"acknowledged_writes": 106, "acks": 63, "cycle": 1, "deliveries": 63, "ran_ms": 2642, "ready": true}, {"acknowledged_writes": 63, "acks": 36, "cycle": 2, "deliveries": 36, "ran_ms": 1616, "ready": true}, {"acknowledged_writes": 136, "acks": 83, "cycle": 3, "deliveries": 83, "ran_ms": 3649, "ready": true}, {"acknowledged_writes": 150, "acks": 87, "cycle": 4, "deliveries": 87, "ran_ms": 3957, "ready": true}]`

## PostgreSQL settings

- postgres_default: `{"fsync": "on", "full_page_writes": "on", "max_connections": "100", "server_version": "14.17 (Homebrew)", "shared_buffers": "128MB", "synchronous_commit": "on", "wal_level": "replica", "wal_sync_method": "open_datasync"}`
- postgres_fsync_writethrough: `{"fsync": "on", "full_page_writes": "on", "max_connections": "100", "server_version": "14.17 (Homebrew)", "shared_buffers": "128MB", "synchronous_commit": "on", "wal_level": "replica", "wal_sync_method": "fsync_writethrough"}`
