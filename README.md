# decds
A Distribued Erasure-Coded Data Storage System


**WIP**

```bash
Timer precision: 19 ns
build_blob                                                     fastest       │ slowest       │ median        │ mean          │ samples │ iters
╰─ build_blob                                                                │               │               │               │         │
   ├─ Erasure code + Generate Merkle proof for 1.00 GB blob    2.156 s       │ 2.766 s       │ 2.656 s       │ 2.54 s        │ 40      │ 40
   │                                                           474.9 MiB/s   │ 370.1 MiB/s   │ 385.4 MiB/s   │ 403 MiB/s     │         │
   │                                                           max alloc:    │               │               │               │         │
   │                                                             4           │ 4             │ 4             │ 8.15          │         │
   │                                                             1 GiB       │ 1 GiB         │ 1 GiB         │ 1 GiB         │         │
   │                                                           alloc:        │               │               │               │         │
   │                                                             11          │ 11            │ 11            │ 15.32         │         │
   │                                                             16.16 KiB   │ 16.16 KiB     │ 16.16 KiB     │ 17.58 KiB     │         │
   │                                                           dealloc:      │               │               │               │         │
   │                                                             10          │ 10            │ 10            │ 10.17         │         │
   │                                                             2 GiB       │ 2 GiB         │ 2 GiB         │ 2 GiB         │         │
   │                                                           grow:         │               │               │               │         │
   │                                                             11          │ 11            │ 11            │ 11.05         │         │
   │                                                             1 GiB       │ 1 GiB         │ 1 GiB         │ 1 GiB         │         │
   ├─ Erasure code + Generate Merkle proof for 1.00 MB blob    76.91 ms      │ 128.4 ms      │ 83.02 ms      │ 83.75 ms      │ 100     │ 100
   │                                                           13 MiB/s      │ 7.787 MiB/s   │ 12.04 MiB/s   │ 11.93 MiB/s   │         │
   │                                                           max alloc:    │               │               │               │         │
   │                                                             39          │ 39            │ 39            │ 39            │         │
   │                                                             45 MiB      │ 45 MiB        │ 45 MiB        │ 45 MiB        │         │
   │                                                           alloc:        │               │               │               │         │
   │                                                             142         │ 142           │ 142           │ 142           │         │
   │                                                             26.02 MiB   │ 26.02 MiB     │ 26.02 MiB     │ 26.02 MiB     │         │
   │                                                           dealloc:      │               │               │               │         │
   │                                                             108         │ 108           │ 108           │ 108           │         │
   │                                                             30.02 MiB   │ 30.02 MiB     │ 30.02 MiB     │ 30.02 MiB     │         │
   │                                                           grow:         │               │               │               │         │
   │                                                             19          │ 19            │ 19            │ 19            │         │
   │                                                             19 MiB      │ 19 MiB        │ 19 MiB        │ 19 MiB        │         │
   ├─ Erasure code + Generate Merkle proof for 4.00 GB blob    10.02 s       │ 10.8 s        │ 10.35 s       │ 10.42 s       │ 10      │ 10
   │                                                           408.5 MiB/s   │ 378.9 MiB/s   │ 395.5 MiB/s   │ 392.7 MiB/s   │         │
   │                                                           max alloc:    │               │               │               │         │
   │                                                             4           │ 4             │ 4             │ 4             │         │
   │                                                             4 GiB       │ 4 GiB         │ 4 GiB         │ 4 GiB         │         │
   │                                                           alloc:        │               │               │               │         │
   │                                                             13          │ 13            │ 13            │ 13            │         │
   │                                                             61.98 KiB   │ 61.98 KiB     │ 61.98 KiB     │ 61.98 KiB     │         │
   │                                                           dealloc:      │               │               │               │         │
   │                                                             12          │ 12            │ 12            │ 12            │         │
   │                                                             8 GiB       │ 8 GiB         │ 8 GiB         │ 8 GiB         │         │
   │                                                           grow:         │               │               │               │         │
   │                                                             22          │ 22            │ 22            │ 22            │         │
   │                                                             4 GiB       │ 4 GiB         │ 4 GiB         │ 4 GiB         │         │
   ├─ Erasure code + Generate Merkle proof for 16.00 MB blob   109.7 ms      │ 163.4 ms      │ 122 ms        │ 123.9 ms      │ 100     │ 100
   │                                                           145.8 MiB/s   │ 97.89 MiB/s   │ 131 MiB/s     │ 129 MiB/s     │         │
   │                                                           max alloc:    │               │               │               │         │
   │                                                             4           │ 4             │ 4             │ 4.01          │         │
   │                                                             16 MiB      │ 16 MiB        │ 16 MiB        │ 16 MiB        │         │
   │                                                           alloc:        │               │               │               │         │
   │                                                             5           │ 5             │ 5             │ 5.03          │         │
   │                                                             544 B       │ 544 B         │ 544 B         │ 589.6 B       │         │
   │                                                           dealloc:      │               │               │               │         │
   │                                                             4           │ 4             │ 4             │ 4             │         │
   │                                                             32 MiB      │ 32 MiB        │ 32 MiB        │ 32 MiB        │         │
   │                                                           grow:         │               │               │               │         │
   │                                                             1           │ 1             │ 1             │ 1             │         │
   │                                                             16 MiB      │ 16 MiB        │ 16 MiB        │ 16 MiB        │         │
   ╰─ Erasure code + Generate Merkle proof for 256.00 MB blob  562.2 ms      │ 773.4 ms      │ 675.5 ms      │ 673.5 ms      │ 100     │ 100
                                                               455.3 MiB/s   │ 330.9 MiB/s   │ 378.9 MiB/s   │ 380 MiB/s     │         │
                                                               max alloc:    │               │               │               │         │
                                                                 4           │ 4             │ 4             │ 4.02          │         │
                                                                 256 MiB     │ 256 MiB       │ 256 MiB       │ 256 MiB       │         │
                                                               alloc:        │               │               │               │         │
                                                                 9           │ 9             │ 9             │ 9.03          │         │
                                                                 4.484 KiB   │ 4.484 KiB     │ 4.484 KiB     │ 4.528 KiB     │         │
                                                               dealloc:      │               │               │               │         │
                                                                 8           │ 8             │ 8             │ 8             │         │
                                                                 512 MiB     │ 512 MiB       │ 512 MiB       │ 512 MiB       │         │
                                                               grow:         │               │               │               │         │
                                                                 4           │ 4             │ 4             │ 4             │         │
                                                                 256 MiB     │ 256 MiB       │ 256 MiB       │ 256 MiB       │         │

     Running benches/repair_blob.rs (target/optimized/deps/repair_blob-275aa69fb83bf938)
Timer precision: 20 ns
repair_blob                                         fastest       │ slowest       │ median        │ mean          │ samples │ iters
╰─ repair_blob                                                    │               │               │               │         │
   ├─ Verify + Repair Erasure Coded 1.00 GB blob    49.82 ms      │ 214.9 ms      │ 81.51 ms      │ 87.44 ms      │ 100     │ 100
   │                                                20.06 GiB/s   │ 4.651 GiB/s   │ 12.26 GiB/s   │ 11.43 GiB/s   │         │
   │                                                max alloc:    │               │               │               │         │
   │                                                  104         │ 104           │ 104           │ 104           │         │
   │                                                  1.005 GiB   │ 1.005 GiB     │ 1.005 GiB     │ 1.005 GiB     │         │
   │                                                alloc:        │               │               │               │         │
   │                                                  104         │ 104           │ 104           │ 104           │         │
   │                                                  1.005 GiB   │ 1.005 GiB     │ 1.005 GiB     │ 1.005 GiB     │         │
   │                                                dealloc:      │               │               │               │         │
   │                                                  2166        │ 2166          │ 2166          │ 2166          │         │
   │                                                  2.012 GiB   │ 2.012 GiB     │ 2.012 GiB     │ 2.012 GiB     │         │
   ├─ Verify + Repair Erasure Coded 1.00 MB blob    3.936 ms      │ 71.84 ms      │ 22.7 ms       │ 25 ms         │ 100     │ 100
   │                                                254 MiB/s     │ 13.91 MiB/s   │ 44.04 MiB/s   │ 39.99 MiB/s   │         │
   │                                                max alloc:    │               │               │               │         │
   │                                                  2           │ 3             │ 2             │ 2.03          │         │
   │                                                  10 MiB      │ 20 MiB        │ 10 MiB        │ 10.3 MiB      │         │
   │                                                alloc:        │               │               │               │         │
   │                                                  2           │ 4             │ 2             │ 2.06          │         │
   │                                                  10 MiB      │ 30 MiB        │ 10 MiB        │ 10.6 MiB      │         │
   │                                                dealloc:      │               │               │               │         │
   │                                                  24          │ 26            │ 24            │ 24.06         │         │
   │                                                  20 MiB      │ 40 MiB        │ 20 MiB        │ 20.6 MiB      │         │
   ├─ Verify + Repair Erasure Coded 4.00 GB blob    128.3 ms      │ 288.3 ms      │ 152 ms        │ 160.1 ms      │ 100     │ 100
   │                                                31.17 GiB/s   │ 13.86 GiB/s   │ 26.31 GiB/s   │ 24.96 GiB/s   │         │
   │                                                max alloc:    │               │               │               │         │
   │                                                  411         │ 411           │ 411           │ 411           │         │
   │                                                  4.003 GiB   │ 4.003 GiB     │ 4.003 GiB     │ 4.003 GiB     │         │
   │                                                alloc:        │               │               │               │         │
   │                                                  411         │ 411           │ 411           │ 411           │         │
   │                                                  4.003 GiB   │ 4.003 GiB     │ 4.003 GiB     │ 4.003 GiB     │         │
   │                                                dealloc:      │               │               │               │         │
   │                                                  8613        │ 8613          │ 8613          │ 8613          │         │
   │                                                  8.01 GiB    │ 8.01 GiB      │ 8.01 GiB      │ 8.01 GiB      │         │
   ├─ Verify + Repair Erasure Coded 16.00 MB blob   3.632 ms      │ 170.9 ms      │ 34.47 ms      │ 42.65 ms      │ 100     │ 100
   │                                                4.3 GiB/s     │ 93.57 MiB/s   │ 464 MiB/s     │ 375 MiB/s     │         │
   │                                                max alloc:    │               │               │               │         │
   │                                                  3           │ 3             │ 3             │ 3             │         │
   │                                                  20 MiB      │ 20 MiB        │ 20 MiB        │ 20 MiB        │         │
   │                                                alloc:        │               │               │               │         │
   │                                                  3           │ 3             │ 3             │ 3             │         │
   │                                                  20 MiB      │ 20 MiB        │ 20 MiB        │ 20 MiB        │         │
   │                                                dealloc:      │               │               │               │         │
   │                                                  45          │ 45            │ 45            │ 45            │         │
   │                                                  40 MiB      │ 40 MiB        │ 40 MiB        │ 40 MiB        │         │
   ╰─ Verify + Repair Erasure Coded 256.00 MB blob  15.92 ms      │ 158.5 ms      │ 48.19 ms      │ 51.42 ms      │ 100     │ 100
                                                    15.69 GiB/s   │ 1.576 GiB/s   │ 5.187 GiB/s   │ 4.861 GiB/s   │         │
                                                    max alloc:    │               │               │               │         │
                                                      27          │ 27            │ 27            │ 27            │         │
                                                      260 MiB     │ 260 MiB       │ 260 MiB       │ 260 MiB       │         │
                                                    alloc:        │               │               │               │         │
                                                      27          │ 27            │ 27            │ 27            │         │
                                                      260 MiB     │ 260 MiB       │ 260 MiB       │ 260 MiB       │         │
                                                    dealloc:      │               │               │               │         │
                                                      549         │ 549           │ 549           │ 549           │         │
                                                      520.1 MiB   │ 520.1 MiB     │ 520.1 MiB     │ 520.1 MiB     │         │
```
