window.BENCHMARK_DATA = {
  "lastUpdate": 1794608520138,
  "repoUrl": "https://github.com/ThreatFlux/file-scanner",
  "entries": {
    "Rust Benchmark": [
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "91d5c802e91d59ffc2068f374fb160fa255ac581",
          "message": "fix: preserve benchmark_results.json during git cleanup\n\nThe benchmark-action was failing because git stash/clean was removing the\nbenchmark_results.json file. Now we save it to /tmp before cleaning and\nrestore it after to ensure it's available for the benchmark-action.",
          "timestamp": "2025-09-02T10:16:39-04:00",
          "tree_id": "91b23f419823103ed9f6627dc75d9943473fbd46",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/91d5c802e91d59ffc2068f374fb160fa255ac581"
        },
        "date": 1756824098347,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2653274.088947369,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 307259.103162945,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2164726.2512499993,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31388.054943970375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2603916.0665,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4993.704928567528,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38571.57717723452,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74037.61509915319,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238655.14976561762,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3174863.963125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2189139.286956522,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50919.93325519576,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "df34c3109a561692ffd62f0449a6c14588916f2c",
          "message": "fix: remove trailing spaces from performance.yml",
          "timestamp": "2025-09-02T10:17:42-04:00",
          "tree_id": "3c29f09f611e0d6267083c1e04f58eb8d87f7c6f",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/df34c3109a561692ffd62f0449a6c14588916f2c"
        },
        "date": 1756824227658,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2657927.8021052624,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 315393.07106431935,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2153345.69625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31848.247222445807,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2700190.2221052633,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4970.760617194473,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38507.09220182459,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74573.88070661665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235762.84311820436,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3297606.44625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2157131.703913043,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50882.48235207164,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "5388914e50ccbf3dc0313d269c8574007d807d86",
          "message": "fix: add bash shell specification for Windows builds in auto-release\n\nWindows was trying to run bash scripts in PowerShell, causing syntax errors.\nAdded 'shell: bash' to build steps to ensure they use Git Bash on Windows.",
          "timestamp": "2025-09-02T14:49:09-04:00",
          "tree_id": "5530d31890f68a6e268bc260681574e72eb09259",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/5388914e50ccbf3dc0313d269c8574007d807d86"
        },
        "date": 1756840462355,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2651632.962105261,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316005.722145318,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2157351.455833333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31269.57030075233,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2677569.8452631584,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4961.773769266906,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37601.23439715047,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 73631.49471619389,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238155.28329909153,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3298480.244375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2202496.957826087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50162.78743403841,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "1e1b22efff853421d47b0b6816f8c45f6ba30ce5",
          "message": "fix: add timeout to integration tests to prevent CI hangs\n\n- Add 10-minute timeout to integration test execution\n- Properly handle timeout exit code (124) vs test failures\n- Prevent CI workflow from hanging indefinitely on test execution",
          "timestamp": "2025-09-02T15:49:43-04:00",
          "tree_id": "8e43ffe66cba9b10f7a3725510d25c4051de5d0a",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/1e1b22efff853421d47b0b6816f8c45f6ba30ce5"
        },
        "date": 1756844148920,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2655971.9410526305,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 309696.97529954556,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2171277.7920833332,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32922.366017461034,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2636833.3457894735,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4992.879738907416,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 39503.449205717014,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74223.72452897445,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 243253.17398530737,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3271467.735,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2194708.6560869566,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52137.037845502746,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "cf67a825d4a99f213880edbe873dcfeb3543d537",
          "message": "fix: remove unsupported lld linker flag for macOS builds\n\n- Remove -fuse-ld=lld flag for x86_64-apple-darwin target\n- Add configuration for aarch64-apple-darwin target\n- Add placeholder for x86_64-pc-windows-msvc target\n- Fixes Auto Release workflow failure on macOS builds",
          "timestamp": "2025-09-03T06:20:30-04:00",
          "tree_id": "424c5a61701da21ee236b55ebfec73b30937d09f",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/cf67a825d4a99f213880edbe873dcfeb3543d537"
        },
        "date": 1756896291797,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2654788.1047368427,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 315272.23354635295,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2144561.478333332,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31303.270616211244,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2655406.5068421047,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4984.348373283086,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38773.18777223024,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74649.61080831468,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236090.44683748466,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3301152.930625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2218468.771304348,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49878.68233677907,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "0982068d47b2aaf70fe64614130a01748ad13e4d",
          "message": "fix: resolve clippy warnings and improve code quality",
          "timestamp": "2025-09-03T11:05:03Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/87/commits/0982068d47b2aaf70fe64614130a01748ad13e4d"
        },
        "date": 1757023378148,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2651385.9315789463,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 308028.60194569675,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2146709.2466666666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31770.167262479994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2510818.8433333337,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4990.277390604256,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38344.38248506028,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74150.13118891121,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236430.14208200225,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3306651.080625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2175824.1530434773,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50679.5225017282,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "da0c7d6e8a71e24ba2c014b0b086259e8636a4f4",
          "message": "Merge pull request #87 from ThreatFlux/fix/clippy-warnings-code-quality\n\nfix: resolve clippy warnings and improve code quality",
          "timestamp": "2025-09-04T20:48:22-04:00",
          "tree_id": "191fcf55f325e0d341872a2685e3d9f2f30b810a",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/da0c7d6e8a71e24ba2c014b0b086259e8636a4f4"
        },
        "date": 1757034809129,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2663344.090526315,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 310003.91860624845,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2148350.219583333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32586.820367287677,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2600422.8224999993,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4979.137002454783,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40486.31021299387,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76519.99619560395,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237593.61499058432,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3319941.653125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2213661.6656521745,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52893.631355916805,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "47ad6db6ea4560e9070218a99c7c341ac70de7d5",
          "message": "Merge pull request #88 from ThreatFlux/main",
          "timestamp": "2025-09-05T01:30:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/89/commits/47ad6db6ea4560e9070218a99c7c341ac70de7d5"
        },
        "date": 1757042031557,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2663118.248421052,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316890.7347594461,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2150602.6470833337,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31694.521486711194,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2637530.911499999,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4989.639851106297,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 39632.81737558206,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76615.27434503296,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237749.39923120383,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3309338.48375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2176347.327826087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51185.542556714,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c07771ee5692f9a977bd53658a5b966ee1484ca5",
          "message": "Merge pull request #89 from ThreatFlux/fix/clippy-warnings-code-quality\n\nMerge pull request #88 from ThreatFlux/main",
          "timestamp": "2025-09-05T13:45:01-04:00",
          "tree_id": "b97f3a71b2066a3f56bd42e5dd2dcf0ec8d5df9c",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/c07771ee5692f9a977bd53658a5b966ee1484ca5"
        },
        "date": 1757095796053,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2655645.071052632,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 311299.8585508198,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2152176.97125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33185.35248667458,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2631528.8995,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4983.668502297682,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38258.96668873828,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74734.04919850359,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237656.50818890324,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3309696.20875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2188954.0226086956,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52106.270209548355,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "6c8d8b02a9f01721773fe964115e4af14b913279",
          "message": "chore(release): bump version to 0.2.6\n\n  Auto-generated release commit",
          "timestamp": "2025-09-05T18:30:39Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/6c8d8b02a9f01721773fe964115e4af14b913279"
        },
        "date": 1757216643398,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2648326.0721052624,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 304192.9839274122,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2143228.1829166673,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 30900.29052511028,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2602726.5105,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4997.298599145106,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37732.8305298365,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 73136.87548612994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236507.9374244679,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3290467.55625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2191321.9269565213,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50044.35863683114,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "6c8d8b02a9f01721773fe964115e4af14b913279",
          "message": "chore(release): bump version to 0.2.6\n\n  Auto-generated release commit",
          "timestamp": "2025-09-05T18:30:39Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/6c8d8b02a9f01721773fe964115e4af14b913279"
        },
        "date": 1757821520461,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2647018.1221052613,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316082.5973463098,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2166447.867083332,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32073.83955320604,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2630025.0473684217,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5016.3542928251045,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40278.84608178238,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76734.9086995014,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237725.62764730406,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3317912.955625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2159816.318260869,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51000.58429543096,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "84232b9d1809f4e727d86a9155c140869ead92f3",
          "message": "deps: update dependencies and fix code quality issues\n\n- Update Rust dependencies in Cargo.toml:\n  • serde: 1.0.219 → 1.0.223\n  • chrono: 0.4.41 → 0.4.42\n  • addr2line: 0.25.0 → 0.25.1\n  • tempfile: 3.21.0 → 3.22.0\n  • zip: 4.5.0 → 4.6.1\n  • uuid: 1.18.0 → 1.18.1\n  • clap: 4.5.46 → 4.5.47\n  • yara-x: 1.5.0 → 1.6.0\n\n- Update GitHub Actions dependencies:\n  • actions/checkout: v4 → v5\n  • actions/setup-node: v4 → v5\n  • docker/build-push-action: v5 → v6\n  • lewagon/wait-on-check-action: v1.3.4 → v1.4.0\n  • aquasecurity/trivy-action: 0.32.0 → 0.33.1\n\n- Fix code quality issues:\n  • Rename similar variables in call_graph.rs for clarity\n  • Improve pattern matching in disassembly.rs\n  • Add separators to hex literals in entropy_analysis.rs\n\nAll tests pass and code compiles cleanly with no warnings.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T01:11:36-04:00",
          "tree_id": "e2ed00caa1bc4c77c885d9c44df65a8ce68a11ec",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/84232b9d1809f4e727d86a9155c140869ead92f3"
        },
        "date": 1758173864877,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2646846.22,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 312708.3905587897,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2147303.895833333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32745.081248578947,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2630105.101578948,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4987.013143112651,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 39994.87312930542,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76122.57590827873,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237717.27432021347,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3193392.190625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2192848.626956521,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50682.153407529695,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "c1b76fc9589da844f52c7e30b30fce6efe3d6460",
          "message": "fix(ci): update GitHub Actions to use version tags instead of SHAs\n\n- Replace outdated SHA-pinned actions with stable version tags\n- Fix github/codeql-action SHA that was causing workflow failures\n- Update docker/* actions to use v3/v5/v6 version tags\n- Replace actions/checkout SHA with v5\n\nThis resolves the security scan failure in PR #213 where the\ncodeql-action SHA f779452... no longer exists.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T01:26:00-04:00",
          "tree_id": "011ad4b4b8d785197a28c3bbc4edccd576cf12eb",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/c1b76fc9589da844f52c7e30b30fce6efe3d6460"
        },
        "date": 1758174674439,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2644424.085263158,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316484.45420785417,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2142752.5549999992,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31129.609865382263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2664123.4300000006,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4990.096309556914,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38027.87000863809,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75143.4942618473,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236295.37057960324,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3294853.319375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2184236.5639130445,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50049.67159699033,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "2f3312d20d5c552b8695167cefe49895fa20d4ef",
          "message": "fix(ci): improve Trivy scan error handling in Docker workflow\n\n- Add continue-on-error to Trivy scan step to prevent job failure\n- Add SARIF file existence check before upload attempt\n- Only upload SARIF results when file is successfully generated\n- Add debugging output to show SARIF file status\n\nThis fixes the \"Path does not exist: trivy-results.sarif\" error\nthat was causing the security scan to fail when Trivy couldn't\ngenerate results.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T01:39:30-04:00",
          "tree_id": "3a6a53f910592d4a055efeb1e1956d4ff8188eab",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/2f3312d20d5c552b8695167cefe49895fa20d4ef"
        },
        "date": 1758175633164,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2684321.296842105,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 312868.06196546345,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2165956.6175,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31612.432481094824,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2638470.984736842,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4984.931781780111,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38431.519947732915,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74991.10285227594,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239962.35021356237,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3314066.600625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2224797.7791304346,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50880.209837453185,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "9c163362ff6652e2dbb33741e121a65bf5679742",
          "message": "fix(test): fix Windows cache test failure with platform-specific invalid paths\n\nThe test_cache_with_invalid_path test was failing on Windows because\nthe Unix path \"/dev/null/invalid\" behaves differently on Windows.\n\nChanges:\n- Use conditional compilation to provide platform-specific invalid paths\n- Unix: \"/dev/null/invalid\" (existing behavior)\n- Windows: \"C:\\\\invalid<>:\\\"|?*path\" (path with invalid Windows characters)\n\nThis ensures the test validates error handling for invalid paths on\nboth Unix and Windows platforms correctly.\n\nFixes the CI/CD failure:\nassertion failed: result.is_err() in cache_creation_tests::test_cache_with_invalid_path\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T10:11:44-04:00",
          "tree_id": "70cddaa416b52fe92567c6900f10fd627fe0897f",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/9c163362ff6652e2dbb33741e121a65bf5679742"
        },
        "date": 1758206294356,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2764835.22631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 328481.72523861885,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2203705.7613043482,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31737.212650048994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2768168.551666666,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5003.054027040973,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38911.569087579126,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76495.29154132608,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239193.793679786,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3297358.285333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2154646.029565217,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51021.63873268415,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "f2bde9f8ef3775559f65762893e023b28a4fdd0a",
          "message": "fix(ci): fix auto-release workflow tag and checkout issues\n\n- Add release_sha output to version-bump job to track commit SHA\n- Use commit SHA instead of tag reference for checkout operations\n- Add tag verification step to ensure tag exists before release\n- Fix timing issues where jobs tried to checkout non-existent tags\n\nThis resolves the \"Unexpected error fetching GitHub release for tag\nrefs/heads/main\" error by ensuring proper tag creation and checkout\nsynchronization in the release process.\n\nChanges:\n- Output release SHA after tag creation\n- Replace tag-based checkout with SHA-based checkout\n- Add verification step for tag existence\n- Improve error handling and debugging\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T16:24:21-04:00",
          "tree_id": "da9eee3954e46460a5bebac2f28cb5386e6775f2",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/f2bde9f8ef3775559f65762893e023b28a4fdd0a"
        },
        "date": 1758228587932,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2759844.2036842112,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 321329.2964242989,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2199196.18,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31912.15621372469,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2734832.5968421055,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5065.316839764335,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38631.494382893245,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76338.46726868358,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237161.15559108078,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3372014.2919999985,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2215508.4565217393,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50634.6936076358,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "1106cec4ff9bf6f34b5be1fc9aa8269f478168e0",
          "message": "feat: enable threatflux-binary-analysis integration\n\nEnable the threatflux-binary-analysis library integration to provide\nenhanced binary analysis capabilities beyond the current goblin-based\nimplementation.\n\nChanges:\n- Enable threatflux-binary-analysis v0.2.0 dependency with serde-support\n- Uncomment and activate ThreatFlux analyzer integration code\n- Implement hybrid approach: ThreatFlux primary, goblin fallback\n- Fix tests to accommodate ThreatFlux's enhanced format support\n- ThreatFlux can analyze Raw/Unknown formats where goblin fails\n\nEnhanced Capabilities Now Available:\n- Better format detection and parsing\n- More resilient analysis of non-standard binaries\n- Enhanced import/export extraction\n- Improved section analysis with detailed permissions\n- Advanced architecture detection\n\nIntegration maintains backward compatibility with existing API\nwhile providing significantly enhanced analysis capabilities.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T18:08:12-04:00",
          "tree_id": "553c8cbf33cc7091d36f17ffd63169b4d6bdd7fe",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/1106cec4ff9bf6f34b5be1fc9aa8269f478168e0"
        },
        "date": 1758234835810,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2776343.8468421055,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 323550.03467049,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2217721.5147826085,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32332.34987497719,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2740380.0873684203,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5344.979807636244,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40349.77014920237,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 78352.6019894448,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238834.00038892965,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3410338.137333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2209367.027826087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51971.06074255152,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "9192684934edc3217c9bef5777fc307b0965617b",
          "message": "feat: enhance threatflux library integrations\n\nComplete integration improvements for owned ThreatFlux libraries:\n\nString Analysis Enhancements:\n- Fix threatflux-string-analysis integration by removing test ignores\n- Enable basic string tracking test (now working)\n- Keep file hash filtering test ignored (needs library enhancement)\n- 19/20 string tracker tests now passing\n\nCache System Integration:\n- Enable threatflux-cache v0.1.8 dependency\n- Disable openapi feature temporarily (utoipa version conflict)\n- Prepare for future cache migration to leverage:\n  • Multiple backend support\n  • 10x performance improvements\n  • Distributed deployment capabilities\n\nIntegration Status:\n✅ threatflux-binary-analysis: Fully enabled and working\n✅ threatflux-string-analysis: Enhanced integration (95% working)\n✅ threatflux-cache: Available for future migration\n✅ threatflux-hashing: Already integrated\n\nNext Steps:\n- Update threatflux-cache to use utoipa 5.4.0 for full feature support\n- Enhance file hash filtering in threatflux-string-analysis\n- Plan cache migration strategy for performance optimization\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T18:25:25-04:00",
          "tree_id": "9ef34338e02a0b2ebe1353d7ade438ffff845639",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/9192684934edc3217c9bef5777fc307b0965617b"
        },
        "date": 1758235853233,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2770298.9615789484,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316599.8424662214,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2218775.279565218,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 30715.691710529827,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2602141.314210526,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5495.058773320282,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37789.14314464422,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74335.72996730435,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235641.329394879,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3371305.4999999995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2152370.826666666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49983.68918705375,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "Wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "distinct": true,
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T18:56:54-04:00",
          "tree_id": "0fd4ca62060438a72ef5fa29004ad90c7a41a60f",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1758237765223,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2782754.7363157896,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 326179.511912042,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2223629.6221739124,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32361.938671906344,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2740445.532105263,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5461.118969557532,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40445.54052562429,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 79891.07791094802,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236716.15612813368,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3407618.689333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2201919.837391304,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50976.3799901763,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1758426514799,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2818330.3177777785,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 319446.93964229396,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2200698.428695651,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 30300.2645132412,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2720157.607368421,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5499.951372818298,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38253.51109664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76189.30445357427,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236086.04876882755,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3252597.435625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2199396.693913044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49763.08433688509,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1759031378029,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2772088.370526315,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 321832.8936712011,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2212150.4186956524,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32350.387293298507,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2752292.5821052627,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5514.498491913162,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 39115.85721190342,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 77135.31423642043,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237085.7132001454,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3348404.6166666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2203062.5960869566,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50773.93244048946,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1759636237828,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3158430.1775,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 386605.39554684825,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2744663.8063157885,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 29163.525765815382,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3103515.744375,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2643.6502944432577,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34316.90303845179,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 77628.20061831012,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 223993.09116267238,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3991414.3392307693,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2036921.232,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47960.016391481346,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1760240852519,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2779014.651578948,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 313950.9454006866,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2214702.6217391305,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31314.38536500776,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2727795.213684208,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5730.153451346257,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37879.96690058901,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75564.985741285,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235757.27410858806,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3382005.537333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2186088.5173913045,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49820.82878704811,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1760845969872,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2817740.0138888895,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 328897.36600756156,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2246612.673478261,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33826.190440158534,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2752670.816315789,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5523.205192789681,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 41983.4807459298,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 79530.30571191345,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 241242.52525265465,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3415781.8446666677,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2198275.427826086,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 53199.41157991833,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1761450644391,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2767793.6238888893,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 325240.64139831834,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2208889.4543478256,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32420.716875759157,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2743352.5515789473,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5496.048876018713,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40128.76976901944,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 78277.01203261361,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237483.74091074214,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3406094.792666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2207343.0179166654,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50633.28421080552,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1762055602980,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2663524.372105263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 321103.8045082527,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2165495.4275,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31975.430662353574,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2682889.6147368434,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5471.126774162399,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40398.681331422624,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76255.66751261218,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237787.89014652514,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3344010.221999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2202000.706086956,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51253.17988199512,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1762660310451,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2643001.1694736844,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 319786.1619592139,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2165559.1620833334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32789.5191929629,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2641831.0194736845,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5520.866298409533,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43587.8724608615,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 80381.76155719243,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236747.33096699486,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3357492.611333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2210720.633913043,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51816.12557010757,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1763265331184,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2659410.921052633,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 314401.1536615952,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2152480.5824999986,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31402.08259874639,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2632121.738421052,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5444.473507345695,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38352.4518112232,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75555.48240556094,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 240572.47736149165,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3324627.27,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2194037.7399999998,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50767.66987513123,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1763870406359,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2810307.7178947367,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 318051.8071519288,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2165090.168333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33090.835613517294,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2610814.4060000004,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5453.657766089882,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 44196.75867051333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 81545.71735763493,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 240194.15842211925,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3316777.423999998,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2199981.5378260864,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51993.536860169144,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1764475194636,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3193757.328235293,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 369546.19938798965,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2679397.4147368423,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 26953.843128279634,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3031002.0070588235,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2632.3620039980988,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 33174.06778973384,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 69779.94064024634,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 216659.74110716832,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3758927.9242857145,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1968696.3552777355,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 44525.48600205267,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1765080029735,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2678006.1831578957,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 317452.47736918024,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2159867.339166666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31648.78325308703,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2658924.6805263166,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5462.591139631264,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38843.90571782687,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75264.92840168558,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237721.74266762994,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3326738.00375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2230606.545217392,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50294.73877099157,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1765684812803,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2664980.012105264,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 315539.7544490846,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2174991.5929166665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32520.98988616016,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2647827.434210526,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5457.869964799724,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40194.407912200375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76660.30824541533,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239046.40444458707,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3330917.06125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2200296.132608696,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50798.089725501944,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1766289644201,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2664467.353684211,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 314628.96657194657,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2174961.4273913037,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32994.4892454342,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2641471.7065000003,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5532.598479408028,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 40411.21513808592,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76819.15542906387,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237487.7268919171,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3341603.0666666664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2205387.4147826075,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51211.388602884166,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1766894549036,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2653276.691052632,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 312169.5191046197,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2157072.4633333324,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31167.331850334136,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2647500.7773684207,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5418.764768082275,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38130.22869560866,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74782.8213449114,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235427.3246137796,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3301305.65875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2179216.979130435,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49709.40647850966,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1767499379990,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2669404.875263157,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 308624.2820366004,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2168169.7300000004,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31145.61363981735,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2620464.2825000007,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5462.227093887811,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38721.233363683845,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 72626.31913562812,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237118.78074673947,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3150506.309375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2237865.9865217386,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50201.75198512269,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1768104231634,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2698444.3394444436,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 314061.97118347185,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2202619.4734782614,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32307.377945099877,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2603807.8760000006,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5465.318843519349,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43199.63251545806,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76435.64179980602,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238738.78086120065,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3401546.2813333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2234457.6404347825,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51914.55647214204,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1768708943966,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2686315.3147368417,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 314238.9629806945,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2173169.472173913,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31755.834893669024,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2664335.5636842097,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5484.3283380274315,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 38775.18630841177,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75345.94326708232,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236929.31442494373,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3315359.0175,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2204884.6704347827,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50869.55133677365,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1769313930548,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2737345.6505263164,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 326857.550221662,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2206299.1334782606,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32776.43678772663,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2707721.6842105263,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5399.580127322195,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43555.79548802596,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 82970.95740138233,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 241098.86296426159,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3432672.9733333327,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2223931.508260869,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51781.572176089045,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1769919947384,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2725001.577222222,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 327240.1048042583,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2216363.751304348,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32898.753950040395,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2716117.344210526,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5484.276734231967,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43623.84620239367,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 81878.44233672056,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 244446.91643406634,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3446351.258,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2215293.58826087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52259.562235868514,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1770524825048,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3148573.34625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 364061.5613485771,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2644658.62,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27439.88589968833,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2997748.7411764693,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2628.502784491857,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 31427.4406586164,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 66894.62180921072,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 216124.76099387064,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3741874.973571428,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2105919.405999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 43277.67057843903,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1771129129063,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2687376.6368421046,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 323804.24409978813,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2285471.467727273,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35212.21612207906,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2687668.053157894,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6758.947133254376,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45089.695767771285,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 80556.5590188001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 248184.3268583385,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3432277.916666668,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2269556.3913636366,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55085.956322446444,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1771733786700,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2626175.382631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 317450.2189543103,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2167077.967083333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32592.843794110035,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2623510.4989999994,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5537.377270706031,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43453.81072076738,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 83698.03565732438,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 241931.56522398908,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3229622.23875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2240541.94826087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52254.18187841461,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1772338864343,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2746997.653333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336611.2749895536,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2343965.325,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35865.577056333226,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2710088.544736843,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6855.324733000191,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 46248.48233228695,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 78598.48212344453,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 253354.9448111226,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3307800.7133333324,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2293700.9936363623,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56655.83171013073,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1772943278351,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2728548.55631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 327450.3026318624,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2304783.4809090914,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 34970.093199770934,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2719234.8642105265,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6784.2648113321075,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 46439.905514824306,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 81019.3012888496,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 246192.97716594776,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3443410.672,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2268818.4486956517,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54457.47139914301,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1773548752083,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3139438.46875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 360286.1655863417,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2878863.557777777,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35893.528822074746,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2973951.4123529415,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 8595.064575078484,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49336.03834102778,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85927.00594302824,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 274718.53101600776,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3950057.303846155,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2553807.1234999998,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57623.24731984641,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1774153065165,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2705366.1531578936,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 332000.4422648376,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2335145.141818182,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35944.15444547702,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2713634.9478947367,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6809.639868739599,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50236.41732204962,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85269.87082034576,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250455.40690054162,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3509369.024666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2235962.713913044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56538.96527934962,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1774758496982,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2661317.0142105264,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 344677.10792608274,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2414162.4385714284,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38892.26503628248,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2701088.9863157906,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5582.818416788728,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48124.690753042465,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86070.40266224577,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 247844.45752848656,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3353944.3926666672,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2215494.031739129,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57880.16705518923,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "committer": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "Wyattroersma@gmail.com"
          },
          "id": "40f94142805ca1c2586c3c5c1079075612e0e3f2",
          "message": "feat: prepare threatflux-cache integration foundation\n\nAdd threatflux-cache v0.1.8 as dependency and prepare the caching\ninfrastructure for future migration to leverage enhanced performance.\n\nChanges:\n- Enable threatflux-cache v0.1.8 dependency\n- Prepare cache.rs structure for future ThreatFlux backend integration\n- Add migration planning infrastructure\n- Maintain full backward compatibility with current cache API\n\nCurrent Status:\n- threatflux-cache dependency available and compiling\n- All 40 cache tests passing (100% compatibility maintained)\n- All 952 total tests passing with enhanced ThreatFlux ecosystem\n- Ready for future implementation of 10x performance improvements\n\nNext Steps for Full Migration:\n1. Update threatflux-cache library to use utoipa 5.4.0\n2. Implement async cache backend integration\n3. Add multiple backend support (memory, filesystem, distributed)\n4. Performance benchmarking and optimization\n\nFoundation is now ready for advanced caching capabilities while\nmaintaining current functionality and reliability.\n\n🤖 Generated with [Claude Code](https://claude.ai/code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
          "timestamp": "2025-09-18T22:56:54Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/40f94142805ca1c2586c3c5c1079075612e0e3f2"
        },
        "date": 1775363296693,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2661715.931052631,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 335042.3811997117,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2420967.6085714283,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39510.92214854862,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2654435.034210527,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5403.835451487135,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48733.669347515235,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86889.74757578758,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 249688.44138034957,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3370061.4200000013,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2245086.588695652,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58187.35625664636,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "69c82c85c2f1f69ff5b916b3ad3ffc3343d5b173",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/69c82c85c2f1f69ff5b916b3ad3ffc3343d5b173"
        },
        "date": 1775510673593,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2711777.885263158,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 329772.2253108958,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2373351.448181818,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 36735.36179488475,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2641229.1152631585,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5585.741329140707,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43179.18476991323,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 77187.4693903693,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 246329.4920196813,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3249459.5425,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2240697.549565217,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55909.90981216181,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "b6a123e57e1913ec560029457db9205b72893817",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/b6a123e57e1913ec560029457db9205b72893817"
        },
        "date": 1775511232037,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2678706.615263158,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 326640.8637232872,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2371510.3868181817,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 37676.95130835389,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2646022.514210527,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5630.686437610986,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42920.72155846507,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75641.9153027273,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 244792.2260913154,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3232707.074375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2241703.222173913,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54809.84116456123,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "5549b3ed055c781a32dc939efc368a202c3c8d4d",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/5549b3ed055c781a32dc939efc368a202c3c8d4d"
        },
        "date": 1775511431959,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2251507.5213043476,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 270483.05968248076,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2011855.2875999992,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 25811.169478801745,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2225505.18,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5181.26018504695,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32902.51244972394,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 61984.89984033873,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 206606.68378926616,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2682346.2915789476,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1894600.3475925403,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 42706.621049222864,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "45ff93da6079698adbedc9028933ebbef0772bc9",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/45ff93da6079698adbedc9028933ebbef0772bc9"
        },
        "date": 1775511538071,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2697090.22631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 327159.9401763108,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2375282.214090908,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35568.82472285648,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2647714.6868421067,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5579.267654867303,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42770.47879576716,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76387.56931693923,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 243790.41143859547,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3282872.183125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2209644.357826088,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55608.520991232115,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "2a06694372e93ec2d1eaac0898c0c24e92810bcd",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/2a06694372e93ec2d1eaac0898c0c24e92810bcd"
        },
        "date": 1775512216584,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3276377.18,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 422885.9786244739,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 3083792.2405882333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31774.608054176675,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3169784.098125,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2797.9306484715767,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34034.91598103609,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 72328.41085840615,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236379.56322547366,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3974070.993076923,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2064610.1356,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48273.621259775966,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "601a30bbc3247614b4f8834b85d021371a0af75b",
          "message": "[codex] Roll up Dependabot updates",
          "timestamp": "2026-01-29T08:57:53Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/125/commits/601a30bbc3247614b4f8834b85d021371a0af75b"
        },
        "date": 1775512393809,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2717341.654736842,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 337304.1223369646,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2371144.6927272724,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 36794.24492129511,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2709317.7010526317,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5599.566308622907,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42584.329820229745,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76904.9933629418,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 246574.07562554427,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3252391.92625,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2209547.0604347824,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54897.37315379975,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T00:57:49-04:00",
          "tree_id": "66eb482a19713375fe4ada126ca63ef388b5e602",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1775539379528,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2646302.465263157,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 329266.4902683875,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2393533.5857142853,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39210.375290166616,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2656855.1673684213,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5518.113559593288,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48110.931401238544,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85695.5243781621,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 247361.77823962382,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3339226.6613333337,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2262513.5591304344,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58255.94066522103,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1775968289558,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3087585.3317647045,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 376188.76922006294,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2930066.499444444,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27493.082550226034,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3061187.302941177,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2773.444088900582,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32044.593790288694,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 68792.23580319669,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 218599.35392273407,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3742857.9821428577,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2157618.97875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 44592.80623130822,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1776573172552,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2696111.2426315797,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 335778.9224687674,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2429405.077142856,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39251.92425192104,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2704214.619999999,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5640.744475308879,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47914.70148838946,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85942.1882109437,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 246663.61652529045,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3403009.662666665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2212398.4834782616,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58319.43039493505,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "75e57699a3d70e3f6d59f477897e8082d9a0aeae",
          "message": "[codex] Roll up Dependabot and security updates (2026-04-23)",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/126/commits/75e57699a3d70e3f6d59f477897e8082d9a0aeae"
        },
        "date": 1776932607324,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3157191.429375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 378330.2469495304,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2869487.0111111104,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28004.863973879103,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3049747.7052941173,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2809.925708892771,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 30925.561412108236,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 68360.36678878123,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 217603.9567974074,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3763227.9228571444,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2082726.5596000003,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47072.56587718664,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "c70924b0ac015c36165ccb331005984c64b78e6b",
          "message": "[codex] Roll up Dependabot and security updates (2026-04-23)",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/126/commits/c70924b0ac015c36165ccb331005984c64b78e6b"
        },
        "date": 1776934221915,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2920418.3738888893,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 350918.3030105157,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2616598.1525,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33191.09532730948,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2926745.2877777773,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6605.493162137707,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 41024.05294172526,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 80505.20385411361,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 267867.3851812579,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3426923.513333332,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2439267.9757142854,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54181.81911472445,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1777178046190,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2272198.8813043474,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 270106.16904869565,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2039339.9324,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 24918.10503059532,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2270977.5891304347,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5106.366082706978,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32592.414595990707,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 61475.75043252722,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 206870.7240384723,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2671331.1221052636,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1891598.466795721,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 42020.00184350162,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "cd0cb70cf944264133a7b652c2f4d9ee65f0ff51",
          "message": "[codex] Roll up Dependabot and security updates (2026-04-23)",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/126/commits/cd0cb70cf944264133a7b652c2f4d9ee65f0ff51"
        },
        "date": 1777519866448,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2691836.565263158,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 342285.51000441774,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2400304.171904761,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38679.93051578514,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2694823.9742105263,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5594.313304613664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48928.48624664548,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 84198.3452419822,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232481.95153028943,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3355573.0933333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2092419.7863999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55973.99191730419,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "c51648db1649bfe73f2d99ac22459998da625015",
          "message": "chore: use rust-cicd-template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/143/commits/c51648db1649bfe73f2d99ac22459998da625015"
        },
        "date": 1777648062055,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2691789.0426315796,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 334896.2568403377,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2405319.6366666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38562.82833324937,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2691565.469473684,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5705.518358147675,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49960.561727351844,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86371.77084542584,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 233621.09331767616,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3366471.816666665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2031845.2303999993,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57876.759258798345,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "059a60c3c057f4479adb8b3faa676f4e38818599",
          "message": "chore: use rust-cicd-template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/143/commits/059a60c3c057f4479adb8b3faa676f4e38818599"
        },
        "date": 1777648267368,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3106816.2417647056,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 382713.0093074881,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2908612.567222222,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 29317.901798513773,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3042290.5758823534,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2774.3109741174762,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 36536.89748533888,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 73182.69573856995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 210158.11607604273,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3827432.8600000013,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1916660.927819191,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 45500.866282758674,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "aaeed8d95c4b67153b19ae33d417faf8a89f8a05",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/aaeed8d95c4b67153b19ae33d417faf8a89f8a05"
        },
        "date": 1777652308349,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2778820.172222221,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 343959.4448797126,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2445560.7819047607,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39035.16952257676,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2652008.4500000007,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5738.335525497665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49520.74855499099,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85515.24444282315,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 233113.0177609513,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3440591.432000001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2062150.1668,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56072.892290930155,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "b04ab80dc7befe4e0ef67f096a471235f7d5b06c",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/b04ab80dc7befe4e0ef67f096a471235f7d5b06c"
        },
        "date": 1777654458159,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2923656.297222223,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 352565.47577704536,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2629037.2260000017,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32606.214865103335,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2947562.680555555,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6542.307142062157,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42930.53535351524,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 82253.78416026887,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 251117.60800915907,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3508415.8006666666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2287604.129545454,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51802.34552586195,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "6012e3f83c72d0b8177f34d5f1c110cf06e54965",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/6012e3f83c72d0b8177f34d5f1c110cf06e54965"
        },
        "date": 1777655007126,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2783460.701111112,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 350878.2325111802,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2449120.6666666665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38297.895771016345,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2779096.207894738,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5549.701653057765,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49589.13493175301,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87792.4006562871,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232731.40786789206,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3453120.278666666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2042070.6455999997,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55553.84488644809,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "0f27a550ed06d8941305d16a184adc36a834b348",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/0f27a550ed06d8941305d16a184adc36a834b348"
        },
        "date": 1777655771633,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3008536.4188235295,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 354487.8599016144,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2609942.8744999995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31304.774253572697,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2956689.592941177,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6533.02538817469,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42871.769523749055,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 82589.8014426864,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250358.4389510677,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3473417.7100000014,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2276327.0469565224,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 53652.446360784284,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1777783696244,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2916149.2077777786,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 350632.71878506796,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2622764.856,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32176.817958371725,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2906992.5594444447,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6536.149974057154,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42208.080723133644,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 80701.9090979347,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 267358.9914610859,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3432738.6766666668,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2439990.4295238093,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 53647.6049091654,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1778388697342,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2706218.1900000013,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 341221.2627557657,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2432650.332380953,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39828.78618852127,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2707806.9315789468,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5675.370906993247,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48616.83874393485,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86194.14980263867,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250983.34844226434,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3362692.438666665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2221389.8008695655,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57839.53753232324,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1778993617883,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2918028.3466666657,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 346460.55267161905,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2410177.4142857147,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31862.625560282926,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2956785.638823529,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6465.67825034776,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 41804.76106626099,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 81874.78277062895,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 266170.849393535,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3540148.0346666663,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2452044.252380952,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 53880.90932108392,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "71146fdc2902112ff864f23d777a98ec34446c07",
          "message": "Merge pull request #125 from ThreatFlux/codex/dependabot-rollup-20260406\n\n[codex] Roll up Dependabot updates",
          "timestamp": "2026-04-07T04:57:49Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/71146fdc2902112ff864f23d777a98ec34446c07"
        },
        "date": 1779598658949,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2689096.403684212,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 335653.6397028698,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2219117.8269565217,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38602.74833534269,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2708971.2926315786,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5532.023499558613,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47365.92865114829,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87394.7647018791,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 246332.02129823013,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3439699.6413333328,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2216891.542173913,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57244.16666922005,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "dd8f9cae7f36f3355fa9f21f3a1b486b95bc6965",
          "message": "deps(deps): bump md-5 from 0.10.6 to 0.11.0",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/134/commits/dd8f9cae7f36f3355fa9f21f3a1b486b95bc6965"
        },
        "date": 1779657432994,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2921474.164705883,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 350339.74418439536,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2401896.0799999996,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32845.887462026716,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2968970.203529411,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6526.036030324309,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 44584.17687839014,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 84564.31640461586,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250317.89222467353,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3682766.21,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2267385.315217391,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 53018.42835132386,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "eaadd9b0e9c33d53295838c6dd49aa9a6de97edd",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/eaadd9b0e9c33d53295838c6dd49aa9a6de97edd"
        },
        "date": 1779658717219,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2801532.8816666664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 345348.26493682206,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2234432.6739130444,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 37951.86461001277,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2799412.0705555556,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5721.2633254277725,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48660.73234277875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 90547.98356406346,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 234562.2933545771,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3564771.065999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2081775.1829166654,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54815.74073017374,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "772ba8d415cd906823bc6ae543e50868208cf5bb",
          "message": "chore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-04-07T04:57:56Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/144/commits/772ba8d415cd906823bc6ae543e50868208cf5bb"
        },
        "date": 1779681527338,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2792030.682777779,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 337863.47680948576,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2239766.9373913044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39308.51059076297,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2754474.3563157897,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5557.09505796568,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47087.593370407,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 85797.8474683846,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 231527.95237192084,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3464023.224,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2050731.244,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57001.242631471294,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "0a23be144e1dd3624a75cbde9ac3f18675648284",
          "message": "Merge pull request #144 from ThreatFlux/chore/rust-1.95-and-deps\n\nchore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-05-30T20:10:36-04:00",
          "tree_id": "323480d14672e253308e365c896fe97d6c2db59b",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/0a23be144e1dd3624a75cbde9ac3f18675648284"
        },
        "date": 1780187821613,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2709796.066842106,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 337139.12059184804,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2284095.7109090905,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 37858.92079311436,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2702549.700526315,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5557.011413965045,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48423.08683740101,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86599.25317469065,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 231470.18552377203,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3381238.285999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2048204.3264000004,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55767.02082698173,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "0a23be144e1dd3624a75cbde9ac3f18675648284",
          "message": "Merge pull request #144 from ThreatFlux/chore/rust-1.95-and-deps\n\nchore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-05-31T00:10:36Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/0a23be144e1dd3624a75cbde9ac3f18675648284"
        },
        "date": 1780203668243,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2729740.701052632,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336531.72197617695,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2297391.734545455,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39334.7252057333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2662268.763157894,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5666.601231246064,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49498.832264704855,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87852.88657677818,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 234911.62431248385,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3359047.2573333317,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2087916.6654166672,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57160.33970945338,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Wyatt Roersma",
            "username": "wroersma",
            "email": "wyattroersma@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "0a23be144e1dd3624a75cbde9ac3f18675648284",
          "message": "Merge pull request #144 from ThreatFlux/chore/rust-1.95-and-deps\n\nchore: migrate to Rust 1.95.0 and template base image",
          "timestamp": "2026-05-31T00:10:36Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/0a23be144e1dd3624a75cbde9ac3f18675648284"
        },
        "date": 1780808495994,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2739739.1963157896,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 335436.6801788559,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2300823.79909091,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39121.8903255484,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2667602.3768421058,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5682.9231836942945,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49897.127512006846,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87949.11773632086,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 234125.55158592746,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3417549.942666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2047225.4528000006,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56675.48719363373,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "7f8ad96393a7855a12f3f9b59b13555841009092",
          "message": "[codex] use rust docker template 1.96",
          "timestamp": "2026-05-31T00:10:42Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/147/commits/7f8ad96393a7855a12f3f9b59b13555841009092"
        },
        "date": 1781326624777,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2725081.8442105264,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 342389.83250127063,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2289288.0581818176,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 37784.652365995855,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2707721.352631579,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5521.91602624606,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50085.4201036586,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88164.20704120415,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236928.31177084672,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3402071.6726666666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2062182.2959999994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58854.00438267638,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "d6a99e366688a93758769af29af859d2fe160f61",
          "message": "[codex] use rust docker template 1.96",
          "timestamp": "2026-05-31T00:10:42Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/147/commits/d6a99e366688a93758769af29af859d2fe160f61"
        },
        "date": 1781327060861,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2736584.310526316,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 340669.3637091089,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2321330.0172727266,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 40339.08234997764,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2717442.3721052636,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5656.995611290432,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50954.27911849653,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 90422.39927525468,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232393.11880073513,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3412685.0439999993,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2085210.7063999998,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56826.22370821454,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "52627b62c98deb1bf473d069a4b5d0a49ee17933",
          "message": "[codex] use rust docker template 1.96\n\nSquash merge PR #147.",
          "timestamp": "2026-06-13T10:43:57-04:00",
          "tree_id": "8a1aaa00ba29336bb2eca0ed8b140c8479d4aa44",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/52627b62c98deb1bf473d069a4b5d0a49ee17933"
        },
        "date": 1781363468594,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2943202.4161111102,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 349662.7107040361,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2483234.7671428574,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32394.138463379717,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2964935.132777779,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6603.483457340459,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45390.78840125894,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 83712.76693802555,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250930.41045287825,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3513730.794666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2270192.381304348,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52927.72022983611,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "85826dab986d152c6fce2770235c1d183cab0de4",
          "message": "[codex] fix auto-release workspace version bump",
          "timestamp": "2026-06-13T14:44:03Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/148/commits/85826dab986d152c6fce2770235c1d183cab0de4"
        },
        "date": 1781366141451,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2718704.5936842095,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 335643.8942428231,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2278149.2950000004,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38822.61471706976,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2731644.7210526313,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5562.114412907445,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48121.39211230047,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 84667.27427391277,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232726.92955720695,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3356882.3899999987,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2059596.6523999996,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58132.52312879936,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "0aec301a1d7001b74b4ce93afea78817dfd6c2c6",
          "message": "[codex] fix auto-release workspace version bump",
          "timestamp": "2026-06-13T14:44:03Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/148/commits/0aec301a1d7001b74b4ce93afea78817dfd6c2c6"
        },
        "date": 1781367345252,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2743191.860000001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 338658.65379824134,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2292307.5795454546,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39193.84930320779,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2706623.055789473,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5527.892462432921,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50589.0579005873,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87221.70238278287,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232703.1491121858,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3342752.9206666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2072347.1944,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56469.39581499654,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "63cfa87daac0d9d40817b1600402bfef7a3652c8",
          "message": "[codex] fix auto-release workspace version bump\n\nFix main CI/CD after PR #147 by replacing cargo-bump with workspace-safe version update logic and making integration cleanup tolerate a missing target directory.",
          "timestamp": "2026-06-13T12:40:51-04:00",
          "tree_id": "396bcff9f5ee7ff0680fdd6fc0bfcddd1f8fc369",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/63cfa87daac0d9d40817b1600402bfef7a3652c8"
        },
        "date": 1781370029617,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1679051.9621739713,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 185478.40918661494,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1391950.7357742828,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 22690.64155021456,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1631997.244180871,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 4323.321513972665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 26411.420001842132,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 44348.52781520936,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 160106.15565106698,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 1885098.2753778375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1471202.7849974742,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 36436.80754241283,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "073104c8397c4df5a9b9ff46270680e258f9c37b",
          "message": "[codex] fix auto-release Rust target install",
          "timestamp": "2026-06-13T17:21:48Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/149/commits/073104c8397c4df5a9b9ff46270680e258f9c37b"
        },
        "date": 1781390596783,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2741900.239473685,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 338906.4224679174,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2289458.581818182,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39492.56173850665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2715578.721052632,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5638.223208769169,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50294.41244760333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 89604.29703744769,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232957.34984460115,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3393611.0053333337,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2078096.961999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56683.678816348256,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8df1bfa6241d077597ca524683f29f5348256b71",
          "message": "fix auto-release rust target install (#149)",
          "timestamp": "2026-06-13T19:04:51-04:00",
          "tree_id": "701c63cf952b57acc399a6ae0e1096d40a78cb74",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/8df1bfa6241d077597ca524683f29f5348256b71"
        },
        "date": 1781393478785,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2734067.01631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 338616.64547453186,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2341845.287727273,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39598.27902526698,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2710190.4431578945,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5555.177840861025,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50026.55485346208,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88559.67809284698,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 233426.30811574913,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3462469.0633333325,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2070178.2703999986,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56578.478593464315,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "b6b5144e26b114901d3f9c1e491048e456c510b4",
          "message": "[codex] gate crates publish for local dependency",
          "timestamp": "2026-06-13T23:45:05Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/150/commits/b6b5144e26b114901d3f9c1e491048e456c510b4"
        },
        "date": 1781402088070,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2730221.1352631585,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 340675.8278434512,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2298668.2777272724,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38536.534913940035,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2693469.2584210527,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5690.015260263013,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50127.04522284913,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87735.82916276003,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235904.9089647662,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3410404.8353333324,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2066753.897916666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56722.09541162146,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "99c6c63ec37a862fc31ebb98be37ca7a3a16a149",
          "message": "fix auto-release crates publish gate (#150)",
          "timestamp": "2026-06-13T22:24:04-04:00",
          "tree_id": "013001a7edf81ff97c59a62e44167aa51ccf27f7",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/99c6c63ec37a862fc31ebb98be37ca7a3a16a149"
        },
        "date": 1781405487613,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2737639.752105263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336326.38521658746,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2304007.1727272724,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39586.21782288366,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2665230.070526317,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5695.142541463114,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 51278.554425041664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88147.95932269511,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236106.9328403245,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3397271.194666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2069638.8856000009,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 58013.85132071317,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1781413060659,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2274371.7673913045,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 267983.24634864525,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1899924.9361436414,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 25469.186854118645,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2259450.5386956516,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5127.2590161721655,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34040.70760720691,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 64438.98211840682,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 193407.46471631198,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2707679.245263159,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1760846.7981688133,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 40832.781840811695,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "4a42e49f6d1065b7b1b692b579155d2be776ca89",
          "message": "deps: roll up open Dependabot updates",
          "timestamp": "2026-06-14T03:06:36Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/151/commits/4a42e49f6d1065b7b1b692b579155d2be776ca89"
        },
        "date": 1781446924411,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2702073.322105263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 334582.817798583,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2284083.726818182,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39111.039086147284,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2681548.306842106,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5732.547260498258,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50421.02297573423,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 86934.74805013156,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232527.07054690213,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3366477.911999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2049103.5447999998,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 56928.519379143094,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1782018220987,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2967112.11,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 346000.1364305503,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2497206.572500001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33217.42267213832,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2879505.418333333,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6532.651153363426,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45699.534871213466,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 84828.52674143668,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 252464.5522579182,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3508607.2573333336,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2274426.1486363644,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52987.112572825725,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1782622920175,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2954575.590588234,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 345469.31719999335,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2507364.124761906,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32922.66725154611,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2860805.375555556,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6662.169051836707,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 42602.59307076818,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 82422.51937513068,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 249812.01511323266,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3509425.0720000006,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2268838.28590909,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54658.61501897154,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1783227240765,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2949724.217058824,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 348734.8264090155,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2487650.9119047616,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31957.1755302498,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2923087.3777777785,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 6564.690000500796,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43109.5283026328,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 82499.22719499219,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 249345.9475334793,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3399020.410666664,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2263249.8817391293,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51576.571066168224,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1783831310670,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2735801.522631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 341727.94036632875,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2306327.55590909,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 39638.801347136476,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2740781.9657894736,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5685.708120612785,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 51014.862006583426,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88973.74039594672,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236563.72792100665,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3370356.077333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2069948.5075000005,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57753.6810081799,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb",
          "message": "chore(release): bump version to 0.3.2\n\n  Auto-generated release commit",
          "timestamp": "2026-06-14T03:06:32Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/fe9512df959ce8e8d64f4de1b5b1bb7b9e00b6fb"
        },
        "date": 1784435932114,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2727092.2178947376,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 338709.9532371698,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2286334.532727273,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 40398.927024016055,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2696825.7210526317,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5771.601727735603,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50485.36733977852,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87909.15796003451,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 232425.6561758508,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3409065.966000001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2077626.3071999995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57114.28797033048,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "committer": {
            "name": "ThreatFlux",
            "username": "ThreatFlux"
          },
          "id": "49d7390d2fa6f7c25aa2c995e365c0d2e7abf2af",
          "message": "deps: roll up dependency, action, Docker, and security updates",
          "timestamp": "2026-06-14T03:06:36Z",
          "url": "https://github.com/ThreatFlux/file-scanner/pull/151/commits/49d7390d2fa6f7c25aa2c995e365c0d2e7abf2af"
        },
        "date": 1784489555538,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2681562.273157895,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336820.0192343352,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2264037.863636364,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38048.182086294255,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2685740.1389473695,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5722.12747728499,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50297.67186399376,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88104.77875432026,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 233419.43726991944,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3372460.6513333344,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2074688.3924999994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55657.21236187366,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5a84c49ff88c2e59b64a3b69e2c8ceb7057b8353",
          "message": "deps: roll up dependency, action, Docker, and security updates (#151)\n\n* deps: roll up open dependency updates\n\n* deps: consolidate dependency and security updates\n\n* ci: pin updated actions to immutable revisions\n\n* deps: patch newly disclosed RustSec advisories",
          "timestamp": "2026-07-19T20:46:53-04:00",
          "tree_id": "2d716bdd8242edaddc80597bb06744a29607aba1",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/5a84c49ff88c2e59b64a3b69e2c8ceb7057b8353"
        },
        "date": 1784510113682,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2693213.634736842,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336702.4005650382,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2281307.0831818185,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38866.82258064114,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2666399.80631579,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5609.3436913555315,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 50588.53835087841,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88888.13522503538,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 235645.94735253078,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3407513.3993333345,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2083265.4704166674,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57598.99690687629,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "cc58ac94459ba88d77d446da987b50d45ef70050",
          "message": "chore(release): bump version to 0.3.3\n\n  Auto-generated release commit",
          "timestamp": "2026-07-20T01:31:37Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/cc58ac94459ba88d77d446da987b50d45ef70050"
        },
        "date": 1785040537913,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2153799.8366666674,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 238528.8514485894,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1620631.110715947,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 25418.7634929429,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1985705.957307692,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 2097.574298010675,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32242.3442456643,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 55252.540029786986,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 174379.6731405751,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2458779.4959090906,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1569103.4517537034,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 40228.507449982586,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "github-actions[bot]",
            "username": "github-actions[bot]",
            "email": "github-actions[bot]@users.noreply.github.com"
          },
          "id": "cc58ac94459ba88d77d446da987b50d45ef70050",
          "message": "chore(release): bump version to 0.3.3\n\n  Auto-generated release commit",
          "timestamp": "2026-07-20T01:31:37Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/cc58ac94459ba88d77d446da987b50d45ef70050"
        },
        "date": 1785645658145,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2713538.569473684,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 339796.72344947443,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2293411.47,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 40667.82385158118,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2708062.2021052632,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_elf",
            "value": 5698.067592526232,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 52028.80321296538,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 89217.58474604313,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237805.73521280696,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3357439.0673333337,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2084802.5583999995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57908.47330343244,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "111350795eb0ed0c0804e8fae7bae02578c8e545",
          "message": "perf(strings): compile string categorization regexes once (#239)\n\ncategorize_string compiled up to twelve regexes for every extracted string (about 2.6 ms per string), so 1,000 strings took 2.6 s and the 10,000-string Criterion case needed about 44 minutes; every push and scheduled Performance Benchmarks run on main hit the 60-minute job timeout. Compile the patterns once in a LazyLock with the same order and first-match semantics (1,000 strings: 2.6 s -> 0.6 ms), and add a unit test requiring all twelve patterns to compile.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-06T16:46:43-04:00",
          "tree_id": "97670597edb8416a3dc78716999c2fa1e7d1da4e",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/111350795eb0ed0c0804e8fae7bae02578c8e545"
        },
        "date": 1791321886357,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2659.0037006193797,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 113899.65165373436,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3433.5582187655396,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2311108.4213636355,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3363362.499333334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 325015.8701430617,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2852956.9133333336,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 71624.98480522794,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 36396.62613000897,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250994.5247371379,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2317778.7322727274,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 52482.0603848672,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 34527.40662143038,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3105774.652352941,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 870095.2863641412,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9117006.49833334,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1068403.2579714088,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 225666.3972304699,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8705722.995,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9145950.695000004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9186520.976666665,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 977548.8572586747,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1066448.0182332254,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1172422.6746184537,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 180959.05607747543,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 224313.5953206324,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 346065.06344556366,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "63fa3425b97a51464d508373f4ed80b52e739021",
          "message": "ci(docker): stop pruning multi-arch platform manifests from GHCR (#240)\n\nThe main-branch cleanup job ran actions/delete-package-versions with\ndelete-only-untagged-versions and min-versions-to-keep: 10. GHCR lists\nthe per-platform images and attestation manifests of a multi-arch index\nas untagged versions, so the job deleted the linux/amd64 and linux/arm64\nimages behind released tags: the 0.3.4 and 0.3.5 indexes still resolve,\nbut all four of their child manifests return 404 and cannot be pulled.\n\nRemove the job, as the reference rust-cicd-template and vertex_rust_sdk\nworkflows do, so the next release's image stays pullable.\n\nCo-authored-by: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-06T20:23:18-04:00",
          "tree_id": "a384246f289a94badd9374622490fac178603bdd",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/63fa3425b97a51464d508373f4ed80b52e739021"
        },
        "date": 1791334815877,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5729.994191623763,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 79678.63740772131,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6622.291582913124,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2302096.6604545456,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3384675.1173333335,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 334946.8489653865,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2670066.902105263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88576.7282358922,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49124.45125858114,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 249878.07840088272,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2222815.562173913,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57797.293414682805,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38378.72177694812,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2677999.7357894736,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 1003812.4365324784,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10924301.591999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1245178.8092951616,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 252346.2611294787,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10457325.558,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10929648.049999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10892066.224000001,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1164568.040295486,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1243014.9763090075,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1362604.1865145213,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 211133.8793769507,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 253855.6929951284,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 386025.2863698596,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dab10a4196af07707ad3f96dcf18c1b09cf3c270",
          "message": "chore: release v0.3.6",
          "timestamp": "2026-10-07T02:59:14Z",
          "tree_id": "bbca7f5a3695fc8f2618ca942d9f768e657477c5",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/dab10a4196af07707ad3f96dcf18c1b09cf3c270"
        },
        "date": 1791344157285,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2708.730970800029,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 109449.23845622814,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3488.829730031719,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2286273.9736363646,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3262075.1375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 332217.3104726833,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2907525.321111111,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 71353.12642498604,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 36507.697578343046,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 247047.03125388682,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2232075.109130434,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 54059.906143289314,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 34458.87370937067,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2973298.3670588243,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 871523.8212029109,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9290016.381666668,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1085185.5266848528,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 228763.2166490365,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8742786.59666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9280172.610000001,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9260018.306666665,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 989486.8883952356,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1086296.3510973519,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1209544.8067675987,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 180836.66528787653,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 230022.08648331778,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 360341.9768440107,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2a82711fe5a5ea3fa9e1eb8a720fdd7e0b9ccd51",
          "message": "ci(release): write the Windows checksum with an LF line ending (#241)\n\nThe Windows packaging step wrote its .sha256 with PowerShell Out-File (CRLF), which macOS sha256sum and shasum cannot read. Write it with an LF ending, as rust-cicd-template does, and make Upload Release Assets require, for every archive, a .sha256 sidecar holding exactly one LF-terminated \"<sha256>  <archive>\" line that verifies with sha256sum, with one checksum file per archive.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-07T00:29:15-04:00",
          "tree_id": "da78fecee4512f463805ed45241d059efce0994a",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/2a82711fe5a5ea3fa9e1eb8a720fdd7e0b9ccd51"
        },
        "date": 1791349665631,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2763.4986676396716,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 147744.66587459957,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3441.0403578136325,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 3004734.7341176476,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 4057367.1069230763,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 429375.49730966345,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3229405.45875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75690.65854820177,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37707.90765556021,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 230351.4542592612,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2096840.0666666667,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 51037.33402412081,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31245.95120413297,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3221255.385,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 890441.3029843472,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10013719.904,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1165409.1806525397,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 239012.99304344025,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 9412967.715000004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9971477.606666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10010298.36,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1057152.8913180006,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1166160.5220873326,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1283285.2191882376,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 191187.7715625672,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 239310.64001265398,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 371090.42648000375,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4caeaeb52857f4eaec57cf9f0040cf83c14f84cd",
          "message": "docs(changelog): add the 0.3.6 section (#242)\n\nv0.3.6 shipped while its changes were still listed under [Unreleased].\nMove them into a dated [0.3.6] section, adding the toolchain, dependency,\nMach-O, CLI input and vendored Wasmtime changes from #236 that the\nrelease notes cover. Keep the Windows checksum fix from #241, which\nlanded after the tag, under [Unreleased].\n\nThe remaining [Unreleased] entries predate 0.3.0 and were already part\nof that release, so list them under \"Earlier releases (0.1.1 to 0.3.5)\"\nand point to GitHub Releases for per-version notes. Update the\n[Unreleased] compare link and add one for 0.3.6.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-07T03:02:55-04:00",
          "tree_id": "a3a58daeb164a2a6857c2a8514d380237b6a8cd7",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/4caeaeb52857f4eaec57cf9f0040cf83c14f84cd"
        },
        "date": 1791358844424,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5491.886265579628,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 73251.80147382978,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6422.661121722676,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2302920.629090909,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3367354.2346666665,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 336758.8850099263,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2702453.273157895,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 87891.89697390044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49436.8932498925,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 248909.18260150615,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2214840.9165217383,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57669.60413891452,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38956.032240887725,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2679436.981578948,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 1003104.4608055174,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10696333.669999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1264582.5834457101,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 261500.94259307723,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10277056.624000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10721653.146000003,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10735535.858000001,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1141561.4324914378,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1258610.9676780251,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1366612.3320900588,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 211056.44495482527,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 261224.2369906573,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 407215.7616525703,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b1f58fc42cbe1edc092e37ac6acc3033d8e09bc1",
          "message": "build: publish the crate as threatflux-file-scanner (#243)\n\ncrates.io treats - and _ alike, so the unrelated file_scanner crate owns\nthe file-scanner name. The package is now threatflux-file-scanner; the\nbinary stays file-scanner and the library stays file_scanner, so release\nasset names, the GHCR image and `use file_scanner::...` are unchanged.\nDockerfile, docker.yml, release.yml and the Makefile build the renamed\npackage.\n\nThe local threatflux-threat-detection 0.1.0 path dependency was never on\ncrates.io, so the package could not resolve outside this workspace. Use\nthe published 0.2.3 with its YARA engine instead (the local copy's YARA\nengine was a placeholder) and remove the local copy, its CI feature\nchecks and its Makefile targets.\n\nAn include list ships only src/, Cargo.toml, Cargo.lock, README,\nCHANGELOG and LICENSE. The vendored YARA-X patch is not in the package:\nthe crates.io build uses upstream YARA-X 1.21.0 with Wasmtime 45.0.3,\nand vendor/README.md records why none of the four Wasmtime advisories is\nreachable from it. Release binaries and images keep Wasmtime 49.0.2.\n\nRelease dry runs now run cargo publish --dry-run while\nCRATES_IO_PUBLISH=false (which stays false). README, INSTALLATION and the\nworkflow README document cargo install threatflux-file-scanner, the\none-time manual first publish and the switch to trusted publishing.\nCHANGELOG records 0.3.7.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-10-07T05:51:31-04:00",
          "tree_id": "41353838676132213d77949a9910cde012e58eac",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/b1f58fc42cbe1edc092e37ac6acc3033d8e09bc1"
        },
        "date": 1791368721550,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4975.048937873292,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 63220.687285390675,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5722.813161225665,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1925202.29630477,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2698504.714736842,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 266662.4147504617,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2278044.5534782615,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 63498.820849187774,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 33257.38447101161,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 207318.2312574969,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1904025.980726554,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 42885.62328586564,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 25598.208407025424,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2261023.668695653,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 787738.5371022039,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9005754.139999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1015082.3266098003,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 192359.75350763247,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8741230.585000003,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8952680.479999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9019014.506666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 940642.7944139945,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1010025.9590115246,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1109199.1743707983,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 157518.29857113084,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 192399.77839278066,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 298629.5195887151,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "a34604292e7060f45d3c6f10b392c326afe2ead1",
          "message": "chore: release v0.3.7",
          "timestamp": "2026-10-07T12:06:00Z",
          "tree_id": "71a29382ef0e22f967b9d1962134f6ca6213818f",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/a34604292e7060f45d3c6f10b392c326afe2ead1"
        },
        "date": 1791376859951,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2553.356163815763,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 104553.82286016086,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3215.8936281645715,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2157972.122608696,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3089614.5175,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 309576.6964113436,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2631083.2125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 68702.9604052323,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 36214.748452466905,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236103.40076201715,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2136706.5983333336,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 50357.364057749066,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 32048.78067272764,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2921641.9761111103,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 832023.4102721523,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8907542.303333335,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1012473.7444949076,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 226504.5381981808,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8328535.358333337,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9015950.721666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8984545.56,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 933979.5209334902,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1048443.2151529775,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1156245.9530810737,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 172105.977291377,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 217378.7239256795,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 337368.1876929882,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]",
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a34604292e7060f45d3c6f10b392c326afe2ead1",
          "message": "chore: release v0.3.7",
          "timestamp": "2026-10-07T12:06:00Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/a34604292e7060f45d3c6f10b392c326afe2ead1"
        },
        "date": 1791690826046,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5059.9073955883405,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 64143.45777533998,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5738.819573301282,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1909916.8568080396,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2688929.524736842,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 263422.2675755806,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2216977.794347827,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 63077.50536998855,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 33023.53783375072,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 207052.13260219237,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1901977.7092886777,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 41593.696156953505,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 24804.303338479316,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2246690.6526086945,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 773690.4048130237,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8516851.444999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1023999.9670848363,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 198076.48091529793,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8315708.291428572,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8530123.648333335,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8581175.113333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 902573.3638180214,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1023140.4067674684,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1137812.0183925286,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 159247.86986210587,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 198653.74912970365,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 313137.35575211985,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]",
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a34604292e7060f45d3c6f10b392c326afe2ead1",
          "message": "chore: release v0.3.7",
          "timestamp": "2026-10-07T12:06:00Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/a34604292e7060f45d3c6f10b392c326afe2ead1"
        },
        "date": 1792295654314,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5716.245024751816,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 84218.39810680976,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6486.610203979841,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2365410.5086363633,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3419927.5166666675,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 342697.22283231805,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2709181.2957894737,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 88558.58821023184,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 49635.001627597914,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 248975.18243593787,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2221996.8986956524,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 57153.577541559745,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 38178.92063309665,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2819156.763333333,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 1009579.1957148799,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 11115385.274000006,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1279250.6742071288,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 262362.7448201708,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10694335.317999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 11245868.157999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 11119151.418000005,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1180565.801697284,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1270556.7093553995,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1410323.1519503966,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 215680.06898403604,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 263237.87315064506,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 409199.81834783795,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c2a52612d6a8413469f95a10e2d679a24208ce27",
          "message": "fix: consolidate stable updates and remediate security alerts (#267)\n\n* deps: consolidate stable updates and security alert review\n\n* fix: remediate runtime alerts and enforce complete container scans\n\n* docs: prove every glibc fix against pinned upstream source",
          "timestamp": "2026-10-21T02:02:00-04:00",
          "tree_id": "a95f018c66a9d47989c0a6d147753328b2b7c3cf",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/c2a52612d6a8413469f95a10e2d679a24208ce27"
        },
        "date": 1792564808531,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5307.696665738718,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 81084.85581032548,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6224.51764828733,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2280945.4004545454,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3132651.3375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 320086.69278103334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2708923.4747368423,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 78780.44306488609,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47445.56924949893,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 241831.78486701607,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2227205.0652173916,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48724.75240958072,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28892.67576395328,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2727418.6231578947,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 1011173.1512007724,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 11064838.059999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1252315.0098252988,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 255307.1730444019,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10445825.907999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 11049704.801999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10947305.841999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1162593.4970593166,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1252393.975099789,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1371734.2655345288,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 210858.19095984477,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 254118.50314114202,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 388471.7333335983,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "919924888a2e8aaeb0a7a0bae80819c4c9210610",
          "message": "chore: release v0.3.8",
          "timestamp": "2026-10-21T07:02:13Z",
          "tree_id": "10cfc9b691bc4b46157a486d5e3cb818c8ad0c30",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/919924888a2e8aaeb0a7a0bae80819c4c9210610"
        },
        "date": 1792568387331,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2766.3949600736987,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 116701.28465757151,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3581.697607296261,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2339179.005454545,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3288731.7553333323,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 325340.97787185316,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2777375.9755555564,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 72809.51879574616,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 37219.30687564891,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 250446.92396676532,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2265803.8982608696,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 55013.40156860363,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 35399.89889364165,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3003746.905882353,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 866513.8259909119,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9476833.186666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1093809.4180669028,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 226040.37131270472,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8842717.338333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9488457.828333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9388914.648333335,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1008617.7638607774,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1087869.012202658,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1208964.356953632,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 183535.5106880038,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 227067.7574699836,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 346519.5779588263,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]",
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "919924888a2e8aaeb0a7a0bae80819c4c9210610",
          "message": "chore: release v0.3.8",
          "timestamp": "2026-10-21T07:02:13Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/919924888a2e8aaeb0a7a0bae80819c4c9210610"
        },
        "date": 1792900257902,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4390.411007861312,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 81569.23671204706,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5147.595348725122,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1940185.8126869295,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2611250.121500001,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 261114.13949169547,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2293440.3004545458,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58267.44949399678,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32085.122825667313,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 207668.62608446044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1913364.737030688,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 37797.643022654294,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21374.73171895453,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2270927.004090909,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 757958.0684017637,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8871353.999999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 992902.38976963,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 182314.27516586267,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8731872.623333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8891708.511666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8920008.974999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 928174.9695370398,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 991360.2855695535,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1098473.9171363125,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 146303.4426009641,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 182552.5981949247,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 287614.11005087936,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e4af0ecad3531c48fc175ad1fe6baa24ee13671c",
          "message": "fix(deps): resolve Tokio and transitive security advisories (#280)\n\n* fix(deps): upgrade Tokio in both Cargo projects\n\n* fix(deps): clear remaining crypto advisories\n\n* fix(deps): update Wasmtime to patched 49.0.5\n\n* fix(deps): update reviewed Wasmtime floor and guard\n\n* fix(ci): acknowledge reviewed dependency policy digest\n\n* fix(deps): update vendored libz-sys security wrapper\n\n* fix(ci): preserve executable native regression script\n\n* docs: align container source note with libz-sys upgrade",
          "timestamp": "2026-10-31T03:04:10-04:00",
          "tree_id": "a6611085959cc32c8c8d4699382db834a5038f2e",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/e4af0ecad3531c48fc175ad1fe6baa24ee13671c"
        },
        "date": 1793432537933,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5330.263718641251,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 71350.47817015383,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6050.678627348357,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2253967.9490476195,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3179952.941875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 317875.1385287308,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2713815.122631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76479.31022743341,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45896.089649440284,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239151.9546380779,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2232136.6739130425,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47845.4081497184,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28113.435344152083,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2722498.399473684,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 975475.4246526421,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10851088.138,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1244452.0780071253,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 243581.1314820625,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10449542.282,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10859648.254,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10818307.901999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1142862.765179936,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1242073.7244146103,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1347083.4764567963,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 198244.88275131813,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 242618.80201098372,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 372482.1191156006,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8396ea2e0b82de0c1cb33de5ad8f04e56b32468f",
          "message": "chore: release v0.3.9",
          "timestamp": "2026-10-31T08:10:52Z",
          "tree_id": "bc2da5f9e1bbf3d09b57ab2b2a0560826891e0b0",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/8396ea2e0b82de0c1cb33de5ad8f04e56b32468f"
        },
        "date": 1793436068120,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4088.555637359178,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 41635.259044348306,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 4551.22649650539,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1501819.3692951926,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2006630.6188,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 199275.43333599117,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1780598.0171965584,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 45847.83035850607,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 27330.005936584075,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 178214.24046885394,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1673998.7237988638,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 35067.77722835117,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 20404.695394877504,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1840072.184015725,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 584930.2223767934,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6457230.87875,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 723384.7248112957,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 137670.86006580995,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 6104109.875555556,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 6604607.0575,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6489066.91,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 662648.3043617727,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 718289.8496265885,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 804678.6165866855,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 108388.16036916956,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 135984.52771756312,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 223487.14418303026,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "119b3f249fa855fd89e5783e71edbdd54983007e",
          "message": "deps(deps): bump memmap2 from 0.9.11 to 0.9.12 (#275)\n\nBumps [memmap2](https://github.com/RazrFalcon/memmap2-rs) from 0.9.11 to 0.9.12.\n- [Changelog](https://github.com/RazrFalcon/memmap2-rs/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/RazrFalcon/memmap2-rs/compare/v0.9.11...v0.9.12)\n\n---\nupdated-dependencies:\n- dependency-name: memmap2\n  dependency-version: 0.9.12\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\nCo-authored-by: Wyatt Roersma <wyattroersma@gmail.com>",
          "timestamp": "2026-10-31T09:45:09-04:00",
          "tree_id": "79e02a73977c82db5983760ab1fe81a56bd503cc",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/119b3f249fa855fd89e5783e71edbdd54983007e"
        },
        "date": 1793456119803,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4114.482204837745,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 41704.12404825893,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 4578.082160169866,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1516907.5055545145,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2037823.1947999992,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 198566.90852206916,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1786378.5112305505,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 44319.22586182256,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 26607.07443009214,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 178047.63088049163,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1666847.5823129914,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 35647.24598801797,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 19558.316961070486,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1865094.9686603537,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 581759.2737218775,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6515941.02625,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 711231.0773963879,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 142863.16712211535,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 6245916.1875,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 6449484.47125,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6561137.24125,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 662385.7723459892,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 713956.8803762958,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 801907.6998805329,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 108098.61965402873,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 138712.9938358817,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 225278.9974911422,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "dependabot[bot]",
            "username": "dependabot[bot]",
            "email": "49699333+dependabot[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "119b3f249fa855fd89e5783e71edbdd54983007e",
          "message": "deps(deps): bump memmap2 from 0.9.11 to 0.9.12 (#275)\n\nBumps [memmap2](https://github.com/RazrFalcon/memmap2-rs) from 0.9.11 to 0.9.12.\n- [Changelog](https://github.com/RazrFalcon/memmap2-rs/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/RazrFalcon/memmap2-rs/compare/v0.9.11...v0.9.12)\n\n---\nupdated-dependencies:\n- dependency-name: memmap2\n  dependency-version: 0.9.12\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\nCo-authored-by: Wyatt Roersma <wyattroersma@gmail.com>",
          "timestamp": "2026-10-31T13:45:09Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/119b3f249fa855fd89e5783e71edbdd54983007e"
        },
        "date": 1793504734322,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4667.370691147864,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 65118.208353055146,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5404.4430123768525,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1902244.073046437,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2571445.3184999987,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 259430.88173884145,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2286282.2472727275,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58327.84332757041,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32357.487182572702,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 204349.6864498284,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1898601.6761730178,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 38155.101598793764,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21267.151956402304,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2273970.7804545457,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 766358.0769187221,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8827527.766666662,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 987366.6684997613,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 187620.38683742142,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8573959.360000001,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8833247.044999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8992965.443333331,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 925595.5487960554,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 989975.7454724512,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1097540.859791045,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 147303.62524488254,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 189148.92810326477,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 300411.6996929657,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "f3eac365a75d49ccde9c31a1b0eee5a17214ef73",
          "message": "deps(deps): bump zip from 9.0.5 to 9.1.3 in /threatflux-package-security (#288)\n\nBumps [zip](https://github.com/zip-rs/zip2) from 9.0.5 to 9.1.3.\n- [Release notes](https://github.com/zip-rs/zip2/releases)\n- [Changelog](https://github.com/zip-rs/zip2/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/zip-rs/zip2/compare/v9.0.5...v9.1.3)\n\n---\nupdated-dependencies:\n- dependency-name: zip\n  dependency-version: 9.1.3\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-02T11:48:16-05:00",
          "tree_id": "56eaae8618185f9aa8f6cc889c94ccaa9d4319e7",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/f3eac365a75d49ccde9c31a1b0eee5a17214ef73"
        },
        "date": 1793640187240,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4587.178273830533,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 62295.98418133656,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5408.546034492668,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1905733.7485254204,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2642489.197368422,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 260378.73417594735,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2284914.3459090907,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58329.43658841681,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32162.2081832516,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 206683.7256047678,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1907017.5062822741,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 41788.49717180341,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 24943.106845621656,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2264195.1727272724,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 762541.3889992606,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8987249.27333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1003973.0246593339,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 184940.45225650948,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8767644.078333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8975974.795000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9092024.938333336,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 937140.2481987859,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 999328.3522836315,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1099893.7179553963,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 147720.57572019327,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 184702.15229444523,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 291006.3375932015,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "dependabot[bot]",
            "username": "dependabot[bot]",
            "email": "49699333+dependabot[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f3eac365a75d49ccde9c31a1b0eee5a17214ef73",
          "message": "deps(deps): bump zip from 9.0.5 to 9.1.3 in /threatflux-package-security (#288)\n\nBumps [zip](https://github.com/zip-rs/zip2) from 9.0.5 to 9.1.3.\n- [Release notes](https://github.com/zip-rs/zip2/releases)\n- [Changelog](https://github.com/zip-rs/zip2/blob/master/CHANGELOG.md)\n- [Commits](https://github.com/zip-rs/zip2/compare/v9.0.5...v9.1.3)\n\n---\nupdated-dependencies:\n- dependency-name: zip\n  dependency-version: 9.1.3\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-02T16:48:16Z",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/f3eac365a75d49ccde9c31a1b0eee5a17214ef73"
        },
        "date": 1794109807248,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5451.16796262986,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 74436.3861393637,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6385.081891996209,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2258508.6773913037,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3121087.0775,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 312126.93817946006,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2655427.586315788,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74565.51948183132,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45091.02665857715,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236354.27669891462,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2196513.9452173915,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48537.29137066496,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27351.819667316773,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2652966.045789474,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 961174.4526651851,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10713611.713999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1215175.9341772913,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 240868.1989389907,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10289888.594000004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10770107.327999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10736849.346,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1137284.0014090226,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1215292.6071215747,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1332839.0406213363,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 195624.99630577787,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 241213.30974242638,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 376632.14921466215,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7f7d7b66228cf4776025f56f5ef671c7fee71127",
          "message": "docker(deps): bump chainguard/glibc-dynamic from `7096732` to `aab5cd0` (#289)\n\nBumps [chainguard/glibc-dynamic](https://github.com/chainguard-images/images) from `7096732` to `aab5cd0`.\n- [Commits](https://github.com/chainguard-images/images/commits)\n\n---\nupdated-dependencies:\n- dependency-name: chainguard/glibc-dynamic\n  dependency-version: latest\n  dependency-type: direct:production\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-09T23:32:08-05:00",
          "tree_id": "d9c205828719a777e5d9bc2bf795d3afa3e41813",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/7f7d7b66228cf4776025f56f5ef671c7fee71127"
        },
        "date": 1794286851372,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4234.514117201086,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 41975.32095337416,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 4720.808910345939,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1408462.1545635865,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 1924403.259609196,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 188817.18787694923,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1681347.2002514296,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 41645.89115332505,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 26352.59253871358,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 167368.61442234946,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1546425.0913759628,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 32348.287818585428,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 19240.442193436946,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1720273.8110963318,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 566964.228328288,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6052341.55111111,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 673253.3119299056,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 133473.07812192373,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 5785747.98222222,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 6102182.17875,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6158532.99222222,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 627816.4100036096,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 674221.677266261,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 752666.4506577791,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 105278.73123938568,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 130215.56074554253,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 217643.599772301,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3807ff514982a880646e26cac13aba72d0d8c5a9",
          "message": "ci(deps): bump taiki-e/install-action from 2.88.1 to 2.90.2 (#293)\n\nBumps [taiki-e/install-action](https://github.com/taiki-e/install-action) from 2.88.1 to 2.90.2.\n- [Release notes](https://github.com/taiki-e/install-action/releases)\n- [Changelog](https://github.com/taiki-e/install-action/blob/main/CHANGELOG.md)\n- [Commits](https://github.com/taiki-e/install-action/compare/68a389c788b2cd04016ce8c80ee23b80d2ab3d68...3a3daafd3b7f23b8f65d9f5ba2db203fb59b79e2)\n\n---\nupdated-dependencies:\n- dependency-name: taiki-e/install-action\n  dependency-version: 2.90.2\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-10T11:42:39-05:00",
          "tree_id": "dce9c9cc046837694c1e8c6075ff0dfce7edf894",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/3807ff514982a880646e26cac13aba72d0d8c5a9"
        },
        "date": 1794331330524,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2435.7247288378394,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 113088.16282193907,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3079.2615598770644,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2294101.4868181814,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3356209.6175,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 318953.5499528437,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2801943.7255555545,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 68254.1934851015,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 35505.159092449634,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 248978.08544968854,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2294599.3631818183,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48258.78084333606,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 29534.403333921047,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3074046.7076470596,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 864597.9452681148,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9407216.206666669,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1097478.9700068354,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 225507.08966655706,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8986624.180000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9385032.556666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9494514.845,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1002101.998245626,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1094193.0637765334,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1219417.5301477497,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 170629.91426171054,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 224768.34444335365,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 355393.0004614677,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4f52caebe56314ce6dbeaf3060ffd4130e3a6233",
          "message": "deps(deps): bump rmcp from 3.8.0 to 3.9.0 (#294)\n\nBumps [rmcp](https://github.com/modelcontextprotocol/rust-sdk) from 3.8.0 to 3.9.0.\n- [Release notes](https://github.com/modelcontextprotocol/rust-sdk/releases)\n- [Changelog](https://github.com/modelcontextprotocol/rust-sdk/blob/main/release-plz.toml)\n- [Commits](https://github.com/modelcontextprotocol/rust-sdk/compare/rmcp-v3.8.0...rmcp-v3.9.0)\n\n---\nupdated-dependencies:\n- dependency-name: rmcp\n  dependency-version: 3.9.0\n  dependency-type: direct:production\n  update-type: version-update:semver-minor\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-10T16:21:19-05:00",
          "tree_id": "6ce69058c64ea3419a068fb34a83cf97ab697f28",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/4f52caebe56314ce6dbeaf3060ffd4130e3a6233"
        },
        "date": 1794348024515,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5499.033253950837,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 72777.72043114231,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6424.607874172187,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2277344.4872727273,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3197279.48125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 317609.6323877812,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2863909.7057894743,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 74906.69176645206,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 45676.73322167554,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237240.2511808442,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2208845.0578260873,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47024.94810478299,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28873.45939293988,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2707254.8210526314,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 969428.8605961433,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10841384.766000004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1225414.2423311782,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 242311.46124661673,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10281368.924000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10772948.928,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10732520.092000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1142462.6435440367,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1222080.0753072912,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1343681.731410319,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 196948.559095041,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 240977.13753241964,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 375305.89652455354,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "ca11ad3bd4d867409b72135971069e84e61c7cdc",
          "message": "ci(deps): bump github/codeql-action init, analyze and upload-sarif to 4.39.3 (#304)\n\nMoves all five codeql-action refs together (security.yml init/analyze/\nupload-sarif, docker.yml upload-sarif x2) so the CodeQL steps share one\nversion, and adds a Dependabot group so they stay in lockstep.\nSupersedes #292 and #295.\n\nCo-authored-by: Claude Sonnet 5.5 <noreply@anthropic.com>",
          "timestamp": "2026-11-10T18:30:21-05:00",
          "tree_id": "7629526f4294f11020ccf1fdf936f21bf3b0ea14",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/ca11ad3bd4d867409b72135971069e84e61c7cdc"
        },
        "date": 1794355409376,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4939.925933630962,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 63641.58931539523,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5771.189750347058,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1890864.3019205052,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2647205.4875000003,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 261161.535736028,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2286718.576363636,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58099.669243977194,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32892.6297410514,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 203725.6052461072,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1895875.675382215,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 38438.71085225216,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21489.1804228271,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2266872.792173914,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 752822.148887984,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8847592.084999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 995642.3876058416,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 184658.64402749788,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8653908.281666664,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8902341.584999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8938534.726666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 932788.5025245004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 997147.7704637672,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1098460.2870171408,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 146723.5452558647,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 183962.34813318384,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 290175.6992084009,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "380423a5fc048269925cf0275fa86fbf6a3ba8e6",
          "message": "deps(deps): bump uuid from 1.29.0 to 1.29.1 (#312)",
          "timestamp": "2026-11-10T20:15:51-05:00",
          "tree_id": "ae870a552b42127065bfb0055b4e5fa260e4ad81",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/380423a5fc048269925cf0275fa86fbf6a3ba8e6"
        },
        "date": 1794362090368,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5349.66536767651,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 83325.27730064686,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6284.398787853781,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2352889.828636363,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3177472.3825,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 313888.71400285955,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2715501.5847368417,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75261.8199752234,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 43916.491862930736,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238391.05255298666,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2205577.4073913037,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 46341.5835203837,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27453.553598654744,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2697172.1305263154,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 968456.2506619167,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10876693.107999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1226486.9913924867,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 249434.71810050317,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10357939.419999994,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10838149.261999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10839573.087999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1141915.4990242654,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1229692.0237753002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1358332.1048650558,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 195823.55461135038,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 247431.97838281322,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 389391.68183547835,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3607b81f1e7e4ecb0d2723af1b2726314a5a7ca0",
          "message": "ci(deps): bump sigstore/cosign-installer from 4.1.2 to 4.1.3 (#290)\n\nBumps [sigstore/cosign-installer](https://github.com/sigstore/cosign-installer) from 4.1.2 to 4.1.3.\n- [Release notes](https://github.com/sigstore/cosign-installer/releases)\n- [Commits](https://github.com/sigstore/cosign-installer/compare/6f9f17788090df1f26f669e9d70d6ae9567deba6...756fe2d284c7292c4e9b62c8a28f1e5629c59532)\n\n---\nupdated-dependencies:\n- dependency-name: sigstore/cosign-installer\n  dependency-version: 4.1.3\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>\nCo-authored-by: Wyatt Roersma <wyattroersma@gmail.com>",
          "timestamp": "2026-11-11T00:59:51-05:00",
          "tree_id": "3afaa3e968723c55339d1c57336fc4b09996d8f5",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/3607b81f1e7e4ecb0d2723af1b2726314a5a7ca0"
        },
        "date": 1794378825880,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4936.9649251021765,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 63097.08513691054,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5806.018739843413,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1930840.7236434286,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2651994.8947368427,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 261842.75795524687,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2242691.5790909086,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 60823.271986490574,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34278.087567772825,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 204388.14056479034,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1903993.954810115,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 38969.25495399015,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 23172.686183122092,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2279171.143043479,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 763635.1640255637,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9037794.614999996,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 997926.6036926365,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 186157.9901880644,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8877323.745,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9084871.790000001,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9069062.50333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 939988.3196441091,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1003430.6907988867,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1124589.4574448112,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 147993.9233669765,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 185704.6806082861,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 289002.62865707563,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "364b21364c4a8c39487e5840271bec14962454b3",
          "message": "docker(deps): bump chainguard/glibc-dynamic from `aab5cd0` to `041dfc2` (#306)\n\nBumps [chainguard/glibc-dynamic](https://github.com/chainguard-images/images) from `aab5cd0` to `041dfc2`.\n- [Commits](https://github.com/chainguard-images/images/commits)\n\n---\nupdated-dependencies:\n- dependency-name: chainguard/glibc-dynamic\n  dependency-version: latest\n  dependency-type: direct:production\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-11T16:38:33-05:00",
          "tree_id": "975c440299423e2ad7a602b352a0928d3197853e",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/364b21364c4a8c39487e5840271bec14962454b3"
        },
        "date": 1794434855556,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4219.509499363404,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 40039.25693668406,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 4834.5618274893595,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1404423.0834296264,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 1915711.722216884,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 188667.66499342342,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1665600.385143953,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 41497.466861711,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 26227.46039196588,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 171065.96964482963,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1568517.0213148966,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 33171.35569331926,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 19515.560110639453,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1725660.4488741078,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 549193.3607502653,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6060301.928888891,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 680578.7197890107,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 131377.1404431762,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 5812467.414444446,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 6048667.040000005,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6128052.952222222,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 620280.553048029,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 680281.5322269439,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 753404.6288316137,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 101218.78487723226,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 130037.91867473103,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 203728.38353739813,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "49699333+dependabot[bot]@users.noreply.github.com",
            "name": "dependabot[bot]",
            "username": "dependabot[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "91b6be6f7975c4e72e87014cb4999d218a6e5e13",
          "message": "ci(deps): bump trufflesecurity/trufflehog from 3.99.7 to 3.99.8 (#291)\n\nBumps [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) from 3.99.7 to 3.99.8.\n- [Release notes](https://github.com/trufflesecurity/trufflehog/releases)\n- [Commits](https://github.com/trufflesecurity/trufflehog/compare/31ce31ee1abbcc7dc8eee5764c17121c3044c8b2...ea68ca03c865c5f324e86e849ced20ed3cf9dbbb)\n\n---\nupdated-dependencies:\n- dependency-name: trufflesecurity/trufflehog\n  dependency-version: 3.99.8\n  dependency-type: direct:production\n  update-type: version-update:semver-patch\n...\n\nSigned-off-by: dependabot[bot] <support@github.com>\nCo-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
          "timestamp": "2026-11-12T00:36:26-05:00",
          "tree_id": "4f28ecefeb843a86565045f3be8003e52bb37789",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/91b6be6f7975c4e72e87014cb4999d218a6e5e13"
        },
        "date": 1794464126941,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5350.966243720632,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 85601.7345751665,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6435.504128053926,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2429888.7263636356,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3144680.971875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 347011.6983318355,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2700195.0810526307,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75122.31316940772,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47664.55390129757,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 240076.26900994562,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2196027.0160869556,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47206.740375939946,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28585.16022945161,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2719071.210526316,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 992847.1203255362,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 11092219.916,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1261574.7285431973,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 244679.85236794158,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10541243.858,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 11177215.83,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 11206297.252,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1162947.169038564,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1261542.9395668057,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1377899.5693193404,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 199064.15563894098,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 243443.5449823326,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 372203.15456298523,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "322e6af8b7c5489b27f5f9a963eac0767b76fc21",
          "message": "fix(deps): refresh stable dependencies and protect release publication (#313)\n\n* fix(deps): refresh stable dependencies and protect release publication\n\n* fix(deps): consume verified producers and patched runtime",
          "timestamp": "2026-11-12T12:21:49-05:00",
          "tree_id": "d4bb9bbc2d60d6bf51c70d74bef3dc1b74b5e4e4",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/322e6af8b7c5489b27f5f9a963eac0767b76fc21"
        },
        "date": 1794506471105,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5463.108432519621,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 69802.86860642134,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6396.784672422081,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2295982.7236363636,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3329189.643125,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316873.97918615985,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2720832.842631578,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76669.6983682209,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47500.79770688274,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239605.7406767697,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2199666.115652174,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47923.1152787582,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 29340.73032578225,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2762752.583157895,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 970423.4028698282,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10680486.655999996,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1204944.556662895,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 240104.92358909512,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10187795.833999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10709645.799999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10597518.009999998,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1128212.4680384882,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1206482.6462630136,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1325724.212947229,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 195740.63596104682,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 239274.57771563262,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 369085.99823408393,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "9063edcb74e1e6a741eb5ad60f86b152e5565bed",
          "message": "chore: release v0.3.10",
          "timestamp": "2026-11-12T18:43:33Z",
          "tree_id": "37a9ba843adec113d3ac22e7b970accaff8718e2",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/9063edcb74e1e6a741eb5ad60f86b152e5565bed"
        },
        "date": 1794511321450,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5491.829133466927,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 89300.73761197168,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6449.494360601406,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2275295.437727272,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3297610.524375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 319863.46480922087,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2727756.6505263145,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 75568.36622929019,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 46614.60048958873,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 236023.51813247704,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2220707.783478261,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47973.07642622993,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27533.50847573957,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2714470.443157895,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 990245.9492968245,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10778511.763999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1236418.8227279654,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 242279.97583831198,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10309151.332,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10790908.604,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10758174.290000007,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1158928.7968741092,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1244321.2395569575,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1356335.0447983863,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 200135.93687432673,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 242638.05018904968,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 373094.1755551243,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "74ba71e0b059310c92fbbf0715b8206f1711e6fa",
          "message": "fix(deps): rebase reviewed YARA on stable Wasmtime and RSA (#314)\n\n* fix(deps): refresh stable dependencies and protect release publication\n\n* fix(deps): consume verified producers and patched runtime\n\n* fix(deps): rebase reviewed YARA on stable runtime and RSA\n\n* fix(license): retain verified upstream YARA license\n\n* docs: clarify YARA source and license provenance\n\n* fix(deps): adopt upstream fixed zlib and verified detection\n\n* fix(ci): preserve native regression executable mode\n\n* fix(ci): exclude generated crypto lock from code metrics\n\n* fix(ci): refresh stable tools and verified installer paths\n\n* fix(ci): refresh nested scanner versions and scope queue lint\n\n* fix(dev): refresh stale installed scanner tools\n\n* fix(publish): promote verified scanner image aliases\n\n* fix(ci): use compatible noncancelling image queues\n\n* fix(publish): verify compiled scanner artifact versions",
          "timestamp": "2026-11-12T15:08:08-05:00",
          "tree_id": "426abb9e27e68fb6a614e36be8d0f3813e07d101",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/74ba71e0b059310c92fbbf0715b8206f1711e6fa"
        },
        "date": 1794515948903,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4552.0728108143185,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 42887.88955871115,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5250.252606959584,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1525758.719220166,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2021339.2407999996,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 197528.18272599205,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1772107.872284111,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 43522.37565334641,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 28122.408521441943,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 184329.68532700316,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1659282.4639848673,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 35598.72791653201,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 19930.836135967573,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1844582.867211197,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 601571.9075810333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6626889.64875,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 732879.6143019176,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 139160.88971626564,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 6328481.8675,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 6630456.8875,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6810518.06625,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 684985.4961049696,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 721738.078125494,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 813004.667328381,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 107295.76976823274,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 139632.85719206397,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 219757.30664337747,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "7a67c136f55cf913084d72f5d0c53e2d1ba032ed",
          "message": "chore: release v0.3.11",
          "timestamp": "2026-11-12T21:28:54Z",
          "tree_id": "566cb5c545bc32a52c84c122c113d7e0c3fdeb79",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/7a67c136f55cf913084d72f5d0c53e2d1ba032ed"
        },
        "date": 1794521159903,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2377.124359916545,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 110600.74880605728,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 2962.0914611088606,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2197535.762608696,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3165064.354375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 313901.64643935475,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2825858.8505555545,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 65946.4310158172,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34547.72851359847,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 237256.18502665948,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2188930.215217391,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47834.13508029742,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 31475.323586615963,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2876330.795294118,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 822717.4123972562,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8828072.645,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1007867.0353975232,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 203715.8286825365,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8537372.226666665,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8828789.01166667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8915168.381666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 934178.4936737748,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1004021.4113661817,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1122749.3689427308,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 157984.0960148774,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 201915.19392623592,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 321077.7554857837,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c8b93e316462d756a83bdeba1b18dc0b1bab5d4c",
          "message": "fix(deps): complete stable SDK, producer and release updates (#317)\n\nfix(deps): complete stable SDK, producer and release updates",
          "timestamp": "2026-11-13T00:21:53-05:00",
          "tree_id": "ae5fb178949f1e1ead865b29bcdcb9fa10b68bf3",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/c8b93e316462d756a83bdeba1b18dc0b1bab5d4c"
        },
        "date": 1794549617314,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2484.831021893599,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 111865.42481349414,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3097.7315285751815,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2348111.4740909087,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3317866.431999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 324688.2634517049,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2839136.213333333,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 68079.80925662951,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 35713.279163328436,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 251380.41583877974,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2321936.023181818,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48005.971983728865,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 29562.18754382571,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3132242.884705882,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 871457.8983234384,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9506978.718333332,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1082788.7157322618,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 216502.87639047476,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 9147739.435,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9538744.228333332,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9608570.65333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1004145.8028411086,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1080521.7872313093,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1205419.9223593483,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 169215.33090392288,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 218339.5513730132,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 341515.2250170885,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e8cd415e746a17e0f4c54d4fecbb5472b26af511",
          "message": "chore: release v0.3.12",
          "timestamp": "2026-11-13T06:36:01Z",
          "tree_id": "a7959a4b639c012e6ce6bbef471c24d0b81bcbee",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/e8cd415e746a17e0f4c54d4fecbb5472b26af511"
        },
        "date": 1794553709695,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4951.967330255703,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 63716.97988921292,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5709.516760124894,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1920015.8800380407,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2699041.9905263167,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 264894.03206877573,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2273325.675454546,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 60927.878869210595,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 35002.53988101793,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 206818.6641068509,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1958398.7315610808,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 39738.48472128002,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 23920.33102412058,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2265693.9186956524,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 761017.0007634747,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8962987.243333338,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1006065.5290539828,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 184809.59259047444,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8721022.75,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8962381.061666662,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9013529.886666663,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 940038.5649795763,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1002755.9840382236,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1103130.5180344132,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 149255.618707698,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 183743.27721375044,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 286256.0705306568,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "2530327e78d35559a5515e6a4790d691e1278c6d",
          "message": "fix(deps): refresh PSL and verified detection release (#318)\n\nfix(deps): refresh PSL and verified detection release",
          "timestamp": "2026-11-13T04:47:01-05:00",
          "tree_id": "83a55f52004c83b64d50e7e45ae7bc437875a07d",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/2530327e78d35559a5515e6a4790d691e1278c6d"
        },
        "date": 1794565593812,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5497.772855578172,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 83937.66205639626,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6364.068215642835,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2265423.0930434777,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3154947.51875,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 316948.28159285197,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2833959.398947367,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76376.35570702524,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 48160.90732031228,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 239587.4076173288,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2190862.251304347,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 47825.66500082601,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 30162.964184234497,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2650702.002105263,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 972363.0409860713,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 10691834.246,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1218762.993283279,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 242267.7865046405,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 10230542.178,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 10718865.318,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 10709752.184000004,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1131366.3137513653,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1218221.3891219709,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1341104.471751084,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 197252.60573244403,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 240352.67347641592,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 371973.347889988,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "4c2d3579947372b5db01f2edc144d45a0c9fdf53",
          "message": "chore: release v0.3.13",
          "timestamp": "2026-11-13T11:06:31Z",
          "tree_id": "29a9f836c8be0e5c6162fda46e27e1eb18dbe0c3",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/4c2d3579947372b5db01f2edc144d45a0c9fdf53"
        },
        "date": 1794569987166,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4934.391807602826,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 64268.85481823126,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5805.977374437872,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1902044.6804997963,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2610238.3094999995,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 260765.79946641286,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2293254.1536363633,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58824.34199306385,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 31754.631080301915,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 203928.69999686492,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1899790.4285739737,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 38578.53204070277,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21369.612471308676,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2268268.063181819,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 773863.0479788987,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8917908.353333335,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 991260.3338623414,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 182035.26963963214,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8589058.920000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8908513.97,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8879072.02166667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 924039.7200434488,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 988112.932626185,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1089814.4070432184,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 147447.7911856053,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 182048.15576519596,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 284463.27713090397,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5f858e1f87e1e2bcdcdbffc854063d7210a4bc08",
          "message": "feat(mcp): rebuild the MCP server on rmcp with 17 tools, paged output and safe HTTP defaults (#315)\n\n* feat(mcp): serve MCP with the rmcp runtime on every transport\n\nReplace the hand-written JSON-RPC dispatcher with rmcp 3.9.0's server\nruntime on stdio and Streamable HTTP. One binary now serves clients on\nevery protocol revision the SDK knows, from 2024-11-05 through\n2026-07-28 (stateless).\n\nProtocol\n- Notifications get no reply, ping is answered, instructions and the\n  package version are delivered at initialize and server/discover.\n- Tool failures are tool errors (isError) with text a model can act on;\n  unknown arguments are rejected; unknown tools are -32602.\n- Tools carry titles, annotations and schemas generated from the\n  request types.\n- Every result is compact JSON under a hard byte budget\n  (max_output_bytes, default 80,000, ceiling 400,000) with an explicit\n  note of what was cut.\n- Analysis runs off the async runtime; a panic in an analyzer becomes a\n  tool error and the release profile no longer aborts on panic.\n\nHTTP\n- mcp-http binds 127.0.0.1 by default (--host to change it), checks\n  Host and Origin on every route, has no wildcard CORS, and takes an\n  optional bearer token (--auth-token / FILE_SCANNER_AUTH_TOKEN).\n- mcp-sse is a deprecated alias for mcp-http; the old /sse route is\n  gone.\n- REST helper routes are kept; /tools/list and /tools/call go through\n  the same tool router.\n- Graceful shutdown on SIGINT and SIGTERM.\n\nFile-system scope\n- --allow-root / FILE_SCANNER_ALLOWED_ROOTS limits what any tool may\n  read, including through symlinks inside a directory argument.\n- A leading ~/ is expanded; FIFOs, sockets and devices are refused.\n\nCache\n- A section cache keyed by file SHA-256 keeps the full sections of a\n  run (compressed, bounded) so later single-section calls on the same\n  file are answered from it.\n- Cache directory and files are private to the user.\n\nRemoved: the uncompiled src/mcp tree, src/hash_wrapper.rs and the two\nMCP refactoring documents.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): make analyze_file an overview with cached drill-down tools\n\nA bare path returns a compact triage overview; sections, flags and all: true return summaries. query_analysis, disassemble, read_hex and compare_files page through the cached full results. Directories return a paged triage table. String extraction keeps offsets, categories and printable UTF-16 only.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): add search_strings, string_details and cache tools\n\nStrings can be searched in one file or across the session, with offsets; cache status, listing, search and clearing are MCP tools. The analysis history is bounded and written atomically to a per-user cache directory; --cache-dir and --no-cache control it.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): scan package sources and page npm and Python findings\n\nanalyze_npm_package and analyze_python_package return a short summary with reasons, scan source files with file and line, read lock files and requirements, and page dependencies, files and findings. Known-malicious lists are matched by name and version; unused modules are removed.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(binary): report fat Mach-O, signatures, entropy and dependencies accurately\n\nFat Mach-O slices are listed and one is analyzed, architecture names follow the CPU type, signature presence is reported without claiming verification, entropy verdicts no longer flag ordinary sections, and imports are attributed to their libraries.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(analysis): bound disassembly and control flow, calibrate vulnerability rules\n\nDisassembly and control-flow analysis are capped and report coverage, 32-bit x86 is decoded correctly, unsupported architectures say so, vulnerability rules resolve call targets by name, and call-graph and taint analysis gain path-based entry points.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): scan with YARA rule files, built-in rules, paging and limits\n\nyara_scan_file accepts rule text, a rule file or directory, or the built-in rules; compile errors are tool errors with line and column; matches are paged and capped; scans have file and time limits. Threat levels and behavioral findings carry evidence and are calibrated on ordinary files.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): page Java, APK and class analysis by view\n\nanalyze_java_file returns a summary first and pages classes, findings, resources and the manifest; the kind is detected from content; Android manifests are decoded; entry, nested-archive and total-size limits are enforced.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): add analyze_document and analyze_script\n\nPDF and Office documents get a bounded structural scan with paged findings (scripts, actions, attachments, macros); scripts get paged findings by category. Parsers are bounded against hostile input.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): add inspect_archive and content-based file kind detection\n\nZIP, tar, tar.gz, RAR and 7z listings are paged and filterable with risk flags; the file kind is detected from content, not the name. Archive readers are bounded against hostile input.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* chore(deps): drop six crates nothing uses\n\nstrsim, git2, url, edit-distance, threatflux-cache and the non-dev reqwest had no remaining use in src/ after the repository-integrity and typosquatting modules were removed. reqwest stays as a dev-dependency for the HTTP tests.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(cache): feed the string index once per file and keep tests out of the user cache\n\nThe session string index is fed idempotently by any tool, searches past the string cap say so, budget-cut pages report the rows sent, and tests use temporary cache directories.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* feat(mcp): wire file kinds, analyzer errors, slices and new sections into analyze_file\n\nThe overview names the file kind and the specialist tool for it; no section vanishes without the analyzer's reason; an arch argument selects a fat Mach-O slice; call_graph and taint are sections; strings are counted while scanning with a bounded kept list; a budget-cut disassembly listing continues where it stopped; directory checks are bounded; the server instructions describe all 17 tools.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(archives): bound 7z, tar and RAR readers and report what was not read\n\nCounts are checked against the header bytes, long-name and pax records have a total cap, later gzip members and data past the decompression limit are noted, stored content is not called a bomb, and UTC timestamps are marked.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(binary): bound symbol, version and signature reading on crafted files\n\nCounts and offsets from Mach-O and ELF headers are checked against the bytes present, signature detection reads only what it needs, entropy verdicts need a high-entropy region of real size, and imports are no longer counted as functions.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(analysis): disassemble fat Mach-O slices and ranges within memory budgets\n\nFat Mach-O files are analyzed through the selected slice, call and jump targets are recorded, one function or address range can be decoded on demand, function grouping no longer copies instructions per symbol, and noisy arithmetic rules are reported as counts.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(yara): answer later pages from one bounded result and calibrate built-in rules\n\nPaging no longer re-runs the scan or stores every result, a budget-cut page reports the rows sent, generic built-in rules no longer mark ordinary system binaries as known malware, and the CLI gains --max-files, --timeout and rule files.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(java): charge every parsed structure to one memory and work budget\n\nConstant-pool strings are shared, long names are cut with a note, nested prefixed archives are opened, lists are paged with honest counts, and the CLI detects Java input by content.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(documents): bound Office macro reading and rescan PDFs from the xref table\n\nThe PROJECT-stream fallback has module and work budgets, short Office input is an error again, and a PDF whose objects hide inside a stream is found through its cross-reference table.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(packages): restore install-script detection and read standard Python metadata\n\nDownload-and-execute install scripts are findings again, .d.ts files and comment prefixes no longer hide code, tar headers are bounded, pyproject.toml and setup.py metadata are read correctly, and ordinary sdists are no longer rated High.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* chore(deps): keep git2 so the reviewed native zlib pin stays in the graph\n\nDropping git2 removed libz-sys from the crate graph, which leaves the vendored libz-sys patch unused and fails scripts/check-native-zlib.py. git2 has no use in src/ any more; removing it belongs with a change to that guard.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: describe the MCP server as built\n\nRewrite docs/MCP.md, README, CLAUDE.md, the deployment and security guides,\nUSAGE, API, ARCHITECTURE, FAQ and INSTALLATION for the rmcp server: 17 tools,\nstdio and Streamable HTTP, overview-first analysis with paged drill-down, the\nsection cache, path policy and HTTP safety flags. Add server.json for the MCP\nregistry, the registry label in the Dockerfile, and extend scripts/mcp-smoke.py\nto check the tool list and a cached drill-down.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): bound the stored control-flow lists and keep budget-sized pages whole\n\nLoops, exit blocks, unreachable blocks and block links share caps and report true counts. A page sized by fit_rows keeps a reserve for the caller's fields. Two tests paged lists that are now short.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(cache): steady shutdown under load and clearer cache notes\n\nMinor fixes from the last review of the strings and cache tools.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(binary): walk Mach-O export tries and bind opcodes safely\n\nThe export trie is walked iteratively with a visited set, bind opcodes are checked before goblin reads them, names are capped against one budget, forged code signatures no longer exempt entropy, and data symbols are not counted as functions.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(analysis): stop copying bind names per stub and bound the bind walk\n\nStub and indirect-symbol names are shared, an out-of-range segment index ends the walk, and the typed control-flow graph stays within its caps.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(yara): check the budget before building match detail\n\nMatch detail is built only for rows that will be sent, and three simulated-malware samples no longer rate Clean.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(documents): read PDF objects past the rescan window and loose headers\n\nAn object cut by the 1 MiB window is reported as not fully read, a script without endobj is listed, and headers with long whitespace runs are found.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(archives): list ZIP entries the end record does not count\n\nThe central directory is walked when the declared count is lower than what it holds, multi-byte tar names are clipped, and long-name archives stay within time and memory bounds.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(java): bound constant pools and entry names, rate unread content honestly\n\nThe constant pool is sized by the bytes present, entry names are clipped, nested or encrypted content that was not read is rated Medium with a warning, and class-view lists share the output budget.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(packages): close comment-evasion routes and bound tar walks\n\nComments are found across lone CR and Unicode line ends, docstring examples are not rated as code, zero-block runs and repeated long-name headers are bounded or refused.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: correct the MCP guides after a literal-follow review\n\nFix the Docker cache location, the environment-variable list, the YAML excerpt\nin USAGE, and the Docker HTTP recipe that generated a token nobody could read.\nMark the worked examples as illustrative, add the registry name line to the\nREADME, state the per-file YARA rule limits and the source extensions the\npackage tools read, list what server.json needs before it can be published,\nand make the Makefile's docker-run-http bind loopback with a token and a\nread-only mount. Wrap prose to the lint width.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): make arch select the slice for every code section\n\nAn arch the file does not have is a tool error that names the slices present. Control-flow rows carry true loop and exit-block counts, a directory entry that is a FIFO, socket or device is skipped and listed, and the server instructions and the disassemble description say what the tools do.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(cache): drop rows another server cleared and steady the start-up tests\n\nStart-up tests wait for the banner lines they assert on and use a temporary cache directory. search_strings and string_details say when a total is a lower bound.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(binary): bound PE import names and refuse import tables that cost too much\n\nPE import and DLL names are capped and charged to the shared name budget, and a pre-check walks the import lookup tables before goblin so a small file with one long name on many thunks is refused instead of costing gigabytes.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(analysis): say when imports were left unnamed and clip call-graph names\n\nUnbound SET_SYMBOL names are dropped, call-graph node names are clipped, a cut import map adds a note, and the package's tests no longer assert wall-clock durations.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(yara): check each walked entry inside the file and time limits\n\nThe whole-tree pre-check of the scanned path is replaced by a per-entry check, special files are listed as skipped, the three newest built-in rules no longer match ordinary identifiers and prose, and the description gives no rule count.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(archives): find the ZIP end record the way extractors do\n\nTrailing bytes after the end record, a wrong ZIP64 locator offset and a lowered directory offset no longer hide entries. A directory read up to a cap says so instead of claiming a count mismatch.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(java): return one row when a class-view list misses its share\n\nThe retry no longer spends the whole unspent budget on one list, so walks at small budgets finish. The echoed filter is clipped.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(packages): rate unread inputs and vulnerable pins honestly, read multi-member archives\n\nA requirements or lock file with a known-vulnerable pin is no longer rated Safe, gzip members and zero padding between them are read through, the slow directory path is fixed, the tool descriptions list every source extension read, and a malformed test fixture is corrected.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(binary): measure a PE import name where goblin reads it\n\nThe import pre-check mapped rva + 2, so a hint in the last two bytes of a\nsection measured a zero-length name and the table was not refused. Map the\nRVA first, then step over the hint. Also print the expanded --allow-root\npaths in the start-up banner, and name 0.3.10 as the current release in the\ndeployment docs.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: correct paging, cache and protocol notes after the real-client review\n\nDocument the cut markers per answer kind (truncated, hint, note), the\nper-tool paging field names, the headers a stateless 2026-07-28 request\nneeds over HTTP, the SDK-level replies to batches and malformed bodies,\nand what --no-cache does and does not skip.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): reach every function by name and offer only steps that run\n\ndisassemble resolves a name through the symbol table when the grouped\nfunction list is capped, and capped lists say so on every page. Next\nsteps carry real arguments and the caller's arch, and the overview\noffers only the sections that apply to the kind of file. Slice names in\nthe overview are the names arch accepts. The triage walk counts links\nthat leave the allowed roots and no longer fails on them.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(cache): record string offsets from analyze_file and clear the same things over REST\n\nstring_details returns offsets for strings indexed by analyze_file.\nPOST /cache/clear clears what the cache_clear tool clears. The stdio\nserver exits when its input closes.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(analysis): ask the parse guards before every object parse\n\nThe control-flow and disassembly entry points check PE import tables\nand Mach-O load commands before parsing, and their errors name the\ndisassemble tool.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(yara): stop rating ordinary files as threats on weak matches\n\nShort, common strings no longer raise the threat level on their own, so\neditors, documentation and interpreters rate clean. The scan reports\nwhich limit stopped it, and a symlinked root is not listed as skipped.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(documents): never rate a PDF with no readable body low\n\nA PDF whose body could not be read is rated at least medium and says\nwhy. Findings beyond the list caps are reachable by paging.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(archives): never rate an encrypted archive low\n\nAn archive whose entries could not be read is rated at least medium.\nNested archives are noted, unknown counts are explicit nulls, and a\npossible bomb is a risk indicator.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(java): name nested libraries by their full path and honour --no-cache\n\nA library two levels deep is named with its parent\n(a.war!WEB-INF/lib/util.jar), so same-named libraries can be told\napart. The in-memory result store respects --no-cache and can be\nemptied. DEX files count as unread content.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(packages): follow install hooks into the script they run\n\nAn install hook that runs a JavaScript or Python file is judged by what\nthat file does, so a dropper written with Node APIs is rated Critical.\nA dependency on a known-malicious release is rated High or above, a\ntyposquat at least Medium, and unsafe tar paths are reported.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(java): open a class by the container path findings give, and clear the result store with the cache\n\nview=class split the container from the class name only after turning\nslashes into dots, so a copy inside WEB-INF/lib could not be opened by\nthe name findings and also_in list. cache_clear now drops the server's\nin-memory Java results too.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): make four argument descriptions say what the server does\n\nThe budget description named only truncated although cut pages carry\nhint or note; rule_path loads a rule file of any extension; the\ncontrol-flow error for a stripped binary names the disassemble tool.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: bring the MCP guide and changelog in line with the merged server\n\nRe-ran every example that shows a rating or next steps, documented the\nnew slice names, function lookup beyond the grouped table, nested Java\npaths, package scoring and the weak-evidence marker, and merged the\nchangelog entries of the last fix rounds.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: name 0.3.11 as the current release\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): give next steps one shape and Java archives the Java overview\n\nEvery analyze_file next step carries gives. The function-list step\npasses an address when the name is shared, and function accepts a\ndecimal address. A .war, .ear or .aar gets the Java archive overview and\nno zip is offered native sections. The threats cache keys carry a\nrevision, and the threats filter searches a row's metadata.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(disassembly): choose the decoder from the PE machine field\n\nAn ARM64 PE was decoded as x86-64. The decoder now follows the COFF\nmachine value and refuses machines it cannot decode. The digest prints\nuniversal slices by the names arch accepts.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(packages): tie a run to what was written and stop rating configuration as exfiltration\n\nA download-write-run finding needs the run to start what was written\n(same name, field, expression or literal, or a shell or interpreter).\nReading one named environment variable is no longer data exfiltration;\nsending the whole environment still is. A decoded command passed to a\nprocess call is a finding, an obfuscated file run by an install hook\ncounts as install-time code, and hooks are followed through cd, leading\nassignments and extensionless paths.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(archives): make inspect_archive next steps callable and refuse scripts in unsupported languages\n\nNext steps are objects with tool, arguments and gives; advice moved to\nthe summary notes. Directory triage names universal slices as arch\naccepts them. A script whose shebang names an unsupported interpreter is\nrefused instead of guessed. A page with a very long path drops examples\nbefore it would cut the path.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(yara): require more than one thin string before a file rates Suspicious\n\nA lone schtasks mention, two hypervisor names or two short byte\npatterns in a large binary are weak evidence. A padding run is weak\nwhen no other string satisfied the rule. A Python dup2 reverse shell is\ncaught.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(cache): keep cache and string listings inside the allowed roots\n\nWith --allow-root, cache_status, the REST cache and string routes,\nsearch_strings and string_details leave out entries for files outside\nthe roots. /strings/details answers 404 for an unknown string, the stdio\nserver exits 0 on SIGTERM, and next steps are objects.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(mcp): say what the disassembly range holds when an address is outside it\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* chore(security): re-review the CodeQL token inventory after the MCP rebuild\n\nSeven first-party files in the inventory changed and no vendored source.\nThe matching lines are the scanner's own certificate report types and\nchecks; none uses a YARA-X certificate, thumbprint or TLSH value.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* test(mcp): expect the new wording of the out-of-range disassemble message\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: add analysis isolation to the roadmap\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* docs: sync the guides with the final server\n\nNext steps have one shape in every tool, --allow-root also filters the\ncache and string listings, and the package, threat, Java archive and PE\nsections describe what the last fix round changed.\n\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>\n\n* fix(ci): bound shared ELF fixture allocation and restore Windows lint\n\n* fix(mcp): keep next-step paths whole under max_output_bytes\n\nA small max_output_bytes no longer shortens a path inside a next step: the\nstep is kept whole or dropped and listed under truncated, and answers just\nover the budget keep more content. The overview stops offering steps that\nwould fail (analyze_script for Perl, Ruby, PHP, Lua and AWK; inspect_archive\nfor an unreadable archive), offers both package tools for a .tgz, and drops\nthe symbols note on Java archives.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(mcp): print canonical paths in cache listings of rooted servers\n\nWith --allow-root, cache_status list/search and REST /cache/list and /cache/search\nnow print each row's canonical path in file_path and tool_args, so a file stored\nunder a \"..\" spelling no longer reveals a directory outside the roots.\nfile_path_pattern matches the printed path; other path arguments such as yara\nrule_path show canonically, or as \"<outside the allowed roots>\".\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* test(ci): use the reported Mach-O architecture on macOS\n\n* docs: follow the last fix round\n\nDescribe the final behavior in the guides and changelog: arm64/aarch64\nslice choice, overview steps that only offer calls that work, next_steps\nkept whole under max_output_bytes, canonical paths in rooted cache\nlistings and /strings/related filtering, the narrowed persistence and\nbackdoor rules, and the setup.py literal-run cases.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(mcp): rehash rewritten files, count unread package sources, recheck detached signatures\n\nsearch_strings no longer reuses an old SHA-256 after a same-length in-place rewrite\nwith the modification time put back (Unix change time, device and inode must match).\nnpm and Python package analyses no longer count unreadable sources as scanned: the\nanswer says how many were not read, and such a package is never rated Safe.\nThe analyze_file signatures section is recomputed whenever <file>.sig or <file>.asc\nexists, and signature answers stored by earlier builds are not served.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(mcp): keep detached signature files inside the allowed roots\n\nOn a server started with --allow-root, a <file>.sig or <file>.asc that is\na link resolving outside the allowed roots is no longer opened or handed to\ngpg, so no line of the outside file can come back in verification_status.\nThe signatures section now says such a side file exists but was not read,\nwithout printing its target. A link to a file inside the roots is still\nverified, and servers without roots and the command line are unchanged.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(packages): calibrate the npm and Python package rules\n\n- Exfiltration hosts (webhook.site, oast.*, interact.sh, ...) match only as\n  host names, so property reads such as sonner's toast.promise are no longer\n  rated Critical \"Data exfiltration\".\n- Compiled TypeScript droppers (node_https_1.default.get, (0, x.spawn)(...))\n  and runs started on a quoted literal now rate like the plain spelling.\n- Python asyncio subprocess calls, aiohttp downloads and os.write count in the\n  download, write and run checks; a decoded payload passed to a process call\n  rates High at least. Package cache keys move to v3.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(threats): keep anti-analysis level for source that calls the technique\n\nSource files that call an anti-debug or anti-VM technique (IsDebuggerPresent(,\nCheckRemoteDebuggerPresent(, ptrace(PTRACE_TRACEME, a /proc/self/status read,\nsysctl with P_TRACED, or a file read beside a DMI product path) rate Suspicious\nagain instead of being dismissed as prose. Names in strings, comments, backtick\nspans, Markdown documents or plain prose stay weak evidence (Clean). The cached\nthreats sections move to revision 3 so results of earlier builds are not served.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(mcp): never hand gpg a side file that is not a regular signature\n\nA .sig or .asc file beside the analyzed file that is a named pipe, socket, device,\ndirectory or larger than 16 MiB is no longer opened or passed to gpg (server and\ncommand-line scanner); the signatures answer says it exists, was not read, and why.\nThe roots policy reaches the signature check as an explicit argument now.\nThe library methods analyze_file, analyze_npm_package, analyze_python_package and\nyara_scan_file apply the same allowed-roots checks and errors as the registered tools.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* fix(mcp): confine the last library entry points to the allowed roots\n\nOn a server state with allowed roots, the library methods\nFileScannerMcp::llm_analyze_file and FileScannerMcp::analyze_java_file now\nrefuse a path outside the roots, or a link leaving them, with the same text\nas the registered tools, instead of reading the file.\nServerState::file_sha256 also refuses such a path instead of hashing it.\nWithout allowed roots nothing changes; the MCP and REST tools are unaffected.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* docs: describe the package and threat-rule fixes\n\nDocument the run-to-write tie (path words, 4+ character literals, quoted\nliteral runs), compiled TypeScript and asyncio spellings, whole-host\nexfiltration matching, the decoded-payload High floor and the v3 cache\nkeys, plus the anti_analysis call test and the known limits of both\nrule sets. Every example and rating was re-run against the built binary.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n* chore(security): rehash the reviewed signature and analyze_file sources\n\nsrc/signature.rs and src/mcp_server/tools_analyze.rs changed in the MCP\nhardening round. Their certificate lines are the scanner's own report\ntypes, the PE certificate-table lookup and the codesign authority chain;\nneither file imports YARA-X or uses a YARA-X certificate, thumbprint or\nTLSH value. Refresh their inventory hashes and the policy digest and\nrecord the 2026-11-13 re-review.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n\n---------\n\nCo-authored-by: Claude Fable 5.2 <noreply@anthropic.com>",
          "timestamp": "2026-11-13T09:04:45-05:00",
          "tree_id": "d9d11091259111ccb2973c8a817ab941219fa75e",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/5f858e1f87e1e2bcdcdbffc854063d7210a4bc08"
        },
        "date": 1794580669437,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 4798.242202708047,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 43177.841843418166,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 5473.1883998381,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1504850.296404941,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2067644.2740000007,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 207356.596038331,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 1739250.4788400182,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 47195.29322711757,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 28522.925431881744,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 170969.8494336738,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1641088.2154014516,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 37151.53901291827,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21821.843170087348,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 1845014.6633266523,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 657019.2231655151,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 5924574.816666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 683203.5367657345,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 130250.12994759022,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 5820747.61222222,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 5938353.769999999,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 5893376.197777778,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 644814.6779071114,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 692847.6628545625,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 698577.5175662207,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 108731.66444685578,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 125772.77156559873,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 152245.85315955154,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "49dfddc0ee57ba5bbc395aff2920add49d184006",
          "message": "fix(deps): update cc and restore Windows lint (#319)\n\n* fix(deps): update cc to 1.11.2\n\n* fix(ci): gate Unix-only review test helpers",
          "timestamp": "2026-11-13T10:46:25-05:00",
          "tree_id": "738298316d4f465e7e8c11e96528bdcf81b10c14",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/49dfddc0ee57ba5bbc395aff2920add49d184006"
        },
        "date": 1794586949402,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5290.566768275183,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 64223.89482655443,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6448.473523202419,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1912952.030064566,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2619822.2935000006,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 261417.56515280227,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2271316.639999999,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 59380.260237380986,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 32582.554194035725,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 205004.8527511261,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1899262.726580025,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 37850.76945746463,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 21734.905072847403,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2275602.5068181823,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 807317.1631846919,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8853857.816666665,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1005151.4560249265,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 173174.9576493606,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8609668.566666666,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8872647.026666664,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8837567.824999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 967782.5344466164,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1007815.0159741772,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1034887.7224362653,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 152980.11399073963,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 173687.46672503828,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 205817.8693781351,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "3350e9842a9ee78a35b0fbfd965dc4b71b309fbe",
          "message": "fix(mcp): last-round fixes for cache clearing, package cache keys, signer text and schemas (#320)\n\nCarries the fix round that was still in review when #315 merged.\n\n- REST POST /cache/clear reads the scope from the query string or a JSON\n  body, and refuses an unknown scope or two different scopes with a 400\n  that clears nothing.\n- Rooted servers apply the limit of /strings/search and /strings/related\n  to the rows the caller may see.\n- string_details marks counts that stopped at the 10-occurrence cap.\n- A package directory is cached only when the key covered its whole tree,\n  and unsafe archive entries are counted in full.\n- The GPG signer is the name alone, disassemble accepts a partial function\n  name, the binary_info and yara_indicators cache keys carry the name\n  class, and tool schemas carry no format on numbers.\n- Docs for these and for the late fixes of #315, and the CodeQL guard\n  rehash for the signer change.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>",
          "timestamp": "2026-11-13T12:25:51-05:00",
          "tree_id": "bdba4bd77c40d7b36498ecb5ea0a0e91fa364fda",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/3350e9842a9ee78a35b0fbfd965dc4b71b309fbe"
        },
        "date": 1794592941759,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 5327.223823956589,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 64343.84392505279,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 6363.1493526354825,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1922297.5530271686,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2644454.1805263166,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 264241.59093876346,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2278935.9945454546,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 61158.50733773804,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 34140.938099492276,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 205671.6966320334,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1956947.1271948882,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 38926.45714173828,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 22559.611333619076,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2264201.296363637,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 805510.813300856,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 8692874.931666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 994941.0672684609,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 168759.0991684056,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 8439981.568333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 8743115.04666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 8687486.174999997,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 955634.9047690389,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 991732.0261651829,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1021373.6759856123,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 152351.69010536568,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 170082.54548077605,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 205469.85533667373,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5669b25171eb4fd69a421dad5be189e8051f1eba",
          "message": "chore: release v0.4.1",
          "timestamp": "2026-11-13T19:04:15Z",
          "tree_id": "6fb211d0c26066765f69dc47a939527a9f933dfd",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/5669b25171eb4fd69a421dad5be189e8051f1eba"
        },
        "date": 1794599176665,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 6041.967617404708,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 82941.73532062404,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 7249.563765641356,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2272656.3713636356,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3173225.604375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 329797.57462115475,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2683304.304736843,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 76868.9453842194,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 47983.72270462593,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 238054.91239050732,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2207787.3773913044,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 48072.16799187262,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 28373.1491991377,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2689484.3915789467,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 1024616.0816885179,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9999618.86,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1156417.4115129996,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 221414.11656422514,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 9598258.393333334,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9980202.490000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9899889.695,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1105354.7522420052,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1161836.137052344,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1194527.193310241,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 197085.518859694,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 225359.66928521293,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 262801.16838343313,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "wyattroersma@gmail.com",
            "name": "Wyatt Roersma",
            "username": "wroersma"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "8828f69ca29c7476feb7f31774b6f8f97385a717",
          "message": "fix(mcp): refuse a JSON array body on cache clear and count unsafe archive entries once (#321)\n\n- REST `POST /cache/clear` now refuses any body that is not a JSON object. An array such as `[null]` used to be accepted and cleared the whole cache; it now gets a 400 that says nothing was cleared.\n- Package scans count each unsafe archive entry once. An entry with an unsafe path and an unsafe link target is one entry with two findings, and the note gives both numbers when they differ. Listed findings stop at 50.\n- Package cache keys move to `package:npm:v5` and `package:python:v5`, so results cached by older builds are not reused.\n- `server.json`, the `Dockerfile` default version and the deployment and API docs name release 0.4.0.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nCo-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>",
          "timestamp": "2026-11-13T15:12:38-05:00",
          "tree_id": "a29a065e4650f483a7f266ef34111f24099bc640",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/8828f69ca29c7476feb7f31774b6f8f97385a717"
        },
        "date": 1794602924018,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2197.273423846951,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 99859.58144474681,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3011.3323301768983,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 1794126.5360216512,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 2739201.30631579,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 248320.11084992177,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 2247653.7504347814,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 58135.6713838993,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 33081.22432571011,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 215269.14994284365,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 1876904.9335601183,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 49752.21235502751,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 33602.12871876481,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 2469467.035714285,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 784840.691902709,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 6978711.93125,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 868605.3505037235,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 163168.48080753334,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 6092856.2425,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 7400983.494285714,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 6656375.665,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 710103.2070155835,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 877810.5144020873,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 885874.0907130903,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 137899.8129874095,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 164898.55082083584,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 196909.88828578324,
            "unit": "ns"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "338381904+threatflux-automation[bot]@users.noreply.github.com",
            "name": "threatflux-automation[bot]",
            "username": "threatflux-automation[bot]"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "80f5aafda9e1a8bb31e58b2e4544f5152972fe4c",
          "message": "chore: release v0.4.2",
          "timestamp": "2026-11-13T21:38:33Z",
          "tree_id": "c965d229336264569f8220c707fb59285e2ab365",
          "url": "https://github.com/ThreatFlux/file-scanner/commit/80f5aafda9e1a8bb31e58b2e4544f5152972fe4c"
        },
        "date": 1794608519043,
        "tool": "customSmallerIsBetter",
        "benches": [
          {
            "name": "binary_parsing/parse_elf",
            "value": 2959.8190278312127,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_large_binary",
            "value": 144444.5999994779,
            "unit": "ns"
          },
          {
            "name": "binary_parsing/parse_pe",
            "value": 3944.093111969924,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/concurrent_hashing",
            "value": 2992567.150588235,
            "unit": "ns"
          },
          {
            "name": "concurrent_hashing/sequential_hashing",
            "value": 3932534.95,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/100KB",
            "value": 407556.275855455,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1024KB",
            "value": 3153081.194375,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/10KB",
            "value": 73815.52763256646,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_all_hashes/1KB",
            "value": 36312.248920114704,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/100KB",
            "value": 226718.3134579994,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1024KB",
            "value": 2071238.9887999997,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/10KB",
            "value": 44717.141385350245,
            "unit": "ns"
          },
          {
            "name": "hash_calculations/calculate_md5_only/1KB",
            "value": 27363.67933857953,
            "unit": "ns"
          },
          {
            "name": "individual_hash_algorithms/all_hashes_1mb",
            "value": 3471945.08125,
            "unit": "ns"
          },
          {
            "name": "string_categorization/extract_with_categorization",
            "value": 972695.8785268372,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/10000_strings",
            "value": 9722005.576666668,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/1000_strings",
            "value": 1124192.679676802,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings/100_strings",
            "value": 208343.78230549378,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_16",
            "value": 9176368.693333333,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_4",
            "value": 9719565.27666667,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/10000_strings_min_8",
            "value": 9625220.240000002,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_16",
            "value": 1037586.5832388012,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_4",
            "value": 1129791.8051223438,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/1000_strings_min_8",
            "value": 1143549.545865032,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_16",
            "value": 180194.74048743694,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_4",
            "value": 209113.0087260589,
            "unit": "ns"
          },
          {
            "name": "string_extraction/extract_strings_min_len/100_strings_min_8",
            "value": 246009.76099391346,
            "unit": "ns"
          }
        ]
      }
    ]
  }
}