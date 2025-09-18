window.BENCHMARK_DATA = {
  "lastUpdate": 1758175633664,
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
      }
    ]
  }
}