window.BENCHMARK_DATA = {
  "lastUpdate": 1764475195666,
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
      }
    ]
  }
}