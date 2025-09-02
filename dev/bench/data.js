window.BENCHMARK_DATA = {
  "lastUpdate": 1756824228025,
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
      }
    ]
  }
}