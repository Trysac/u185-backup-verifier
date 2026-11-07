# Project record

## Objective

Verify backup archives against a SHA-256 manifest, perform safe restore tests into empty directories, and validate archive freshness using an injected clock.

## Scope

- Deterministic manifest creation and parsing.
- In-memory archive integrity verification (tar, zip) using `hashlib`.
- Safe restore verification ensuring no traversal or device node risks.
- Freshness monitoring for backup rotation.
- CLI support for all primary operations.

## Out-of-scope

- Encryption, database-specific dumps, cloud storage drivers, incremental chain management, and automated scheduling.

## Factory run u185 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | gemini-3.8-flash | yes | 4691 | 15736 | 0 | 0 | 0.0313 |
| fix-1 | gemini-3.8-flash | no | 53751 | 1058 | 0 | 274345 | 0.0649 |
| fix-2 | gemini-3.8-flash | no | 98884 | 1351 | 0 | 1039911 | 0.1572 |
| fix-3 | gemini-3.8-flash | no | 20247 | 4456 | 0 | 33734 | 0.0344 |
| fix-4 | gemini-3.8-flash | no | 36023 | 841 | 0 | 132001 | 0.0401 |
| audit | gemini-3.1-flash-lite | no | 34581 | 350 | 0 | 22387 | 0.0097 |
| docs | gemini-3.1-flash-lite | no | 129343 | 1279 | 0 | 0 | 0.0343 |

Total: $0.3718. Prices: Anthropic list prices.
