# Dual-Layer Security Gateway

**CS F213 — Object Oriented Programming | BITS Pilani, Summer 2026**
**Group 12**
**Authors: Angadh & Mridul**

A dual-layer security gateway for a festival digital wallet ledger handling ₹1.5+ crore in transactions across 5,000–6,000 users. It sits in front of the wallet ledger and intercepts two attack vectors before any data reaches the database: **file tampering** (SHA-256 integrity checking) and **replay attacks** (custom Bloom Filter deduplication).

---

## Table of Contents

- [Problem](#problem)
- [Architecture](#architecture)
- [The Bloom Filter](#the-bloom-filter)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Setup](#setup)
- [Running the Tests](#running-the-tests)
- [Running the Integration Demo](#running-the-integration-demo)
- [Running the Large-Scale Stress Test](#running-the-large-scale-stress-test)
- [Running the Benchmarks](#running-the-benchmarks)
- [Advanced Java Features Used](#advanced-java-features-used)
- [Integration with the Wallet Platform](#integration-with-the-wallet-platform)
- [Future Work](#future-work)

---

## Problem

Vendor devices sync transaction batches to the central wallet ledger throughout the festival, often over unreliable networks. Two integrity risks arise:

- **Tampering in transit** — a batch is altered (amounts inflated, rows injected) between the vendor device and the ledger.
- **Replay attacks** — an already-processed transaction (or batch) is resubmitted to double-credit or double-debit a wallet.

The gateway sits between vendor CSV uploads and the wallet ledger, rejecting a batch before any row reaches the database.

| | |
|---|---|
| **Input** | CSV per vendor sync batch — `TxID,UserID,Amount` (with header row) |
| **Config input** | A trusted SHA-256 checksum per file |
| **Output (success)** | `List<Transaction>` — validated, de-duplicated |
| **Output (failure)** | `SecurityViolationException` naming the specific violation |
| **Persisted state** | Serialized `.ser` snapshot of the gateway, including everything the Bloom Filter has learned |

---

## Architecture

Built around the **Strategy pattern**. A `SecurityLayer` interface declares `execute(File)`, implemented by two static nested strategies inside `AdvancedSecurityGateway<T>`:

- **`GuavaIntegrityLayer`** (Layer 1) — computes a Guava SHA-256 hash and compares it to the trusted checksum.
- **`BloomFilterLayer`** (Layer 2) — parses the CSV and checks every transaction ID against a `TransactionBloomFilter` before accepting it.

The gateway composes both layers rather than inheriting from them, and the whole object graph — gateway, both layers, the Bloom Filter, and `Transaction` — is `Serializable`, so gateway state (including everything the Bloom Filter has seen) survives a service restart.

```
AdvancedSecurityGateway<T>
├── GuavaIntegrityLayer   implements SecurityLayer   (Layer 1: tamper detection)
├── BloomFilterLayer      implements SecurityLayer   (Layer 2: replay detection)
│   └── TransactionBloomFilter                       (custom data structure)
│   └── List<Transaction>                            (validated buffer)
└── SecurityViolationException                       (custom checked exception)
```

Adding a third layer (e.g. rate-limiting) means implementing `SecurityLayer` — no existing code needs to change (Open/Closed Principle).

---

## The Bloom Filter

`TransactionBloomFilter` is a probabilistic set-membership structure backed by a `BitSet`, used for O(1) replay detection with a fixed, bounded memory footprint — no false negatives, and a small, tunable false-positive rate.

**Kirsch–Mitzenmacher double hashing:** instead of implementing `k` independent hash functions, two base hashes are combined to derive all `k` probe positions:

- `h1(id)` — Java's built-in String hash, masked non-negative
- `h2(id)` — an independently implemented FNV-1a hash (different avalanche behaviour from `h1`)
- `probe_i = (h1 + i × h2) mod m` for `i = 0 … k-1`, computed in `long` precision to avoid overflow at large filter sizes

| Version | Hashes (k) | Bits (m) @ n=10M | False-positive rate |
|---|---|---|---|
| Original | 2 | 130,000,000 | ≈ 2.03% (~203k FP / 10M lookups) |
| **Current** | **7** | **500,000,000** | **≈ 0.0001% (~6 FP / 10M lookups)** |

The bit array is sized at ~50 bits per expected entry, keeping the false-positive rate constant regardless of scale.

---

## Project Structure

```
src/main/java/com/mycompany/project/
├── AdvancedSecurityGateway.java   # Gateway, both SecurityLayer strategies, Bloom Filter, Transaction, exception
├── HashSetBenchmark.java          # Bloom Filter vs HashSet: memory + speed at 1M–5M entries
├── BloomFilterBenchmark.java      # O(1) lookup proof + festival-scale throughput (JUnit 5)
├── IntegratedGatewayTest.java     # End-to-end demo: tamper attack + replay attack
├── LargeScaleGatewayTest.java     # 4-phase stress test against a real 10M-row CSV
└── SecurityGatewayUnitTest.java   # 20-test JUnit 5 suite (5 @Nested groups)

server.js                          # Generates the synthetic 10M-row transactions.csv
```

---

## Requirements

- Java 11+
- Maven 3.6+
- Node.js (only for generating the synthetic 10M-row dataset)

**Dependencies** (declared in `pom.xml`):
- `com.google.guava:guava:33.6.0-jre`
- `org.junit.jupiter:junit-jupiter:5.10.2`
- `maven-surefire-plugin:3.2.5`

---

## Setup

```bash
git clone <repo-url>
cd OOP_Project
mvn clean compile
```

---

## Running the Tests

```bash
mvn test
```

Runs all 20 tests in `SecurityGatewayUnitTest` via Surefire, across five `@Nested` groups:

| Group | Tests | Covers |
|---|---|---|
| `Layer1Tests` | 5 | Clean pass, tampered amount, injected row, unset checksum fails closed, re-verification |
| `Layer2Tests` | 5 | Unique rows buffer, replay throws, malformed amount throws (not a raw `NumberFormatException`), single-row files, buffer clears between runs |
| `BloomFilterTests` | 5 | add/contains correctness, unseen IDs, multiple distinct IDs, common-prefix IDs, empty string |
| `SerializationTests` | 3 | Reloaded gateway still blocks replay, still accepts new transactions, `.ser` file non-empty |
| `EndToEndTests` | 2 | `runAllLayers()` passes clean batch; stops at Layer 1 on tamper (never reaches Layer 2) |

A report is written to `target/surefire-reports/`.

---

## Running the Integration Demo

```bash
mvn compile exec:java -Dexec.mainClass="com.mycompany.project.IntegratedGatewayTest"
```

Or in NetBeans: right-click `IntegratedGatewayTest.java` → **Run File**.

Simulates a clean vendor sync, freezes gateway state, then runs:
- **Attack A (tamper):** an inflated transaction amount — caught by Layer 1.
- **Attack B (replay):** a genuinely-hashed file reusing an already-processed transaction ID — passes Layer 1, caught by Layer 2 after reloading serialized gateway state.

---

## Running the Large-Scale Stress Test

```bash
# 1. Generate the synthetic 10M-row dataset
node server.js
# writes transactions.csv under src/main/java/com/mycompany/project/

# 2. Run the 4-phase stress test (VM option recommended: -Xmx768m)
mvn compile exec:java -Dexec.mainClass="com.mycompany.project.LargeScaleGatewayTest"
```

- **Phase 1** — SHA-256 integrity check across the full 10M-row file
- **Phase 2** — Bloom Filter deduplication across all rows, timed for throughput
- **Phase 3** — reload gateway state from disk, replay a real transaction ID pulled from the dataset
- **Phase 4** — tamper attack on a small file, confirming Layer 1 fires independent of scale

Set `-Xmx768m` via NetBeans → Project Properties → Run → VM Options, or `MAVEN_OPTS`.

---

## Running the Benchmarks

```bash
# O(1) lookup proof + festival-scale throughput
mvn test -Dtest=BloomFilterBenchmark

# Bloom Filter vs HashSet: memory + insert/lookup speed (VM option: -Xmx2g)
mvn compile exec:java -Dexec.mainClass="com.mycompany.project.HashSetBenchmark"
```

`BloomFilterBenchmark` asserts lookup time at 1M entries stays within 3× of lookup time at 100 entries (proving O(1); a linear structure would show ~10,000×), and that a single lookup at festival scale (150M-bit array, sized for 1.5 crore transactions) stays under 1ms.

`HashSetBenchmark` compares memory, insert speed, and lookup speed against `java.util.HashSet<String>` at scales from 1M to 5M entries. At large scale, the Bloom Filter uses roughly an order of magnitude less memory than the HashSet's ~88-bytes-per-entry overhead, at a false-positive cost of ~0.0001%.

---

## Advanced Java Features Used

| Feature | Where |
|---|---|
| Generics | `AdvancedSecurityGateway<T>`, `List<Transaction>` |
| Custom exceptions | `SecurityViolationException` |
| File I/O | `BufferedReader`/`FileReader` with try-with-resources for streaming large CSVs; `PrintWriter` for fixtures |
| Serialization | `ObjectOutputStream`/`ObjectInputStream` for gateway state persistence |
| Static nested classes | `GuavaIntegrityLayer`, `BloomFilterLayer` (Strategy pattern) |
| Collections framework | `ArrayList`, `BitSet`, `HashSet` (benchmark baseline) |
| Third-party library | Google Guava (`Hashing.sha256()`, `Files.asByteSource()`) |
| Unit testing | JUnit 5 — `@Nested`, `@TempDir`, `@DisplayName`, Maven Surefire |

---

## Integration with the Wallet Platform

The gateway integrates via a file-based interface, consuming the same `TxID,UserID,Amount` CSV format the Django wallet backend's vendor-sync jobs already produce. It returns a `List<Transaction>` the existing ledger-crediting code can consume with no schema changes. In production it would run as a pre-processing step immediately before the wallet's Celery task that commits transactions to PostgreSQL, rejecting a batch outright before any row reaches the database. The serialized gateway state should be persisted to a durable volume so replay protection survives a restart.

---

## Future Work

- A third `SecurityLayer` for per-user/vendor rate-limiting, addable without touching existing layers.
- A counting Bloom Filter or Cuckoo Filter to support deletion (e.g. reversing a refunded transaction) — the current structure can't safely un-mark a bit.
- Direct JDBC/Celery integration in place of the file-based interface.
- Concurrent Bloom Filter population via `java.util.concurrent`, since `BitSet` isn't thread-safe for concurrent writers.

---

## License

Educational project submitted for CS F213, BITS Pilani. Not licensed for external use.
