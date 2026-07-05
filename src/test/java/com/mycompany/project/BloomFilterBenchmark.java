/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author angadh
 */

package com.mycompany.project;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Bloom Filter Speed Benchmark
 * Measures lookup time across 4 scales to prove O(1) constant-time behavior.
 * The lookup time must NOT grow as the filter fills up -- that's the core claim.
 */
@DisplayName("Bloom Filter Speed Benchmark")
class BloomFilterBenchmark {

    private static final int WARMUP_OPS   = 100_000;   // JIT warmup iterations
    private static final int MEASURE_OPS  = 1_000_000; // ops per timing window

    /**
     * Runs a timed lookup block and returns nanoseconds per operation.
     * Performs JIT warmup before measuring to avoid timing the JVM startup cost.
     */
    private double timeLookupsNsPerOp(TransactionBloomFilter bf, int scale) {
        // JIT warmup -- run WARMUP_OPS lookups, discard the time
        for (int i = 0; i < WARMUP_OPS; i++) {
            bf.contains("WARMUP_" + (i % 1000));
        }

        // Now measure MEASURE_OPS lookups
        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_OPS; i++) {
            bf.contains("TX_" + (i % scale));
        }
        long elapsed = System.nanoTime() - start;
        return (double) elapsed / MEASURE_OPS;
    }

    @Test
    @DisplayName("O(1) benchmark: lookup time stays flat as filter scales from 100 to 1M entries")
    void bloomFilterIsConstantTime() {
        int[] scales = {100, 1_000, 10_000, 100_000, 1_000_000};

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           BLOOM FILTER SPEED BENCHMARK                       ║");
        System.out.println("╠══════════════╦══════════════╦══════════════╦═════════════════╣");
        System.out.println("║ Entries      ║ ns / lookup  ║ ms / 1M ops  ║ Status          ║");
        System.out.println("╠══════════════╬══════════════╬══════════════╬═════════════════╣");

        double[] nsPerOp = new double[scales.length];

        for (int s = 0; s < scales.length; s++) {
            int scale = scales[s];
            // Bit-array sized 10x the entry count to keep false-positive rate low
            TransactionBloomFilter bf = new TransactionBloomFilter(scale * 10);

            // Pre-populate the filter with 'scale' unique IDs
            for (int i = 0; i < scale; i++) {
                bf.add("TX_" + i);
            }

            nsPerOp[s] = timeLookupsNsPerOp(bf, scale);
            double msPerMillion = nsPerOp[s] * MEASURE_OPS / 1_000_000.0;

            String status = nsPerOp[s] < 100 ? "FAST (<100ns)" : "OK";
            System.out.printf("║ %-12s ║ %-12.2f ║ %-12.2f ║ %-15s ║%n",
                String.format("%,d", scale),
                nsPerOp[s],
                msPerMillion,
                status);
        }

        System.out.println("╚══════════════╩══════════════╩══════════════╩═════════════════╝");

        // --- O(1) assertion ---
        // For true O(1), the lookup time at 1M entries must be within 3x of
        // the lookup time at 100 entries. Any linear algorithm would be 10,000x
        // slower at 1M entries vs 100 entries.
        double ratio = nsPerOp[scales.length - 1] / nsPerOp[0];
        System.out.printf("%n[O(1) PROOF] Time ratio (1M entries / 100 entries) = %.2fx%n", ratio);
        System.out.printf("[O(1) PROOF] For O(n) this ratio would be ~10,000x -- we got %.2fx%n", ratio);

        assertTrue(ratio < 3.0,
            String.format("Lookup time grew %.2fx from 100 to 1M entries -- expected <3x for O(1)", ratio));

        System.out.println("[PASS] Bloom Filter lookup is O(1) constant time -- confirmed.");
    }

    @Test
    @DisplayName("Throughput benchmark: raw operations per second")
    void throughputBenchmark() {
        // Festival scale: 1.5 crore = 15M transactions
        // We use a 150M-bit array (about 18MB) to handle that at low false-positive rate
        int festivalScale = 150_000_000;
        TransactionBloomFilter bf = new TransactionBloomFilter(festivalScale);

        // Pre-load 10,000 transactions (realistic batch size from one vendor sync)
        int batchSize = 10_000;
        for (int i = 0; i < batchSize; i++) {
            bf.add("TX_" + i);
        }

        // Warmup
        for (int i = 0; i < WARMUP_OPS; i++) bf.contains("TX_" + i);

        // Measure
        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_OPS; i++) {
            bf.contains("TX_" + i);
        }
        long elapsed = System.nanoTime() - start;

        double nsPerOp      = (double) elapsed / MEASURE_OPS;
        double opsPerSecond = 1_000_000_000.0 / nsPerOp;
        double msFor15Cr    = (15_000_000.0 * nsPerOp) / 1_000_000.0;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           THROUGHPUT BENCHMARK (Festival Scale)              ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║  ns per lookup:           %-34.2f ║%n", nsPerOp);
        System.out.printf( "║  Lookups per second:      %-34s ║%n", String.format("%,.0f", opsPerSecond));
        System.out.printf( "║  Time to scan 1.5Cr txns: %-31.2f ms ║%n", msFor15Cr);
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║  Presentation claim:      <1ms per lookup            %s   ║%n",
            nsPerOp < 1_000_000 ? "[CONFIRMED]" : "[EXCEEDED] ");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // Each individual lookup must be under 1ms (1,000,000 ns)
        assertTrue(nsPerOp < 1_000_000,
            String.format("Single lookup took %.2f ns -- must be under 1ms (1,000,000 ns)", nsPerOp));

        System.out.println("[PASS] Sub-millisecond lookup confirmed at festival scale.");
    }
}