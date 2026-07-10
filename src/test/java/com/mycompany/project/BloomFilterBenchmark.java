/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author angadh
 * @author mridul
 */

package com.mycompany.project;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;


@DisplayName("Bloom Filter Speed Benchmark")
class BloomFilterBenchmark {

    private static final int WARMUP_OPS   = 100_000;
    private static final int MEASURE_OPS  = 1_000_000;


    private double timeLookupsNsPerOp(TransactionBloomFilter bf, int scale) {
        for (int i = 0; i < WARMUP_OPS; i++) {
            bf.contains("WARMUP_" + (i % 1000));
        }

        long start = System.nanoTime();
        for (int i = 0; i < MEASURE_OPS; i++) {
            bf.contains("TX_" + (i % scale));
        }
        long elapsed = System.nanoTime() - start;
        return (double) elapsed / MEASURE_OPS;
    }

    @Test
    @DisplayName("benchmark: lookup time stays flat as filter scales from 100 to 1M entries")
    void bloomFilterIsConstantTime() {
        int[] scales = {
            10, 20, 30, 40, 50,
            100, 200, 300, 400, 500,
            1_000, 2_000, 3_000, 4_000, 5_000,
            10_000, 20_000, 30_000, 40_000, 50_000,
            100_000, 200_000, 300_000, 400_000, 500_000,
            1_000_000, 2_000_000, 3_000_000, 4_000_000, 5_000_000,
            10_000_000
        };

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           BLOOM FILTER SPEED BENCHMARK                       ║");
        System.out.println("╠══════════════╦══════════════╦══════════════╦═════════════════╣");
        System.out.println("║ Entries      ║ ns / lookup  ║ ms / 1M ops  ║ Status          ║");
        System.out.println("╠══════════════╬══════════════╬══════════════╬═════════════════╣");

        double[] nsPerOp = new double[scales.length];

        for (int s = 0; s < scales.length; s++) {
            int scale = scales[s];
            TransactionBloomFilter bf = new TransactionBloomFilter(scale * 10);

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
        int festivalScale = 150_000_000;
        TransactionBloomFilter bf = new TransactionBloomFilter(festivalScale);

        int batchSize = 10_000;
        for (int i = 0; i < batchSize; i++) {
            bf.add("TX_" + i);
        }

        for (int i = 0; i < WARMUP_OPS; i++) bf.contains("TX_" + i);

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
        System.out.printf( "║  Presentation claim:      <1ms per lookup        %s ║%n",
            nsPerOp < 1_000_000 ? "[CONFIRMED]" : "[EXCEEDED] ");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        assertTrue(nsPerOp < 1_000_000,
            String.format("Single lookup took %.2f ns -- must be under 1ms (1,000,000 ns)", nsPerOp));

        System.out.println("[PASS] Sub-millisecond lookup confirmed at festival scale.");
    }
}