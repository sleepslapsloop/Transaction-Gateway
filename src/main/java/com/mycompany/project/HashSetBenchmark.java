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

/*
 * VM Options: -Xmx2g  (HashSet at 5M entries needs ~440MB alone)
 */

import java.util.HashSet;

public class HashSetBenchmark {

    private static final int BITS_PER_ENTRY = 50;
    private static final int WARMUP         = 50_000;

    private static final int[] SCALES = {
        1_000_000,
        2_000_000,
        3_000_000,
        4_000_000,
        5_000_000
    };

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════════════════════════════════════════╗");
        System.out.println("║              BLOOM FILTER  vs  HASHSET  —  Scaling Benchmark                                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
        System.out.println("  Bloom Filter bit-array = 50 bits/entry  (k=7 probes, ~0.0001% FP rate at every scale)\n");

        System.out.println("  ┌────────────┬──────────────┬──────────────┬──────────────┬──────────────┬──────────────┬───────────────┐");
        System.out.println("  │   Entries  │  BF Memory   │  HS Memory   │  Mem Saving  │  BF Insert   │  HS Insert   │  BF FP Count  │");
        System.out.println("  ├────────────┼──────────────┼──────────────┼──────────────┼──────────────┼──────────────┼───────────────┤");

        for (int n : SCALES) {
            runScale(n);
        }

        System.out.println("  └────────────┴──────────────┴──────────────┴──────────────┴──────────────┴──────────────┴───────────────┘");

        System.out.println("\n  ┌────────────┬──────────────┬──────────────┬");
        System.out.println("  │   Entries  │  BF Lookup   │  HS Lookup   │");
        System.out.println("  ├────────────┼──────────────┼──────────────┼");

        for (int n : SCALES) {
            runLookupScale(n);
        }

        System.out.println("  └────────────┴──────────────┴──────────────┴───────────────────────────────────────────────────────────┘");

        
    }

    private static void runScale(int n) {
        int bloomBits = n * BITS_PER_ENTRY;

        String[] known   = ids("TX_KNOWN_",  n);
        String[] unknown = ids("TX_UNSEEN_", n);

        long bfBytes = bloomBits / 8L;
        long hsBytesEst = (long) n * 88;  // ~88 bytes per String entry in HashMap

        TransactionBloomFilter bf = new TransactionBloomFilter(bloomBits);
        HashSet<String> hs = new HashSet<>(n * 2);

        TransactionBloomFilter wbf = new TransactionBloomFilter(WARMUP * BITS_PER_ENTRY);
        HashSet<String> whs = new HashSet<>();
        for (int i = 0; i < WARMUP; i++) { wbf.add(known[i]); whs.add(known[i]); }

        long t0 = System.nanoTime();
        for (String id : known) bf.add(id);
        long bfInsertNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        for (String id : known) hs.add(id);
        long hsInsertNs = System.nanoTime() - t0;

        long fp = 0;
        for (String id : unknown) if (bf.contains(id)) fp++;

        System.out.printf("  │ %,10d │ %8.1f MB   │ %8.1f MB   │ %10.1fx   │ %8.0f ns/op │ %8.0f ns/op │ %,13d │%n",
            n,
            bfBytes    / 1_048_576.0,
            hsBytesEst / 1_048_576.0,
            (double) hsBytesEst / bfBytes,
            (double) bfInsertNs / n,
            (double) hsInsertNs / n,
            fp);
    }

    private static void runLookupScale(int n) {
        int bloomBits = n * BITS_PER_ENTRY;
        String[] known = ids("TX_KNOWN_", n);

        TransactionBloomFilter bf = new TransactionBloomFilter(bloomBits);
        HashSet<String> hs = new HashSet<>(n * 2);
        for (String id : known) { bf.add(id); hs.add(id); }

        for (int i = 0; i < WARMUP; i++) {
            bf.contains(known[i % n]);
            hs.contains(known[i % n]);
        }

        long t0 = System.nanoTime();
        for (String id : known) bf.contains(id);
        long bfNs = System.nanoTime() - t0;

        t0 = System.nanoTime();
        for (String id : known) hs.contains(id);
        long hsNs = System.nanoTime() - t0;


        System.out.printf("  │ %,10d │ %8.0f ns/op │ %8.0f ns/op │%n",
            n,
            (double) bfNs / n,
            (double) hsNs / n);
    }

    private static String[] ids(String prefix, int count) {
        String[] arr = new String[count];
        for (int i = 0; i < count; i++)
            arr[i] = prefix + String.format("%07d", i);
        return arr;
    }
}
