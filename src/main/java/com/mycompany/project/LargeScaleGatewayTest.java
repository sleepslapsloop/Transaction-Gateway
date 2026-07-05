/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author angadh
 */

package com.mycompany.project;

import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import java.io.*;

/*
 * CS F213 Object Oriented Programming Project
 * BITS Pilani | Summer 2026
 *
 * LargeScaleGatewayTest
 * Stress-tests AdvancedSecurityGateway against the real 10M-row festival CSV.
 *
 * CSV format (3 columns, with header):
 *   TxID,UserID,Amount
 *   TX_00000000,1455,3556
 *
 * VM Options (NetBeans → Project Properties → Run → VM Options):
 *   -Xmx768m
 */

public class LargeScaleGatewayTest {

    private static final int    BLOOM_BITS = 900_000_000;
    private static final String CSV_PATH   = System.getProperty("csv.path",
        "src/main/java/com/mycompany/project/transactions.csv");
    private static final String STATE_FILE = "large_gateway.ser";

    public static void main(String[] args) throws Exception {
        System.out.println("=== LARGE-SCALE DUAL-LAYER GATEWAY TEST — 10M Transactions ===\n");

        File csv = new File(CSV_PATH);
        if (!csv.exists()) {
            System.err.println("[FATAL] CSV not found: " + csv.getAbsolutePath());
            System.exit(1);
        }
        System.out.printf("[INFO] File: %s  (%.1f MB)%n%n", csv.getAbsolutePath(),
                          csv.length() / 1_048_576.0);

        phase1_and_2(csv);
        phase3_Replay(csv);
        phase4_Tamper();

        System.out.println("\n=== ALL PHASES PASSED — GATEWAY VERIFIED AT FESTIVAL SCALE ===");
        new File(STATE_FILE).delete();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1 + 2: integrity check then deduplication on the full CSV
    // ─────────────────────────────────────────────────────────────────────────
    private static void phase1_and_2(File csv) throws Exception {
        System.out.println("--- PHASE 1: Layer 1 — SHA-256 Integrity Check ---");

        AdvancedSecurityGateway<Transaction> gateway =
            new AdvancedSecurityGateway<>(BLOOM_BITS);

        long t0       = System.currentTimeMillis();
        String hash   = Files.asByteSource(csv).hash(Hashing.sha256()).toString();
        long hashTime = System.currentTimeMillis() - t0;

        gateway.setExpectedChecksum(hash);
        gateway.verifyFileIntegrity(csv);

        System.out.printf("[Layer 1] Hashed %.1f MB in %,d ms%n%n",
                          csv.length() / 1_048_576.0, hashTime);

        System.out.println("--- PHASE 2: Layer 2 — Bloom Filter across all rows ---");
        System.out.println("[INFO] Processing 10M rows — this will take a few minutes...");

        t0 = System.currentTimeMillis();
        gateway.processAndDeduplicate(csv);
        long passTime = System.currentTimeMillis() - t0;

        int  count      = gateway.getValidatedTransactions().size();
        double rowsPerS = count / (passTime / 1000.0);

        System.out.printf("[Layer 2] %,d rows  |  %,d ms  |  %,.0f rows/sec  |  %.1f ns/lookup%n",
                          count, passTime, rowsPerS, passTime * 1_000_000.0 / count);
        System.out.println("[SUCCESS] Layer 2 PASSED — zero duplicates in 10M transactions.\n");

        System.out.print("[INFO] Serializing gateway state... ");
        gateway.saveGatewayState(STATE_FILE);
        System.out.println("done.\n");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: reload serialized state, submit replay — Layer 2 must fire
    // ─────────────────────────────────────────────────────────────────────────
    private static void phase3_Replay(File csv) throws Exception {
        System.out.println("--- PHASE 3: Replay Attack ---");

        // Grab the first TX ID from the real CSV as the replayed ID
        String replayId;
        try (BufferedReader br = new BufferedReader(new FileReader(csv))) {
            br.readLine(); // skip header
            replayId = br.readLine().split(",")[0].trim();
        }
        System.out.printf("[INFO] Attacker replays: %s%n", replayId);

        @SuppressWarnings("unchecked")
        AdvancedSecurityGateway<Transaction> reloaded =
            (AdvancedSecurityGateway<Transaction>)
                AdvancedSecurityGateway.loadGatewayState(STATE_FILE);

        // Replay file — attacker computes a genuine hash of their own batch,
        // so Layer 1 passes. Only Layer 2 can detect the duplicate TX ID.
        File replayFile = new File("replay_batch.csv");
        try (PrintWriter pw = new PrintWriter(replayFile)) {
            pw.println("TxID,UserID,Amount");
            pw.printf("%s,9999,5000.00%n", replayId);        // already in Bloom Filter
            pw.println("TX_BRAND_NEW_001,1111,750.00");
        }

        reloaded.setExpectedChecksum(
            Files.asByteSource(replayFile).hash(Hashing.sha256()).toString());

        try {
            reloaded.verifyFileIntegrity(replayFile);         // Layer 1: PASS
            System.out.println("[Layer 1] PASSED — attacker provided a genuine hash.");
            reloaded.processAndDeduplicate(replayFile);       // Layer 2: THROWS
            throw new RuntimeException("PHASE 3 FAILED — replay not detected!");
        } catch (SecurityViolationException e) {
            System.err.println("[ALERT] Layer 2 Intercepted: " + e.getMessage());
            System.out.println("[SUCCESS] Phase 3 PASSED.\n");
        } finally {
            replayFile.delete();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: tamper a file's content — Layer 1 must fire before Layer 2 runs
    // ─────────────────────────────────────────────────────────────────────────
    private static void phase4_Tamper() throws Exception {
        System.out.println("--- PHASE 4: Tamper Attack ---");

        File f = new File("tamper_test.csv");
        AdvancedSecurityGateway<Transaction> gateway = new AdvancedSecurityGateway<>(1000);

        try (PrintWriter pw = new PrintWriter(f)) {
            pw.println("TxID,UserID,Amount");
            pw.println("TX_99990001,1234,1500.00");
        }
        gateway.setExpectedChecksum(
            Files.asByteSource(f).hash(Hashing.sha256()).toString());

        // Tamper: inflate amount
        try (PrintWriter pw = new PrintWriter(f)) {
            pw.println("TxID,UserID,Amount");
            pw.println("TX_99990001,1234,99999.00");
        }
        System.out.println("[INFO] Amount altered 1500 → 99999.");

        try {
            gateway.verifyFileIntegrity(f);
            throw new RuntimeException("PHASE 4 FAILED — tamper not detected!");
        } catch (SecurityViolationException e) {
            System.err.println("[ALERT] Layer 1 Intercepted: " + e.getMessage());
            System.out.println("[SUCCESS] Phase 4 PASSED.");
        } finally {
            f.delete();
        }
    }
}