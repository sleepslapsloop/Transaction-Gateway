/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author angadh
 * @author mridul
 */

/*
 * CS F213 Object Oriented Programming Project
 * BITS Pilani | Summer 2026
 *
 * IntegratedGatewayTest — end-to-end demonstration of both attack vectors.
 *
 * Fix applied: Attack B previously set the replay hash on the wrong gateway
 * object, causing Layer 1 to fire instead of Layer 2. The reloaded gateway
 * now correctly receives the replay file's hash so Layer 1 passes and
 * Layer 2 (Bloom Filter) catches the duplicate TX ID as intended.
 */

package com.mycompany.project;

import java.io.File;
import java.io.PrintWriter;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import java.io.IOException;

public class IntegratedGatewayTest {

    public static void main(String[] args) {
        System.out.println("=== STARTING DUAL-LAYER SECURITY GATEWAY TEST ===\n");

        File transactionFile = new File("offline_sync_log.csv");
        String stateCache = "gateway_state.ser";

        // Bloom Filter bit-array size of 1000 — sufficient for this test volume.
        AdvancedSecurityGateway<Transaction> gateway = new AdvancedSecurityGateway<>(1000);

        try {

            // ──────────────────────────────────────────────────────────────────
            // STEP 1: Write a clean vendor sync file and establish the trusted
            //         checksum. Run both layers, then freeze the gateway state.
            // ──────────────────────────────────────────────────────────────────
            writeCSV(transactionFile,
                "TX_7701,USER_A,3500.00",
                "TX_7702,USER_B,120.50");

            String trustedHash = sha256(transactionFile);
            gateway.setExpectedChecksum(trustedHash);
            gateway.verifyFileIntegrity(transactionFile);
            gateway.processAndDeduplicate(transactionFile);
            gateway.saveGatewayState(stateCache);

            System.out.println("\n[SYSTEM LOG] Base state (Bloom Filter + checksum) frozen to disk.");
            System.out.println("[SYSTEM LOG] Validated transactions: " + gateway.getValidatedTransactions());

            // ──────────────────────────────────────────────────────────────────
            // ATTACK SCENARIO A: File Tampering
            // A vendor device's CSV is altered mid-transfer (amount inflated).
            // Layer 1 (SHA-256 checksum) must intercept before any data lands.
            // ──────────────────────────────────────────────────────────────────
            System.out.println("\n--- SIMULATING ATTACK A: ALTERING RUPEE AMOUNT ---");

            writeCSV(transactionFile,
                "TX_7701,USER_A,99999.00",   // Rs 3500 maliciously inflated to Rs 99999
                "TX_7702,USER_B,120.50");

            try {
                gateway.verifyFileIntegrity(transactionFile);
            } catch (SecurityViolationException e) {
                System.err.println("[ALERT] Layer 1 Intercepted Tampering: " + e.getMessage());
            }

            // Reset the file to its original valid content for the next scenario.
            writeCSV(transactionFile,
                "TX_7701,USER_A,3500.00",
                "TX_7702,USER_B,120.50");

            // ──────────────────────────────────────────────────────────────────
            // ATTACK SCENARIO B: Replay Attack
            //
            // An attacker submits a new, legitimately-signed batch file that
            // re-uses TX_7701 (already processed in Step 1) alongside a new
            // transaction TX_7703 — attempting to double-credit USER_A.
            //
            // Layer 1 must PASS (the attacker provides a genuine checksum of
            // their fabricated file). Layer 2 must CATCH the duplicate TX ID.
            //
            // FIX vs. original: we call setExpectedChecksum() on reloadedGateway,
            // not on 'gateway'. The reloaded object must know the hash of the
            // replay file; otherwise it still holds the old hash and Layer 1
            // fires instead of Layer 2, producing a misleading demo output.
            // ──────────────────────────────────────────────────────────────────
            System.out.println("\n--- SIMULATING ATTACK B: REPLAY TRANSACTION ID ---");

            writeCSV(transactionFile,
                "TX_7701,USER_A,3500.00",   // Replayed — already in Bloom Filter
                "TX_7703,USER_C,450.00");

            // Compute the hash of the REPLAY file (attacker provides a valid hash
            // of their own batch, so Layer 1 cannot detect wrongdoing from the
            // file bytes alone — only the Bloom Filter can catch the duplicate ID).
            String replayHash = sha256(transactionFile);

            // Restore gateway from the frozen state. This reloaded instance has
            // TX_7701 and TX_7702 already tracked in its Bloom Filter bit-array.
            @SuppressWarnings("unchecked")
            AdvancedSecurityGateway<Transaction> reloadedGateway =
                (AdvancedSecurityGateway<Transaction>)
                    AdvancedSecurityGateway.loadGatewayState(stateCache);

            // KEY FIX: set the replay file's hash on reloadedGateway so that
            // Layer 1 passes, allowing Layer 2 to be the one that fires.
            reloadedGateway.setExpectedChecksum(replayHash);

            reloadedGateway.verifyFileIntegrity(transactionFile);   // Layer 1: passes (hash matches)
            reloadedGateway.processAndDeduplicate(transactionFile); // Layer 2: throws on TX_7701

        } catch (SecurityViolationException e) {
            // Only Layer 2 can throw here; Layer 1 exceptions are caught inline above.
            System.err.println("[ALERT] Layer 2 Intercepted Replay Attack: " + e.getMessage());
            System.out.println("\n=== INTEGRATED TESTING COMPLETE: ALL ATTACK VECTORS BLOCKED ===");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (transactionFile.exists()) transactionFile.delete();
            new File(stateCache).delete();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void writeCSV(File file, String... rows) throws IOException {
        try (PrintWriter pw = new PrintWriter(file)) {
            pw.println("TxID,UserID,Amount");
            for (String row : rows) pw.println(row);
        }
    }

    private static String sha256(File file) throws IOException {
        return Files.asByteSource(file).hash(Hashing.sha256()).toString();
    }
}
