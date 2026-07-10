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

        // Bloom Filter bit-array size of 1000
        AdvancedSecurityGateway<Transaction> gateway = new AdvancedSecurityGateway<>(1000);

        try {

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


            System.out.println("\n--- SIMULATING ATTACK A: ALTERING RUPEE AMOUNT ---");

            writeCSV(transactionFile,
                "TX_7701,USER_A,99999.00",   //Rs 3500 maliciously inflated to Rs 99999
                "TX_7702,USER_B,120.50");

            try {
                gateway.verifyFileIntegrity(transactionFile);
            } catch (SecurityViolationException e) {
                System.err.println("[ALERT] Layer 1 Intercepted Tampering: " + e.getMessage());
            }

            // Reset the file
            writeCSV(transactionFile,
                "TX_7701,USER_A,3500.00",
                "TX_7702,USER_B,120.50");


            System.out.println("\n--- SIMULATING ATTACK B: REPLAY TRANSACTION ID ---");

            writeCSV(transactionFile,
                "TX_7701,USER_A,3500.00",   // Replayed — already in Bloom Filter
                "TX_7703,USER_C,450.00");


            String replayHash = sha256(transactionFile);


            @SuppressWarnings("unchecked")
            AdvancedSecurityGateway<Transaction> reloadedGateway =
                (AdvancedSecurityGateway<Transaction>)
                    AdvancedSecurityGateway.loadGatewayState(stateCache);


            reloadedGateway.setExpectedChecksum(replayHash);

            reloadedGateway.verifyFileIntegrity(transactionFile);   // Layer 1: passes (hash matches)
            reloadedGateway.processAndDeduplicate(transactionFile); // Layer 2: throws on TX_7701

        } catch (SecurityViolationException e) {
            System.err.println("[ALERT] Layer 2 Intercepted Replay Attack: " + e.getMessage());
            System.out.println("\n=== INTEGRATED TESTING COMPLETE: ALL ATTACK VECTORS BLOCKED ===");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (transactionFile.exists()) transactionFile.delete();
            new File(stateCache).delete();
        }
    }


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
