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
 * Dual-Layer Security Gateway for Rs. 1.5 Cr Festival Wallet Ledger
 * Refactored: Strategy pattern (SecurityLayer interface), static nested
 * layer classes, independent Bloom Filter hash functions, guarded CSV
 * parsing, and corrected serialization API.
 */

package com.mycompany.project;

import com.google.common.hash.Hashing;
import com.google.common.io.Files;
import java.io.*;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;

// ── Custom Exception ───────────────────────────────────────────────────────────

class SecurityViolationException extends Exception {
    public SecurityViolationException(String message) {
        super(message);
    }
}

// ── Strategy Interface ─────────────────────────────────────────────────────────
// Both security layers implement this contract, making the gateway open for
// extension (additional layers) without modifying existing code (OCP).

interface SecurityLayer extends Serializable {
    void execute(File file) throws SecurityViolationException, IOException;
}

// ── Bloom Filter ───────────────────────────────────────────────────────────────
// Uses two genuinely independent hash functions to minimize correlated
// collisions and achieve a lower false-positive rate than the original.

class TransactionBloomFilter implements Serializable {
    private static final long serialVersionUID = 1L;
    private final BitSet bitSet;
    private final int    bitSetSize;

    public TransactionBloomFilter(int size) {
        this.bitSetSize = size;
        this.bitSet     = new BitSet(size);
    }

    // Hash 1: Java's built-in polynomial hash, safely masked to avoid
    // Integer.MIN_VALUE (which has no positive int representation).
    private int hash1(String id) {
        return (id.hashCode() & Integer.MAX_VALUE) % bitSetSize;
    }

    // Hash 2: FNV-1a — a well-known non-cryptographic hash with very
    // different avalanche properties from Java's polynomial hash, giving
    // the two probes genuine independence.
    private int hash2(String id) {
        int hash = 0x811c9dc5;          // FNV offset basis
        for (char c : id.toCharArray()) {
            hash ^= c;
            hash *= 0x01000193;         // FNV prime
        }
        return (hash & Integer.MAX_VALUE) % bitSetSize;
    }

    public void add(String transactionId) {
        bitSet.set(hash1(transactionId));
        bitSet.set(hash2(transactionId));
    }

    /** Returns true if the ID was previously added (no false negatives). */
    public boolean contains(String transactionId) {
        return bitSet.get(hash1(transactionId)) && bitSet.get(hash2(transactionId));
    }
}

// ── Transaction Data Holder ────────────────────────────────────────────────────

class Transaction implements Serializable {
    private static final long serialVersionUID = 1L;
    final String txId;
    final String userId;
    final double amount;

    public Transaction(String txId, String userId, double amount) {
        this.txId   = txId;
        this.userId = userId;
        this.amount = amount;
    }

    @Override
    public String toString() {
        return String.format("Transaction{txId='%s', userId='%s', amount=%.2f}",
                             txId, userId, amount);
    }
}

// ── Main Gateway ───────────────────────────────────────────────────────────────
// Uses the Strategy pattern: holds two SecurityLayer implementations as
// static nested classes. Each layer encapsulates its own state and logic,
// keeping the gateway itself free of parsing or hashing details.

public class AdvancedSecurityGateway<T> implements Serializable {
    private static final long serialVersionUID = 1L;

    // ════════════════════════════════════════════════════════════════════════
    // Static Nested Class 1 — Layer 1: Guava Integrity Check (Strategy A)
    // ════════════════════════════════════════════════════════════════════════
    static class GuavaIntegrityLayer implements SecurityLayer {
        private static final long serialVersionUID = 1L;
        private String expectedChecksum;

        public GuavaIntegrityLayer() {
            this.expectedChecksum = "";
        }

        public void setExpectedChecksum(String checksum) {
            this.expectedChecksum = checksum;
        }

        public String getExpectedChecksum() {
            return expectedChecksum;
        }

        @Override
        public void execute(File file) throws SecurityViolationException, IOException {
            String calculated = Files.asByteSource(file).hash(Hashing.sha256()).toString();
            System.out.println("[Guava Layer] Expected Checksum:   " + expectedChecksum);
            System.out.println("[Guava Layer] Calculated Checksum: " + calculated);
            if (!calculated.equals(expectedChecksum)) {
                throw new SecurityViolationException(
                    "CRITICAL MALICIOUS TAMPERING DETECTED! File checksum mismatch."
                );
            }
            System.out.println("[SUCCESS] Layer 1: Cryptographic Integrity Verified via Google Guava.");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Static Nested Class 2 — Layer 2: Bloom Filter Deduplication (Strategy B)
    // ════════════════════════════════════════════════════════════════════════
    static class BloomFilterLayer implements SecurityLayer {
        private static final long serialVersionUID = 1L;
        private final TransactionBloomFilter filter;
        private final List<Transaction>      validatedBuffer;

        public BloomFilterLayer(int filterSize) {
            this.filter          = new TransactionBloomFilter(filterSize);
            this.validatedBuffer = new ArrayList<>();
        }

        /** Returns a defensive copy of the validated transaction list. */
        public List<Transaction> getValidatedBuffer() {
            return new ArrayList<>(validatedBuffer);
        }

        @Override
        public void execute(File file) throws SecurityViolationException, IOException {
            validatedBuffer.clear();
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                br.readLine(); // skip header row
                String line;
                while ((line = br.readLine()) != null) {
                    String[] tokens = line.split(",");
                    if (tokens.length < 3) continue;

                    String txId   = tokens[0].trim();
                    String userId = tokens[1].trim();
                    double amount;

                    // Guard: malformed amount triggers a SecurityViolationException
                    // instead of leaking a raw NumberFormatException to the caller.
                    try {
                        amount = Double.parseDouble(tokens[2].trim());
                    } catch (NumberFormatException e) {
                        throw new SecurityViolationException(
                            "MALFORMED DATA DETECTED: Invalid amount for transaction ID " + txId
                        );
                    }

                    if (filter.contains(txId)) {
                        throw new SecurityViolationException(
                            "REPLAY ATTACK DETECTED! Transaction ID " + txId +
                            " has already been processed."
                        );
                    }

                    filter.add(txId);
                    validatedBuffer.add(new Transaction(txId, userId, amount));
                }
            }
            System.out.println("[SUCCESS] Layer 2: All " + validatedBuffer.size() +
                               " transactions passed the Bloom Filter check.");
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Gateway fields — composed of the two layer strategies
    // ════════════════════════════════════════════════════════════════════════
    private final GuavaIntegrityLayer integrityLayer;
    private final BloomFilterLayer    deduplicateLayer;

    public AdvancedSecurityGateway(int filterSize) {
        this.integrityLayer   = new GuavaIntegrityLayer();
        this.deduplicateLayer = new BloomFilterLayer(filterSize);
    }

    // ── Public API ────────────────────────────────────────────────────────

    public void setExpectedChecksum(String checksum) {
        integrityLayer.setExpectedChecksum(checksum);
    }

    /** Executes Layer 1 only (integrity check). */
    public void verifyFileIntegrity(File file) throws SecurityViolationException, IOException {
        integrityLayer.execute(file);
    }

    /** Executes Layer 2 only (deduplication). */
    public void processAndDeduplicate(File file) throws SecurityViolationException, IOException {
        deduplicateLayer.execute(file);
    }

    /**
     * Convenience method: runs both security layers in sequence.
     * Layer 1 (integrity) must pass before Layer 2 (replay detection) runs.
     */
    public void runAllLayers(File file) throws SecurityViolationException, IOException {
        integrityLayer.execute(file);
        deduplicateLayer.execute(file);
    }

    /** Returns the validated transactions produced by the last Layer 2 run. */
    public List<Transaction> getValidatedTransactions() {
        return deduplicateLayer.getValidatedBuffer();
    }

    // ── Serialization ─────────────────────────────────────────────────────

    /** Freezes the entire gateway state (including the Bloom Filter bit-array)
     *  to disk so that deduplication history survives server restarts. */
    public void saveGatewayState(String cachePath) throws IOException {
        try (ObjectOutputStream oos =
                 new ObjectOutputStream(new FileOutputStream(cachePath))) {
            oos.writeObject(this);
        }
    }

    /** Restores a previously frozen gateway state from disk. */
    public static AdvancedSecurityGateway<?> loadGatewayState(String cachePath)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois =
                 new ObjectInputStream(new FileInputStream(cachePath))) {
            return (AdvancedSecurityGateway<?>) ois.readObject();
        }
    }
}