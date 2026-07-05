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

// --- Custom Exception ---

class SecurityViolationException extends Exception {
    public SecurityViolationException(String message) {
        super(message);
    }
}

// --- Strategy Interface ---
// Both security layers implement this contract (Strategy pattern / OCP).

interface SecurityLayer extends Serializable {
    void execute(File file) throws SecurityViolationException, IOException;
}

// --- Bloom Filter ---
//
// Double-hashing construction: generates NUM_HASHES independent bit probes
// from two base hash functions using probe_i = (h1 + i*h2) mod m.
// This is the standard Kirsch-Mitzenmacher technique and avoids needing
// NUM_HASHES separate hash implementations.
//
// False positive rates (n = 10M entries):
//   k=2,  m=130M  -> 2.03%   (~203k FP per 10M lookups)  [old]
//   k=7,  m=500M  -> 0.0001% (~6   FP per 10M lookups)   [new]

class TransactionBloomFilter implements Serializable {
    private static final long serialVersionUID = 2L;
    private final BitSet bitSet;
    private final int    bitSetSize;
    private static final int NUM_HASHES = 7;

    public TransactionBloomFilter(int size) {
        this.bitSetSize = size;
        this.bitSet     = new BitSet(size);
    }

    // Base hash 1: Java built-in polynomial hash.
    // Masked with MAX_VALUE to guarantee a non-negative result.
    private int h1(String id) {
        return (id.hashCode() & Integer.MAX_VALUE) % bitSetSize;
    }

    // Base hash 2: FNV-1a — different avalanche properties from h1,
    // giving double-hashing genuine probe independence.
    private int h2(String id) {
        int hash = 0x811c9dc5;
        for (char c : id.toCharArray()) {
            hash ^= c;
            hash *= 0x01000193;
        }
        return (hash & Integer.MAX_VALUE) % bitSetSize;
    }

    // i-th probe index: (h1 + i*h2) mod m.
    // Cast to long before multiply to prevent int overflow.
    private int probe(int a, int b, int i) {
        return (int) (((long) a + (long) i * b) % bitSetSize);
    }

    public void add(String transactionId) {
        int a = h1(transactionId), b = h2(transactionId);
        for (int i = 0; i < NUM_HASHES; i++) bitSet.set(probe(a, b, i));
    }

    /** Returns true if the ID was previously added. No false negatives. */
    public boolean contains(String transactionId) {
        int a = h1(transactionId), b = h2(transactionId);
        for (int i = 0; i < NUM_HASHES; i++)
            if (!bitSet.get(probe(a, b, i))) return false;
        return true;
    }
}

// --- Transaction Data Holder ---

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

// --- Main Gateway (Strategy pattern with two static nested layer classes) ---

public class AdvancedSecurityGateway<T> implements Serializable {
    private static final long serialVersionUID = 1L;

    // =========================================================================
    // Static Nested Class 1: Layer 1 -- Guava SHA-256 Integrity (Strategy A)
    // =========================================================================
    static class GuavaIntegrityLayer implements SecurityLayer {
        private static final long serialVersionUID = 1L;
        private String expectedChecksum;

        public GuavaIntegrityLayer() { this.expectedChecksum = ""; }

        public void setExpectedChecksum(String checksum) {
            this.expectedChecksum = checksum;
        }

        public String getExpectedChecksum() { return expectedChecksum; }

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

    // =========================================================================
    // Static Nested Class 2: Layer 2 -- Bloom Filter Deduplication (Strategy B)
    // =========================================================================
    static class BloomFilterLayer implements SecurityLayer {
        private static final long serialVersionUID = 1L;
        private final TransactionBloomFilter filter;
        private final List<Transaction>      validatedBuffer;

        public BloomFilterLayer(int filterSize) {
            this.filter          = new TransactionBloomFilter(filterSize);
            this.validatedBuffer = new ArrayList<>();
        }

        public List<Transaction> getValidatedBuffer() {
            return new ArrayList<>(validatedBuffer);
        }

        @Override
        public void execute(File file) throws SecurityViolationException, IOException {
            validatedBuffer.clear();
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                br.readLine(); // skip header
                String line;
                while ((line = br.readLine()) != null) {
                    String[] tokens = line.split(",");
                    if (tokens.length < 3) continue;

                    String txId   = tokens[0].trim();
                    String userId = tokens[1].trim();
                    double amount;

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

    // =========================================================================
    // Gateway: composed of the two layer strategies
    // =========================================================================
    private final GuavaIntegrityLayer integrityLayer;
    private final BloomFilterLayer    deduplicateLayer;

    public AdvancedSecurityGateway(int filterSize) {
        this.integrityLayer   = new GuavaIntegrityLayer();
        this.deduplicateLayer = new BloomFilterLayer(filterSize);
    }

    public void setExpectedChecksum(String checksum) {
        integrityLayer.setExpectedChecksum(checksum);
    }

    public void verifyFileIntegrity(File file) throws SecurityViolationException, IOException {
        integrityLayer.execute(file);
    }

    public void processAndDeduplicate(File file) throws SecurityViolationException, IOException {
        deduplicateLayer.execute(file);
    }

    public void runAllLayers(File file) throws SecurityViolationException, IOException {
        integrityLayer.execute(file);
        deduplicateLayer.execute(file);
    }

    public List<Transaction> getValidatedTransactions() {
        return deduplicateLayer.getValidatedBuffer();
    }

    public void saveGatewayState(String cachePath) throws IOException {
        try (ObjectOutputStream oos =
                 new ObjectOutputStream(new FileOutputStream(cachePath))) {
            oos.writeObject(this);
        }
    }

    public static AdvancedSecurityGateway<?> loadGatewayState(String cachePath)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois =
                 new ObjectInputStream(new FileInputStream(cachePath))) {
            return (AdvancedSecurityGateway<?>) ois.readObject();
        }
    }
}