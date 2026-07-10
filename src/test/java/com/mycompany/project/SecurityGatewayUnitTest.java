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

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;

import java.io.*;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Security Gateway — Unit Test Suite")
class SecurityGatewayUnitTest {

    @TempDir
    Path tempDir;

    private File csvFile;
    private AdvancedSecurityGateway<Transaction> gateway;

    @BeforeEach
    void setUp() throws IOException {
        csvFile = tempDir.resolve("transactions.csv").toFile();
        gateway = new AdvancedSecurityGateway<>(1000);
    }

    private void writeCSV(String... rows) throws IOException {
        try (PrintWriter pw = new PrintWriter(csvFile)) {
            pw.println("TxID,UserID,Amount");
            for (String row : rows) pw.println(row);
        }
    }

    private String sha256(File file) throws IOException {
        return Files.asByteSource(file).hash(Hashing.sha256()).toString();
    }

    private void trustAndVerify(File file) throws Exception {
        gateway.setExpectedChecksum(sha256(file));
        gateway.verifyFileIntegrity(file);
    }


    @Nested
    @DisplayName("Layer 1: Guava integrity check")
    class Layer1Tests {

        @Test
        @DisplayName("Clean file with matching checksum passes")
        void cleanFilePasses() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            assertDoesNotThrow(() -> trustAndVerify(csvFile));
        }

        @Test
        @DisplayName("Tampered amount throws SecurityViolationException")
        void tamperedAmountThrows() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            gateway.setExpectedChecksum(sha256(csvFile)); // hash of original

            writeCSV("TX_001,USER_A,99999.00");           // tamper AFTER hashing
            SecurityViolationException ex = assertThrows(
                SecurityViolationException.class,
                () -> gateway.verifyFileIntegrity(csvFile)
            );
            assertTrue(ex.getMessage().contains("TAMPERING"),
                       "Exception message must mention TAMPERING");
        }

        @Test
        @DisplayName("Added row throws SecurityViolationException")
        void addedRowThrows() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            gateway.setExpectedChecksum(sha256(csvFile));

            writeCSV("TX_001,USER_A,100.00", "TX_002,USER_B,999.00"); // row injected
            assertThrows(SecurityViolationException.class,
                         () -> gateway.verifyFileIntegrity(csvFile));
        }

        @Test
        @DisplayName("Empty expected checksum always fails (default state)")
        void emptyChecksumAlwaysFails() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            // No setExpectedChecksum call — defaults to ""
            assertThrows(SecurityViolationException.class,
                         () -> gateway.verifyFileIntegrity(csvFile));
        }

        @Test
        @DisplayName("Same content re-verified after reset passes")
        void sameContentAfterResetPasses() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            String hash = sha256(csvFile);
            gateway.setExpectedChecksum(hash);
            gateway.verifyFileIntegrity(csvFile);

            // Simulate writing the same data again (e.g. re-upload)
            writeCSV("TX_001,USER_A,100.00");
            gateway.setExpectedChecksum(sha256(csvFile));
            assertDoesNotThrow(() -> gateway.verifyFileIntegrity(csvFile));
        }
    }


    @Nested
    @DisplayName("Layer 2: Bloom Filter deduplication")
    class Layer2Tests {

        @Test
        @DisplayName("Unique transactions populate the validated buffer")
        void uniqueTransactionsBuffered() throws Exception {
            writeCSV("TX_001,USER_A,100.00",
                     "TX_002,USER_B,200.00",
                     "TX_003,USER_C,300.00");
            trustAndVerify(csvFile);
            gateway.processAndDeduplicate(csvFile);

            List<Transaction> result = gateway.getValidatedTransactions();
            assertEquals(3, result.size());
            assertEquals("TX_001", result.get(0).txId);
            assertEquals("TX_003", result.get(2).txId);
            assertEquals(300.00, result.get(2).amount, 0.001);
        }

        @Test
        @DisplayName("Duplicate TX ID in same file throws replay exception")
        void duplicateInSameFileThrows() throws Exception {
            writeCSV("TX_001,USER_A,100.00",
                     "TX_001,USER_B,200.00"); // TX_001 replayed
            trustAndVerify(csvFile);

            SecurityViolationException ex = assertThrows(
                SecurityViolationException.class,
                () -> gateway.processAndDeduplicate(csvFile)
            );
            assertTrue(ex.getMessage().contains("REPLAY ATTACK"));
            assertTrue(ex.getMessage().contains("TX_001"));
        }

        @Test
        @DisplayName("Malformed amount throws SecurityViolationException (not NumberFormatException)")
        void malformedAmountThrowsSecurityException() throws Exception {
            writeCSV("TX_001,USER_A,NOT_A_NUMBER");
            trustAndVerify(csvFile);

            SecurityViolationException ex = assertThrows(
                SecurityViolationException.class,
                () -> gateway.processAndDeduplicate(csvFile)
            );
            assertTrue(ex.getMessage().contains("MALFORMED DATA"),
                       "Must report malformed data, not leak NumberFormatException");
        }

        @Test
        @DisplayName("Single-row file processes without error")
        void singleRowFile() throws Exception {
            writeCSV("TX_001,USER_A,50.00");
            trustAndVerify(csvFile);
            assertDoesNotThrow(() -> gateway.processAndDeduplicate(csvFile));
            assertEquals(1, gateway.getValidatedTransactions().size());
        }

        @Test
        @DisplayName("Buffer is cleared on each processAndDeduplicate call")
        void bufferClearedBetweenRuns() throws Exception {
            writeCSV("TX_001,USER_A,100.00", "TX_002,USER_B,200.00");
            trustAndVerify(csvFile);
            gateway.processAndDeduplicate(csvFile);
            assertEquals(2, gateway.getValidatedTransactions().size());

            // Second file is different; Bloom Filter already has TX_001 + TX_002
            // so any repeat would throw. Here we use fresh IDs to test buffer clear.
            writeCSV("TX_003,USER_C,300.00");
            gateway.setExpectedChecksum(sha256(csvFile));
            gateway.verifyFileIntegrity(csvFile);
            gateway.processAndDeduplicate(csvFile);

            // Buffer must reflect only the latest run's results
            assertEquals(1, gateway.getValidatedTransactions().size(),
                         "Buffer must contain only the most recent batch");
        }
    }



    @Nested
    @DisplayName("TransactionBloomFilter internals")
    class BloomFilterTests {

        @Test
        @DisplayName("add then contains returns true")
        void addThenContains() {
            TransactionBloomFilter bf = new TransactionBloomFilter(1000);
            bf.add("TX_ALPHA");
            assertTrue(bf.contains("TX_ALPHA"));
        }

        @Test
        @DisplayName("Unseen ID returns false")
        void unseenIdFalse() {
            TransactionBloomFilter bf = new TransactionBloomFilter(1000);
            bf.add("TX_ALPHA");
            assertFalse(bf.contains("TX_BETA"));
        }

        @Test
        @DisplayName("Multiple distinct IDs are all tracked independently")
        void multipleDistinctIds() {
            TransactionBloomFilter bf   = new TransactionBloomFilter(2000);
            String[]               ids  = {"TX_001", "TX_002", "TX_003", "TX_004", "TX_005"};
            for (String id : ids) bf.add(id);
            for (String id : ids) {
                assertTrue(bf.contains(id), "Expected " + id + " to be present");
            }
        }

        @Test
        @DisplayName("IDs sharing a common prefix are distinguished correctly")
        void commonPrefixIDs() {
            TransactionBloomFilter bf = new TransactionBloomFilter(1000);
            bf.add("TX_1");
            assertFalse(bf.contains("TX_10"),  "TX_10 should not match TX_1");
            assertFalse(bf.contains("TX_100"), "TX_100 should not match TX_1");
            assertFalse(bf.contains("TX_"),    "Prefix alone should not match");
        }

        @Test
        @DisplayName("Empty string handled without exception")
        void emptyStringHandled() {
            TransactionBloomFilter bf = new TransactionBloomFilter(1000);
            assertDoesNotThrow(() -> bf.add(""));
            assertTrue(bf.contains(""));
        }
    }

    @Nested
    @DisplayName("Java serialization (state persistence)")
    class SerializationTests {

        @Test
        @DisplayName("Reloaded gateway retains Bloom Filter and blocks replay")
        void reloadedGatewayBlocksReplay() throws Exception {
            writeCSV("TX_001,USER_A,100.00", "TX_002,USER_B,200.00");
            trustAndVerify(csvFile);
            gateway.processAndDeduplicate(csvFile);

            File stateFile = tempDir.resolve("state.ser").toFile();
            gateway.saveGatewayState(stateFile.getAbsolutePath());

            // Build a replay file: TX_001 was already processed, TX_003 is new.
            writeCSV("TX_001,USER_A,100.00", "TX_003,USER_C,300.00");
            String replayHash = sha256(csvFile);

            @SuppressWarnings("unchecked")
            AdvancedSecurityGateway<Transaction> reloaded =
                (AdvancedSecurityGateway<Transaction>)
                    AdvancedSecurityGateway.loadGatewayState(stateFile.getAbsolutePath());

            // Set the replay file's own hash so Layer 1 passes — only Layer 2
            // can detect the replayed TX_001.
            reloaded.setExpectedChecksum(replayHash);
            reloaded.verifyFileIntegrity(csvFile); // must NOT throw

            SecurityViolationException ex = assertThrows(
                SecurityViolationException.class,
                () -> reloaded.processAndDeduplicate(csvFile)
            );
            assertTrue(ex.getMessage().contains("REPLAY ATTACK"),
                       "Reloaded Bloom Filter must catch replayed TX_001");
        }

        @Test
        @DisplayName("Reloaded gateway accepts entirely new transactions")
        void reloadedGatewayAcceptsNewTransactions() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            trustAndVerify(csvFile);
            gateway.processAndDeduplicate(csvFile);

            File stateFile = tempDir.resolve("state2.ser").toFile();
            gateway.saveGatewayState(stateFile.getAbsolutePath());

            writeCSV("TX_002,USER_B,500.00", "TX_003,USER_C,750.00");
            String newHash = sha256(csvFile);

            @SuppressWarnings("unchecked")
            AdvancedSecurityGateway<Transaction> reloaded =
                (AdvancedSecurityGateway<Transaction>)
                    AdvancedSecurityGateway.loadGatewayState(stateFile.getAbsolutePath());

            reloaded.setExpectedChecksum(newHash);
            assertDoesNotThrow(() -> reloaded.runAllLayers(csvFile));
            assertEquals(2, reloaded.getValidatedTransactions().size());
        }

        @Test
        @DisplayName("Serialized file is non-empty (actual bytes written)")
        void serializedFileNonEmpty() throws Exception {
            writeCSV("TX_001,USER_A,100.00");
            trustAndVerify(csvFile);
            gateway.processAndDeduplicate(csvFile);

            File stateFile = tempDir.resolve("state3.ser").toFile();
            gateway.saveGatewayState(stateFile.getAbsolutePath());

            assertTrue(stateFile.exists(), "State file must be created");
            assertTrue(stateFile.length() > 0, "State file must contain bytes");
        }
    }


    @Nested
    @DisplayName("End-to-end: full dual-layer pipeline")
    class EndToEndTests {

        @Test
        @DisplayName("runAllLayers passes for a clean, unique batch")
        void runAllLayersCleanBatch() throws Exception {
            writeCSV("TX_A01,USER_X,1500.00",
                     "TX_A02,USER_Y,2500.00",
                     "TX_A03,USER_Z,500.00");
            gateway.setExpectedChecksum(sha256(csvFile));
            assertDoesNotThrow(() -> gateway.runAllLayers(csvFile));
            assertEquals(3, gateway.getValidatedTransactions().size());
        }

        @Test
        @DisplayName("runAllLayers stops at Layer 1 when file is tampered")
        void runAllLayersStopsAtLayer1() throws Exception {
            writeCSV("TX_A01,USER_X,1500.00");
            gateway.setExpectedChecksum(sha256(csvFile));

            writeCSV("TX_A01,USER_X,9999999.00"); // tamper
            SecurityViolationException ex = assertThrows(
                SecurityViolationException.class,
                () -> gateway.runAllLayers(csvFile)
            );
            assertTrue(ex.getMessage().contains("TAMPERING"));
        }
    }
}
