package com.example.entity;

import se.deversity.blindbean.annotations.Scheme;
import se.deversity.blindbean.context.BlindContext;
import se.deversity.blindbean.junit.BlindBeanTest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Round-trips and arithmetic for every newly supported type, driven the way a consumer would.
 */
public class TypeZooTest {

    // ── Paillier-encoded types (pure Java, no native library) ────────────────

    @Nested
    class PaillierTypes {

        @org.junit.jupiter.api.BeforeEach
        void setup() { BlindContext.init(); }

        @AfterEach
        void teardown() { BlindContext.clear(); }

        @Test
        void bigDecimalIsExactAndAddsExactly() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptPrice(new BigDecimal("19.99"));
            w.addPrice(new BigDecimal("0.01"));

            // The whole point of doing money on Paillier: 19.99 + 0.01 is exactly 20.00,
            // not 19.999999999. CKKS could not promise this.
            assertEquals(new BigDecimal("20.00"), w.decryptPrice());
        }

        @Test
        void bigDecimalRefusesToSilentlyLoseACent() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);
            // scale = 2, so a third decimal cannot be stored. Rounding it away silently would be
            // the worst possible behaviour for money.
            assertThrows(ArithmeticException.class, () -> w.encryptPrice(new BigDecimal("1.005")));
        }

        @Test
        void byteArraySurvivesIncludingLeadingZeros() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            // The leading zero is the trap: a BigInteger drops it, so without the length marker
            // this would come back one byte shorter.
            byte[] blob = { 0x00, 0x00, 0x7f, (byte) 0xff, 0x01 };
            w.encryptBlob(blob);
            assertArrayEquals(blob, w.decryptBlob());
        }

        @Test
        void emptyByteArrayRoundTrips() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);
            w.encryptBlob(new byte[0]);
            assertArrayEquals(new byte[0], w.decryptBlob());
        }

        @Test
        void instantAndLocalDateRoundTrip() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            Instant seen = Instant.ofEpochMilli(1_752_000_000_000L);
            LocalDate born = LocalDate.of(1984, 4, 1);

            w.encryptSeenAt(seen);
            w.encryptBornOn(born);

            assertEquals(seen, w.decryptSeenAt());
            assertEquals(born, w.decryptBornOn());
        }

        @Test
        void durationsAddBecauseTheyAreQuantitiesNotPoints() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptUptime(Duration.ofHours(2));
            w.addUptime(Duration.ofMinutes(30));

            assertEquals(Duration.ofMinutes(150), w.decryptUptime());
        }

        @Test
        void nullRoundTripsForReferenceTypes() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptPrice(null);
            w.encryptBlob(null);
            w.encryptSeenAt(null);

            assertNull(w.decryptPrice());
            assertNull(w.decryptBlob());
            assertNull(w.decryptSeenAt());
        }

        @Test
        void aNegativeDecimalRoundTrips() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);
            w.encryptPrice(new BigDecimal("-5.50"));
            assertEquals(new BigDecimal("-5.50"), w.decryptPrice());
        }
    }

    // ── BFV integer vectors ──────────────────────────────────────────────────

    @Nested
    @Tag("native")
    @BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)
    class BfvVectors {

        @Test
        void intVectorRoundTripsAndAddsSlotwise() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptCounters(new int[] { 1, 2, 3 });
            w.addCounters(new int[] { 10, 20, 30 });

            int[] out = w.decryptCounters();
            assertEquals(11, out[0]);
            assertEquals(22, out[1]);
            assertEquals(33, out[2]);
        }

        @Test
        void intVectorsMultiplySlotwise() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptCounters(new int[] { 2, 3, 4 });
            w.mulCounters(new int[] { 5, 5, 5 });

            int[] out = w.decryptCounters();
            assertEquals(10, out[0]);
            assertEquals(15, out[1]);
            assertEquals(20, out[2]);
        }

        @Test
        void shortVectorRoundTrips() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);
            w.encryptFlags(new short[] { 7, -8, 9 });
            short[] out = w.decryptFlags();
            assertEquals((short) 7, out[0]);
            assertEquals((short) -8, out[1]);
            assertEquals((short) 9, out[2]);
        }
    }

    // ── CKKS real vectors ────────────────────────────────────────────────────

    @Nested
    @Tag("native")
    @BlindBeanTest(scheme = Scheme.CKKS, polyModulusDegree = 8192, ckksScale = 1099511627776.0)
    class CkksVectors {

        private static final double TOL = 0.01;

        @Test
        void doubleVectorRoundTripsAndAddsSlotwise() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            w.encryptSignal(new double[] { 1.5, 2.5, 3.5 });
            w.addSignal(new double[] { 0.5, 0.5, 0.5 });

            double[] out = w.decryptSignal();
            assertEquals(2.0, out[0], TOL);
            assertEquals(3.0, out[1], TOL);
            assertEquals(4.0, out[2], TOL);
        }

        @Test
        void floatVectorRoundTrips() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);
            w.encryptWeights(new float[] { 0.25f, -1.5f });
            float[] out = w.decryptWeights();
            assertEquals(0.25f, out[0], 0.01f);
            assertEquals(-1.5f, out[1], 0.01f);
        }

        @Test
        void aCkksVectorCarriesEverySlotNotJustTheFirst() {
            TypeZoo z = new TypeZoo();
            var w = new TypeZooBlindWrapper(z);

            // Before the batch path existed, CKKS wrote only slot 0 — this would have come back
            // as [3.0, 0, 0, ...].
            w.encryptSignal(new double[] { 3.0, 6.0, 9.0, 12.0 });
            double[] out = w.decryptSignal();
            assertEquals(6.0, out[1], TOL);
            assertEquals(12.0, out[3], TOL);
        }
    }
}
