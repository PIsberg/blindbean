package se.deversity.blindbean.fhe;

import se.deversity.blindbean.context.BlindContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts the BFV/CKKS contexts are booted with secure parameters and the correct slot geometry.
 *
 * <p>The 128-bit security of these schemes rests on two things: a polynomial modulus degree at or
 * above the {@code 8192} floor (below which the standard's coefficient-modulus tables cannot reach
 * 128 bits), and the coefficient modulus itself — which the native bridge takes from Microsoft
 * SEAL's HomomorphicEncryption.org-standard default for the chosen degree. This test pins the degree
 * floor and the slot geometry that follows from it; the coeff-modulus security is inherited from
 * SEAL's vetted defaults and must not be weakened in the native layer.
 */
@Tag("native")
@DisplayName("FHE: BFV/CKKS secure parameters and slot geometry")
public class FheParametersTest {

    private static final double CKKS_SCALE = Math.pow(2, 40);

    @AfterEach
    public void teardown() {
        BlindContext.clear();
    }

    @Test
    @DisplayName("BFV at the recommended degree meets the floor and batches one slot per coefficient")
    public void bfvUsesSecureDegreeAndFullSlots() {
        BlindContext.initBfv(8192);
        FheContext ctx = BlindContext.getFheContext();

        assertTrue(ctx.polyModulusDegree() >= 8192,
                "BFV degree below the 8192 security floor: " + ctx.polyModulusDegree());
        assertEquals(8192, ctx.polyModulusDegree());
        assertEquals(ctx.polyModulusDegree(), ctx.slotCount(),
                "BFV has one batching slot per polynomial coefficient");
    }

    @Test
    @DisplayName("CKKS at the recommended degree meets the floor and has degree/2 slots")
    public void ckksUsesSecureDegreeAndHalfSlots() {
        BlindContext.initCkks(8192, CKKS_SCALE);
        FheContext ctx = BlindContext.getFheContext();

        assertTrue(ctx.polyModulusDegree() >= 8192,
                "CKKS degree below the 8192 security floor: " + ctx.polyModulusDegree());
        assertEquals(8192, ctx.polyModulusDegree());
        assertEquals(ctx.polyModulusDegree() / 2L, ctx.slotCount(),
                "CKKS carries degree/2 slots (complex-conjugate symmetry)");
    }

    @Test
    @DisplayName("a larger secure degree is honoured and scales its slot count")
    public void largerDegreeIsHonoured() {
        BlindContext.initBfv(16384);
        FheContext ctx = BlindContext.getFheContext();

        assertEquals(16384, ctx.polyModulusDegree());
        assertEquals(16384L, ctx.slotCount());
    }
}
