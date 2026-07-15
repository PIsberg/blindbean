package se.deversity.blindbean.junit;

import se.deversity.blindbean.annotations.Scheme;

import org.junit.jupiter.api.extension.ExtendWith;

import se.deversity.vibetags.annotations.AIPublicAPI;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Class-level JUnit 5 annotation that manages the {@code BlindContext}
 * lifecycle for every test: the context is initialized before each test
 * method and cleared afterwards, replacing the hand-rolled
 * {@code @BeforeEach BlindContext.init()} / {@code @AfterEach BlindContext.clear()}
 * pair in consumer test suites.
 *
 * <pre>{@code
 * @BlindBeanTest
 * class WalletTest {
 *     @Test
 *     void deposits() {
 *         Ciphertext c = BlindContext.getPaillier().encrypt(BigInteger.TEN);
 *         // ...
 *     }
 * }
 *
 * @BlindBeanTest(scheme = Scheme.BFV, polyModulusDegree = 8192)
 * class VectorTest { ... }
 * }</pre>
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(BlindBeanExtension.class)
@AIPublicAPI(reason = "Attribute names (scheme, polyModulusDegree, ckksScale) and their defaults are written into consumer test classes; renaming or removing one silently changes which context those suites boot")
public @interface BlindBeanTest {

    /**
     * Scheme to initialize in addition to the always-available Paillier
     * context. {@link Scheme#PAILLIER} (the default) initializes Paillier
     * only; {@link Scheme#BFV} and {@link Scheme#CKKS} additionally boot the
     * native FHE context (which requires the native library to be loadable).
     */
    Scheme scheme() default Scheme.PAILLIER;

    /** Polynomial modulus degree for BFV/CKKS contexts. */
    int polyModulusDegree() default 8192;

    /** Scale for CKKS contexts (ignored by other schemes). */
    double ckksScale() default 1099511627776.0; // 2^40
}
