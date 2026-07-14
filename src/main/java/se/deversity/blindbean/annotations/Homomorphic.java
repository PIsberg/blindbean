package se.deversity.blindbean.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates that the field should be transparently encrypted/decrypted
 * and allows mathematical operations while remaining encrypted.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Homomorphic {
    Scheme scheme() default Scheme.PAILLIER;
    Class<?> type() default Void.class;

    /**
     * Decimal places, for {@code BigDecimal} fields only.
     *
     * <p>Homomorphic schemes operate on integers, so a {@code BigDecimal} is stored as its unscaled
     * value at a <em>fixed</em> scale: {@code 12.34} at {@code scale = 2} is the integer 1234.
     * Additions stay exact because both operands share the scale — which is the point of doing
     * money this way rather than in CKKS, whose approximation makes it unfit for money.
     *
     * <p>The scale is baked into the generated code, so it is part of the storage format: change it
     * and every value already written decodes at the wrong magnitude. A value with more decimals
     * than this is rejected rather than rounded — silently losing a cent is worse than failing.
     */
    int scale() default 0;
}
