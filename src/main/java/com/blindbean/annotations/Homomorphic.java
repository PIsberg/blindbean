package com.blindbean.annotations;

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
}
