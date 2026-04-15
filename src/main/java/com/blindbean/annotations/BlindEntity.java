package com.blindbean.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a class as being managed by BlindBean context for transparent homomorphic encryptions.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface BlindEntity {
    /**
     * When {@code true}, the annotation processor generates additional {@code *Async} methods
     * on the wrapper that return {@link java.util.concurrent.CompletableFuture} and execute
     * on Java 26 virtual threads via {@link com.blindbean.async.BlindAsync}.
     * Defaults to {@code false} so existing wrappers remain byte-identical.
     */
    boolean async() default false;
}
