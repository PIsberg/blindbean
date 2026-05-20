package com.blindbean.async;

/**
 * Thrown when {@link BlindAsync} exhausts its bounded retry budget while attempting
 * to dispatch a task. This can happen when {@link BlindAsync#shutdown()} races with
 * {@link BlindAsync#runAsync} or {@link BlindAsync#supplyAsync} and the executor or
 * semaphore is repeatedly unavailable across all retry attempts.
 *
 * <p>Under normal operation this exception should never be thrown — it indicates
 * a usage error (e.g., calling {@code runAsync} from a shutdown hook or while
 * the executor is being torn down).
 */
public class BlindAsyncException extends RuntimeException {

    private final int attempts;

    /**
     * @param message  human-readable description of the failure
     * @param attempts number of dispatch attempts made before giving up
     */
    public BlindAsyncException(String message, int attempts) {
        super(message);
        this.attempts = attempts;
    }

    /**
     * @param message  human-readable description of the failure
     * @param attempts number of dispatch attempts made before giving up
     * @param cause    underlying cause, if any
     */
    public BlindAsyncException(String message, int attempts, Throwable cause) {
        super(message, cause);
        this.attempts = attempts;
    }

    /**
     * Returns the number of dispatch attempts made before giving up.
     * Always equal to {@link BlindAsync#MAX_ATTEMPTS}.
     */
    public int getAttempts() {
        return attempts;
    }
}
