package com.blindbean.fhe;

/**
 * Exception thrown when a native FHE operation fails.
 * Wraps errors from the Microsoft SEAL backend.
 */
public class FheException extends RuntimeException {

    private final int errorCode;

    public FheException(String message) {
        super(message);
        this.errorCode = -1;
    }

    public FheException(String message, int errorCode) {
        super(message + " (error code: " + errorCode + ")");
        this.errorCode = errorCode;
    }

    public FheException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = -1;
    }

    /** Returns the native error code, or -1 if not applicable. */
    public int getErrorCode() {
        return errorCode;
    }
}
