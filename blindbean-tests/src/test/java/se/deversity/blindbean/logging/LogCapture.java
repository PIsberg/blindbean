package se.deversity.blindbean.logging;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Captures everything BlindBean logs during one test.
 *
 * <p>BlindBean logs through {@code System.Logger}. With no {@code LoggerFinder} on the path the
 * JDK's default finder routes those records into {@code java.util.logging}, so attaching a JUL
 * handler captures them without the library taking a logging dependency or the test installing a
 * JVM-wide service provider.
 *
 * <p>Scoped to the {@code se.deversity.blindbean} logger rather than the root logger, for two
 * reasons: it cannot pick up records from unrelated libraries, and turning parent handlers off
 * keeps a FINE-level run from flooding the build output with the very messages being asserted on.
 *
 * <p>The logger reference is held for the lifetime of the capture on purpose. JUL keeps only weak
 * references to loggers, so a configured logger with no strong reference can be collected along
 * with its level and handlers, and the capture would silently go empty.
 */
final class LogCapture implements AutoCloseable {

    /** Every BlindBean logger is a child of this one, so it sees their records by propagation. */
    private static final String ROOT = "se.deversity.blindbean";

    private final Logger logger;
    private final Handler handler;
    private final Level previousLevel;
    private final boolean previousUseParentHandlers;
    private final List<LogRecord> records = Collections.synchronizedList(new ArrayList<>());

    private LogCapture(Logger logger) {
        this.logger = logger;
        this.previousLevel = logger.getLevel();
        this.previousUseParentHandlers = logger.getUseParentHandlers();

        this.handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
                // Nothing buffered.
            }

            @Override
            public void close() {
                // Nothing to release.
            }
        };
        this.handler.setLevel(Level.ALL);

        logger.addHandler(handler);
        logger.setLevel(Level.ALL);      // children inherit this as their effective level
        logger.setUseParentHandlers(false);
    }

    static LogCapture install() {
        return new LogCapture(Logger.getLogger(ROOT));
    }

    /** Every record captured so far, in order. */
    List<LogRecord> records() {
        synchronized (records) {
            return List.copyOf(records);
        }
    }

    /** Drops what has been captured, so a test can assert on one phase of a run. */
    void clear() {
        records.clear();
    }

    /** Interpolated messages logged at exactly {@code level}. */
    List<String> messagesAt(Level level) {
        List<String> out = new ArrayList<>();
        for (LogRecord record : records()) {
            if (record.getLevel().equals(level)) {
                out.add(format(record));
            }
        }
        return out;
    }

    /**
     * Everything captured, flattened: the interpolated message, plus each parameter rendered on its
     * own, plus any thrown type.
     *
     * <p>Parameters are included separately rather than relying on interpolation alone. A record
     * logged with more parameters than the pattern uses drops the extras during formatting, so a
     * secret passed as a surplus argument would never appear in the formatted text while still
     * being handed to every downstream appender. Checking the raw parameters closes that gap.
     */
    String allText() {
        StringBuilder sb = new StringBuilder();
        for (LogRecord record : records()) {
            sb.append(record.getLevel()).append(' ').append(format(record)).append('\n');

            Object[] params = record.getParameters();
            if (params != null) {
                for (Object p : params) {
                    sb.append("  param: ").append(p).append('\n');
                }
            }
            if (record.getThrown() != null) {
                sb.append("  thrown: ").append(record.getThrown()).append('\n');
            }
        }
        return sb.toString();
    }

    private static String format(LogRecord record) {
        String message = record.getMessage();
        Object[] params = record.getParameters();
        if (message == null) {
            return "";
        }
        if (params == null || params.length == 0) {
            return message;
        }
        try {
            return MessageFormat.format(message, params);
        } catch (IllegalArgumentException malformedPattern) {
            return message;
        }
    }

    @Override
    public void close() {
        logger.removeHandler(handler);
        logger.setLevel(previousLevel);
        logger.setUseParentHandlers(previousUseParentHandlers);
        records.clear();
    }
}
