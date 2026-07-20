/**
 * {@code @BlindBeanTest} and the JUnit 5 extension that boots and tears down a {@code BlindContext}
 * per test method. Its own module so JUnit lands on a consumer's path only when they use it.
 *
 * <p>The extension is instantiated reflectively by JUnit via {@code @ExtendWith}, which the export
 * covers; the {@code @BlindBeanTest} annotation is read reflectively off the consumer's test class,
 * which the consumer opens to JUnit, not us.
 */
module se.deversity.blindbean.junit {
    requires transitive se.deversity.blindbean.runtime;
    requires transitive org.junit.jupiter.api;
    requires static se.deversity.vibetags.annotations;
    requires static org.jspecify;

    exports se.deversity.blindbean.junit;
}
