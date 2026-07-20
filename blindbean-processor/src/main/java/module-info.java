/**
 * The compile-time annotation processor. Depends only on {@code annotations} — it emits the runtime
 * calls as text, so nothing here drags the runtime, the native bridge, or the Vector API onto a
 * consumer's compile path.
 *
 * <p>{@code provides} makes the processor discoverable when this jar is on the
 * {@code --processor-module-path}; AutoService's {@code META-INF/services} entry covers the classic
 * {@code -processorpath}. Both are needed, and the module-path one is what the module-path baseline
 * test exercises.
 */
module se.deversity.blindbean.processor {
    requires java.compiler;                             // javax.annotation.processing, javax.lang.model
    requires se.deversity.blindbean.annotations;
    requires static com.google.auto.service;
    requires static se.deversity.vibetags.annotations;
    requires static org.jspecify;

    provides javax.annotation.processing.Processor
        with se.deversity.blindbean.processor.HomomorphicProcessor;
}
