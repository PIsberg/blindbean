/**
 * The marker annotations a consumer places on a field — nothing else. Kept dependency-free so the
 * compile-time annotation-processor path ({@code blindbean-processor}) pulls only this module.
 */
module se.deversity.blindbean.annotations {
    // The @AI* guardrail annotations are SOURCE-retention: needed to compile, gone at runtime.
    requires static se.deversity.vibetags.annotations;
    requires static org.jspecify;

    exports se.deversity.blindbean.annotations;
}
