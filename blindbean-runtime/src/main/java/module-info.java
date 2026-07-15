/**
 * The runtime a consumer calls into: contexts, rotation, Paillier, the dispatcher, async.
 *
 * <p>Three packages ship together here because they are genuinely entangled: {@code BlindMath}
 * (in {@code math}) dispatches into {@code context}, and {@code context} uses the Paillier types
 * back — a cycle a module boundary cannot cut without moving {@code BlindMath} out of its public
 * package. {@code async} sits on {@code context} and rides along.
 *
 * <p>The Vector API is an incubating module, so it is required here and every JVM using this module
 * needs {@code --add-modules jdk.incubator.vector}. Only {@code PaillierVectorized} touches it; the
 * hot Paillier path does not.
 */
module se.deversity.blindbean.runtime {
    requires transitive se.deversity.blindbean.fhe;   // BlindMath/BlindContext hand back FheContext
    requires jdk.incubator.vector;                    // PaillierVectorized (SIMD)
    requires static se.deversity.vibetags.annotations;

    exports se.deversity.blindbean.math;
    exports se.deversity.blindbean.context;
    exports se.deversity.blindbean.async;
}
