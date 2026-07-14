package se.deversity.blindbean.loadtest;

import se.deversity.blindbean.context.BlindContext;

/**
 * Is the SEAL bridge loadable?
 *
 * <p>The FHE sweeps are <em>skipped</em> rather than failed when it is not, so the Paillier metrics
 * still run on a machine (or a CI gate) with no native library — the same split the core suite uses
 * with {@code @Tag("native")}.
 */
final class Native {

    private static Boolean available;

    private Native() {}

    static synchronized boolean available() {
        if (available == null) {
            try {
                BlindContext.initBfv(4096);
                BlindContext.clear();
                available = true;
            } catch (Throwable t) {
                System.out.println("[load-tests] native SEAL bridge unavailable — FHE sweeps skipped. "
                                 + "Set -Dblindbean.native.path=<dir>. (" + t.getClass().getSimpleName() + ")");
                available = false;
            }
        }
        return available;
    }
}
