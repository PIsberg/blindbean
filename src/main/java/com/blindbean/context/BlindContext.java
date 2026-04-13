package com.blindbean.context;

import com.blindbean.math.PaillierKeyPair;
import com.blindbean.math.PaillierMath;

public class BlindContext {
    private static final ThreadLocal<PaillierMath> paillierInstance = new ThreadLocal<>();

    public static void init() {
        PaillierKeyPair kp = new PaillierKeyPair(1024); // smaller key size for prototype performance
        paillierInstance.set(new PaillierMath(kp));
    }

    public static void init(PaillierKeyPair keyPair) {
        paillierInstance.set(new PaillierMath(keyPair));
    }

    public static PaillierMath getPaillier() {
        PaillierMath instance = paillierInstance.get();
        if (instance == null) {
            init();
            return paillierInstance.get();
        }
        return instance;
    }
    
    public static void clear() {
        paillierInstance.remove();
    }
}
