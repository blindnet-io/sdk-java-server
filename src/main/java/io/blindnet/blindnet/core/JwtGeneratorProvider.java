package io.blindnet.blindnet.core;

import io.blindnet.blindnet.JwtGenerator;

/**
 * Provides default implementation of the jwt generator.
 */
public class JwtGeneratorProvider {

    private JwtGeneratorProvider() {}

    public static JwtGenerator getInstance() {
        return new JwtGeneratorImpl();
    }

}
