package io.blindnet.blindnet;

import java.security.PrivateKey;

/**
 * Provides api for generation of the jwt.
 */
public interface JwtGenerator {

    String generate(String userId, String appId, PrivateKey privateKey);

}
