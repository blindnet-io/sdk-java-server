package io.blindnet.blindnet.core;

import io.blindnet.blindnet.JwtGenerator;
import io.blindnet.blindnet.domain.SignatureException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.json.JSONObject;

import static java.util.Objects.requireNonNull;

/**
 * The default jwt generator implementation.
 *
 * @author stefanveselinovic
 * @since 0.0.1
 */
public class JwtGeneratorImpl implements JwtGenerator {

    private static final Logger LOGGER = Logger.getLogger(JwtGeneratorImpl.class.getName());

    private static final String Ed25519_ALGORITHM = "Ed25519";
    private static final String BC_PROVIDER = "BC";
    private static final String TOKEN_CONTENT_SEPARATOR = ".";
    private static final int TOKEN_VALIDATION_TIME_IN_MINUTES = 30;

    /**
     * Generates jwt.
     *
     * @param userId a user id.
     * @param appId an application id.
     * @param privateKey a private key used for signing of the jwt.
     * @return a jwt.
     */
    @Override
    public String generate(String userId, String appId, PrivateKey privateKey) {
        requireNonNull(userId, "User id cannot be null");
        requireNonNull(appId, "Application id cannot be null");
        requireNonNull(privateKey, "Private key cannot be null");

        String base64EncodedHeader = generateHeader();
        String base64EncodedPayload = generatePayload(userId, appId);

        String jwt = base64EncodedHeader + TOKEN_CONTENT_SEPARATOR + base64EncodedPayload;

        return jwt + TOKEN_CONTENT_SEPARATOR + Base64.getUrlEncoder().encodeToString(sign(privateKey, jwt.getBytes()));
    }

    /**
     * Generates header of the jwt.
     *
     * @return a header.
     */
    private String generateHeader() {
        return Base64.getUrlEncoder().encodeToString(new JSONObject().put("alg", "EdDSA")
                .put("typ", "JWT").toString().getBytes());
    }

    /**
     * Generates a payload of the jwt.
     *
     * @param userId a user id.
     * @param appId an application id.
     * @return a payload.
     */
    private String generatePayload(String userId, String appId) {
        return Base64.getUrlEncoder().encodeToString(new JSONObject().put("app", appId)
                .put("uid", userId)
                .put("exp", LocalDateTime.now().plusMinutes(TOKEN_VALIDATION_TIME_IN_MINUTES)).toString().getBytes());
    }

    /**
     * Signs jwt using Ed25519 algorithm.
     *
     * @param privateKey a private key used for signing.
     * @param data a data to be signed.
     * @return a jwt signature.
     */
    private byte[] sign(PrivateKey privateKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance(Ed25519_ALGORITHM, BC_PROVIDER);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            String msg = "Error during signature creation. " + exception.getMessage();
            LOGGER.log(Level.SEVERE, msg);
            throw new SignatureException(msg, exception);
        }
    }

}
