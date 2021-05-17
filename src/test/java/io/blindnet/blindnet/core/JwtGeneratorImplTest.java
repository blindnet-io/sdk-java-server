package io.blindnet.blindnet.core;

import io.blindnet.blindnet.JwtGenerator;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JwtGeneratorImplTest {

    private JwtGenerator jwtGenerator;

    @BeforeEach
    public void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        jwtGenerator = JwtGeneratorProvider.getInstance();
    }

    @Test
    public void testGenerateJwt() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair keyPair = generateEd25519KeyPair();
        String userId = UUID.randomUUID().toString();
        String appId = UUID.randomUUID().toString();

        String jwt = jwtGenerator.generate(userId, appId, keyPair.getPrivate());

        assertNotNull(jwt);

        String[] jwtParts = jwt.split("\\.");
        JSONObject header = new JSONObject(new String(Base64.getUrlDecoder().decode(jwtParts[0])));

        assertEquals(header.get("alg"), "EdDSA");
        assertEquals(header.get("typ"), "JWT");

        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(jwtParts[1])));
        assertEquals(payload.get("uid"), userId);
        assertEquals(payload.get("app"), appId);

    }

    private KeyPair generateEd25519KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        return kpg.generateKeyPair();
    }

}
