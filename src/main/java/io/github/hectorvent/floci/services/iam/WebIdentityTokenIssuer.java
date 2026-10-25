package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.CompactJws;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.iam.model.WebIdentityTokenKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Mints the signed JWT {@code GetWebIdentityToken} answers with, and owns the signing material
 * behind it. The issuer URL is IAM's: outbound web identity federation mints one per account, and
 * the token names it as {@code iss} so a relying party that pinned that issuer can verify against
 * the keys it publishes.
 *
 * <p>The claim set is a reading. The API Reference says the token "contains standard JWT claims
 * such as subject, audience, expiration time, and additional identity attributes added by STS as
 * custom claims" without naming those attributes, and no recording of the operation is on hand, so
 * what is minted here is the standard claims it does name plus the request's tags, which the
 * Reference does describe as "added as custom claims", and nothing invented beyond them.
 *
 * <p>A tag cannot take over a claim STS sets. The Reference gives no rule for a tag named
 * {@code exp} or {@code sub}, and the safe reading is the only defensible one: the registered
 * claims are written over the tag claims, so a request cannot lengthen its own token's life or
 * speak for another identity by naming a tag after the claim that says so.
 */
@ApplicationScoped
public class WebIdentityTokenIssuer {

    private static final Logger LOG = Logger.getLogger(WebIdentityTokenIssuer.class);

    private static final int RSA_KEY_SIZE = 2048;
    /** P-384, the curve {@code ES384} names, as the JDK spells it. */
    private static final String P384_CURVE = "secp384r1";

    private final StorageBackend<String, WebIdentityTokenKey> keyStore;
    private final ObjectMapper objectMapper;

    @Inject
    public WebIdentityTokenIssuer(StorageFactory storageFactory, ObjectMapper objectMapper) {
        this(storageFactory.create("iam", "sts-web-identity-token-keys.json",
                new TypeReference<Map<String, WebIdentityTokenKey>>() {
                }), objectMapper);
    }

    WebIdentityTokenIssuer(StorageBackend<String, WebIdentityTokenKey> keyStore,
                           ObjectMapper objectMapper) {
        this.keyStore = keyStore;
        this.objectMapper = objectMapper;
    }

    /**
     * The two algorithms the operation publishes, in the order the API Reference names them:
     * "Valid values are RS256 (RSA with SHA-256) and ES384 (ECDSA using P-384 curve with
     * SHA-384)". Each carries the JCA names behind it, the signature one in the {@code P1363}
     * variant for ECDSA, since JWS defines that signature as the raw {@code R || S} pair.
     */
    public enum Algorithm {

        RS256("RSA", "SHA256withRSA"),
        ES384("EC", "SHA384withECDSAinP1363Format");

        private final String keyAlgorithm;
        private final String signatureAlgorithm;

        Algorithm(String keyAlgorithm, String signatureAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        /** The names the Reference lists, in the order a violation reports them in. */
        public static List<String> names() {
            return List.of(RS256.name(), ES384.name());
        }
    }

    /**
     * The token for one request: the standard claims, the request's tags as custom claims, and the
     * {@code kid} of the account's key for {@code algorithm}, which is minted on first use.
     */
    public String mint(Algorithm algorithm, String issuer, String subject, List<String> audiences,
                       Map<String, String> tagClaims, Instant issuedAt, Instant expiresAt) {
        WebIdentityTokenKey key = ensureKey(algorithm);
        ObjectNode header = objectMapper.createObjectNode();
        header.put("alg", algorithm.name());
        header.put("typ", "JWT");
        header.put("kid", key.getKeyId());
        ObjectNode claims = claims(issuer, subject, audiences, tagClaims, issuedAt, expiresAt);
        return CompactJws.sign(writeJson(header), writeJson(claims),
                privateKey(key, algorithm), algorithm.signatureAlgorithm);
    }

    private ObjectNode claims(String issuer, String subject, List<String> audiences,
                              Map<String, String> tagClaims, Instant issuedAt, Instant expiresAt) {
        ObjectNode claims = objectMapper.createObjectNode();
        tagClaims.forEach(claims::put);
        claims.put("iss", issuer);
        ArrayNode audience = claims.putArray("aud");
        audiences.forEach(audience::add);
        claims.put("sub", subject);
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("nbf", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        return claims;
    }

    private synchronized WebIdentityTokenKey ensureKey(Algorithm algorithm) {
        return keyStore.get(algorithm.name()).orElseGet(() -> generateKey(algorithm));
    }

    private WebIdentityTokenKey generateKey(Algorithm algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.keyAlgorithm);
            switch (algorithm) {
                case RS256 -> generator.initialize(RSA_KEY_SIZE);
                case ES384 -> generator.initialize(new ECGenParameterSpec(P384_CURVE));
            }
            KeyPair pair = generator.generateKeyPair();
            WebIdentityTokenKey key = new WebIdentityTokenKey();
            key.setKeyId(UUID.randomUUID().toString().replace("-", ""));
            key.setPublicKey(Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
            key.setPrivateKey(Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
            keyStore.put(algorithm.name(), key);
            LOG.debugv("Generated the account's {0} web identity token signing key", algorithm);
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Failed to generate a " + algorithm + " web identity token signing key", e);
        }
    }

    private static PrivateKey privateKey(WebIdentityTokenKey key, Algorithm algorithm) {
        try {
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getPrivateKey()));
            return KeyFactory.getInstance(algorithm.keyAlgorithm).generatePrivate(spec);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(
                    "Failed to load the " + algorithm + " web identity token signing key", e);
        }
    }

    private byte[] writeJson(ObjectNode node) {
        try {
            return objectMapper.writeValueAsBytes(node);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize web identity token claims", e);
        }
    }
}
