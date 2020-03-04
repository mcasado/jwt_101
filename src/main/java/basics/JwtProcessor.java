package basics;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;


public class JwtProcessor {

    private static final byte JWT_PART_SEPARATOR = (byte) 46;


    static class JWTVerificationException extends RuntimeException {
        public JWTVerificationException(String message) {
            this(message, null);
        }

        public JWTVerificationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class JWTDecodeException extends JWTVerificationException {
        public JWTDecodeException(String message) {
            this(message, null);
        }

        public JWTDecodeException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    class AlgorithmMismatchException extends JWTVerificationException {
        public AlgorithmMismatchException(String message) {
            super(message);
        }
    }

    class InvalidClaimException extends JWTVerificationException {
        public InvalidClaimException(String message) {
            super(message);
        }
    }

    /**
     * Perform the verification against the given Token
     * @param token
     * @param algorithm
     * @param secret
     * @param claims
     * @throws Exception
     */
    public JWT verify(String token, String algorithm, String secret, Map<String, String> claims) throws Exception {
        // decode JWT header, payload and signature
        JWT jwt = decode(token);
        // Check if algorithm to validate signature matches algorithm in header
        verifyAlgorithm(jwt, algorithm);
        // verify signature matches encoded header.payload
        verifySignatureFor(algorithm, secret.getBytes(StandardCharsets.UTF_8), jwt.getParts()[0].getBytes(StandardCharsets.UTF_8), jwt.getParts()[1].getBytes(StandardCharsets.UTF_8), jwt.getSignature().getBytes(StandardCharsets.UTF_8));
        // verify claims
        verifyClaims(jwt, claims);
        return jwt;
    }

    /**
     * Verify signature for JWT header and payload.
     *
     * @param algorithm
     * @param secretBytes
     * @param headerBytes
     * @param payloadBytes
     * @param signatureBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private boolean verifySignatureFor(String algorithm, byte[] secretBytes, byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, headerBytes, payloadBytes), signatureBytes);
    }

    /**
     * @param jwt
     * @param expectedAlgorithm
     * @throws AlgorithmMismatchException
     */
    private void verifyAlgorithm(JWT jwt, String expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.equals(jwt.getHeader().getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    /**
     * Create signature for JWT header and payload.
     *
     * @param algorithm
     * @param secretBytes
     * @param headerBytes
     * @param payloadBytes
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] headerBytes, byte[] payloadBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        mac.update(headerBytes);
        mac.update(JWT_PART_SEPARATOR);
        return mac.doFinal(payloadBytes);
    }

    private void verifyClaims(JWT jwt, Map<String, String> claims) throws Exception {
        for (Map.Entry<String, String> entry : claims.entrySet()) {
            switch (entry.getKey()) {

                case Payload.JWT_ID:
                    assertValidStringClaim(entry.getKey(), jwt.getPayload().getId(), (String) entry.getValue());
                    break;
                case Payload.SUBJECT:
                    assertValidStringClaim(entry.getKey(), jwt.getPayload().getSubject(), (String) entry.getValue());
                    break;

            }
        }
    }

    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }


    /**
     * Method to parse a given JWT token into it's JWT representation
     *
     * @param jwt
     * @return
     * @throws JWTDecodeException
     */
    private JWT decode(String jwt) throws JWTDecodeException {
        String[] parts = splitToken(jwt);
        String headerJson;
        String payloadJson;

        try {
            headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
            String signature = StringUtils.newStringUtf8(Base64.decodeBase64(parts[2]));
            ObjectMapper mapper = new ObjectMapper();
            JWT decodedJwt = new JWT(new Header(mapper.readValue(headerJson, Map.class)), new Payload(mapper.readValue(payloadJson, Map.class)), signature, parts);

            return decodedJwt;
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (JsonMappingException e) {
            throw new JWTDecodeException(e.getMessage(), e);
        } catch (JsonProcessingException e) {
            throw new JWTDecodeException(e.getMessage(), e);
        }
    }

    /**
     * Splits the given token on the "." chars into a String array with 3 parts.
     *
     * @param token
     * @return
     * @throws JWTDecodeException
     */
    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

    public static void main(String[] args) {
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmFsdWUifQ.Jki8pvw6KGbxpMinufrgo6RDL1cu7AtNMJYVh6t-_cE";
        
        Map<String, String> claims = new HashMap();
        claims.put("sub", "1234567890");

        JwtProcessor jwtp = new JwtProcessor();

        try {
            JWT decodedJWT = jwtp.verify(token, "HmacSHA256", "secret", claims);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
