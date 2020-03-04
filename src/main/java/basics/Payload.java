package basics;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.io.Serializable;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
class Payload implements Serializable {

    private static final long serialVersionUID = 1659021498824562311L;

    //Payload
    static final String ISSUER = "iss";
    static final String SUBJECT = "sub";
    static final String EXPIRES_AT = "exp";
    static final String NOT_BEFORE = "nbf";
    static final String ISSUED_AT = "iat";
    static final String JWT_ID = "jti";
    static final String AUDIENCE = "aud";

    private final String issuer;
    private final String subject;
    private final String audience;
    private final Date expiresAt;
    private final Date notBefore;
    private final Date issuedAt;
    private final String jwtId;
    private final Map<String, String> map;


    Payload(String issuer, String subject, String audience, Date expiresAt, Date notBefore, Date issuedAt, String jwtId, Map<String, String> map) {
        this.issuer = issuer;
        this.subject = subject;
        this.audience = audience;
        this.expiresAt = expiresAt;
        this.notBefore = notBefore;
        this.issuedAt = issuedAt;
        this.jwtId = jwtId;
        this.map = map != null ? Collections.unmodifiableMap(map) : Collections.emptyMap();
    }

    Payload(Map<String, String> map) {
        this.issuer = map.get(ISSUER);
        this.subject = map.get(SUBJECT);
        this.audience = map.get(AUDIENCE);
        this.expiresAt = new Date(Long.valueOf(map.get(EXPIRES_AT)) * 1000);
        this.notBefore = new Date(Long.valueOf(map.get(NOT_BEFORE)) * 1000);
        this.issuedAt = new Date(Long.valueOf(map.get(ISSUED_AT)) * 1000);
        this.jwtId = map.get(JWT_ID);
        this.map = map != null ? Collections.unmodifiableMap(map) : Collections.emptyMap();
    }

    public Map<String, String> getMap() {
        return map;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getAudience() {
        return audience;
    }

    public Date getExpiresAt() {
        return expiresAt;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    public String getId() {
        return jwtId;
    }

    public String getClaim(String name) {
        return map.get(name);
    }

}
