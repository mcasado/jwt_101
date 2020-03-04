package basics;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
class Header implements Serializable {
    private static final long serialVersionUID = -4659137688548605095L;
    //Header
    static final String ALGORITHM = "alg";
    static final String CONTENT_TYPE = "cty";
    static final String TYPE = "typ";
    static final String KEY_ID = "kid";


    @JsonProperty("alg")
    private final String algorithm;
    @JsonProperty("typ")
    private final String type;
    @JsonProperty("cty")
    private final String contentType;
    @JsonProperty("kid")
    private final String keyId;
    private final Map<String, String> map;

    Header(String algorithm, String type, String contentType, String keyId, Map<String, String> map) {
        this.algorithm = algorithm;
        this.type = type;
        this.contentType = contentType;
        this.keyId = keyId;
        this.map = map;
    }

    Header(Map<String, String> map) {
         this.algorithm = map.get(ALGORITHM);
         this.type = map.get(TYPE);
         this.contentType = map.get(CONTENT_TYPE);
         this.keyId = map.get(KEY_ID);
         this.map = map;
     }


    public Map<String, String> getMap() {
        return map;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getType() {
        return type;
    }

    public String getContentType() {
        return contentType;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getHeaderClaim(String name) {
        return map.get(name);
    }
}
