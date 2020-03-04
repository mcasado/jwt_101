package basics;

public class JWT {

    private Header header;
    private Payload payload;
    private String signature;
    private String[] parts;

    public JWT(Header header, Payload payload, String signature, String[] parts) {
        this.header = header;
        this.payload = payload;
        this.signature = signature;
        this.parts = parts;
    }

    public Header getHeader() {
        return header;
    }

    public Payload getPayload() {
        return payload;
    }

    public String getSignature() {
        return signature;
    }

    public String[] getParts() {
        return parts;
    }



}
