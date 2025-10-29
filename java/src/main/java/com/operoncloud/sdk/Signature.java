package com.operoncloud.sdk;

public record Signature(String algorithm, String value, String keyId) {
    public Signature withKeyId(String keyId) {
        return new Signature(algorithm, value, keyId);
    }
}
