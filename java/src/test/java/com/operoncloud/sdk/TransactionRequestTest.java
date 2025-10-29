package com.operoncloud.sdk;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class TransactionRequestTest {

    @Test
    void resolvesPayloadBytesAndHash() throws Exception {
        byte[] payload = "hello world".getBytes();
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payload(payload)
            .build();

        TransactionRequest.PayloadResolution resolution = request.resolvePayload();
        assertNotNull(resolution.payloadData());
        assertEquals(Base64.getEncoder().encodeToString(payload), resolution.payloadData());
        assertEquals(43, resolution.payloadHash().length());
    }

    @Test
    void validatesRequiredFields() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId(" ")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payload(new byte[]{1})
            .build();

        OperonException ex = assertThrows(OperonException.class, request::validateForSubmit);
        assertTrue(ex.getMessage().contains("CorrelationID"));
    }
}
