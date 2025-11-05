package cloud.operon.sdk;

import org.junit.jupiter.api.Test;

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
        assertNotNull(resolution.payloadBytes());
        assertArrayEquals(payload, resolution.payloadBytes());
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

    @Test
    void rejectsInvalidDidFormat() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("bad-source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payload(new byte[]{1})
            .build();

        OperonException ex = assertThrows(OperonException.class, request::validateForSubmit);
        assertTrue(ex.getMessage().contains("SourceDID must be a valid DID"));
    }

    @Test
    void detectsPayloadHashMismatch() throws Exception {
        byte[] payload = "payload".getBytes();
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payload(payload)
            .payloadHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .build();

        OperonException ex = assertThrows(OperonException.class, request::resolvePayload);
        assertTrue(ex.getMessage().contains("provided payload hash"));
    }

    @Test
    void rejectsMissingSignatureFields() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("", "", null))
            .payload(new byte[]{1})
            .build();

        OperonException ex = assertThrows(OperonException.class, request::validateForSubmit);
        assertTrue(ex.getMessage().contains("Signature algorithm"));
    }

    @Test
    void rejectsWhenOnlyHashProvidedWithWrongFormat() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .channelId("chan")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payloadHash("short")
            .build();

        OperonException ex = assertThrows(OperonException.class, request::resolvePayload);
        assertTrue(ex.getMessage().contains("payload hash must be 43 characters"));
    }
}
