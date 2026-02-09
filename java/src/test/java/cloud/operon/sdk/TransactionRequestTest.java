package cloud.operon.sdk;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransactionRequestTest {

    @Test
    void resolvesPayloadBytesAndHash() throws Exception {
        byte[] payload = "hello world".getBytes();
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .workstreamId("wstr")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payload(payload)
            .build();

        TransactionRequest.PayloadResolution resolution = request.resolvePayload();
        assertArrayEquals(payload, resolution.payloadBytes());
        assertEquals(43, resolution.payloadHash().length());
    }

    @Test
    void validatesRequiredFields() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId(" ")
            .workstreamId("wstr")
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
    void rejectsNegativeLegacyRoiValues() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .workstreamId("wstr")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payloadHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .roiBaseCost(-1)
            .build();

        OperonException ex = assertThrows(OperonException.class, request::validateForSubmit);
        assertTrue(ex.getMessage().contains("ROIBaseCost"));
    }

    @Test
    void requiresActorAndAssigneeSourceWhenIdentifiersSet() {
        TransactionRequest actorRequest = TransactionRequest.builder()
            .correlationId("corr")
            .workstreamId("wstr")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payloadHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .actorExternalId("actor-1")
            .build();

        OperonException actorError = assertThrows(OperonException.class, actorRequest::validateForSubmit);
        assertTrue(actorError.getMessage().contains("ActorExternalSource"));

        TransactionRequest assigneeRequest = TransactionRequest.builder()
            .correlationId("corr")
            .workstreamId("wstr")
            .interactionId("intr")
            .sourceDid("did:test:source")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "value", "key"))
            .payloadHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .assigneeExternalDisplayName("Owner")
            .build();

        OperonException assigneeError = assertThrows(OperonException.class, assigneeRequest::validateForSubmit);
        assertTrue(assigneeError.getMessage().contains("AssigneeExternalSource"));
    }

    @Test
    void rejectsWhenOnlyHashProvidedWithWrongFormat() {
        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr")
            .workstreamId("wstr")
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
