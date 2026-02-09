package cloud.operon.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.internal.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PatHelpersTest {

    private HttpServer server;
    private URI baseUri;
    private volatile String lastTransactionBody;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/client-api/v1/dids/self/sign", exchange ->
            respond(exchange, 200, "{\"signature\":{\"algorithm\":\"EdDSA\",\"value\":\"signed\",\"keyId\":\"\"}}"));
        server.createContext("/client-api/v1/transactions", new TransactionHandler());
        server.createContext("/client-api/v1/workstreams/wstr-1/interactions", exchange ->
            respond(exchange, 200, "{\"interactions\":[{\"id\":\"wint-1\",\"workstreamId\":\"wstr-1\"}],\"totalCount\":1,\"page\":1,\"pageSize\":1000,\"hasMore\":false}"));
        server.createContext("/client-api/v1/dids/did%3Atest%3Asource/signature/verify", exchange ->
            respond(exchange, 200, "{\"status\":\"VALID\",\"message\":\"ok\",\"did\":\"did:test:source\",\"payloadHash\":\"hash\",\"algorithm\":\"EdDSA\",\"keyId\":\"did:test:source#keys-1\"}"));
        server.start();
        baseUri = URI.create("http://localhost:" + server.getAddress().getPort());
        lastTransactionBody = null;
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void signHashWithPATDerivesKeyIdFromClaims() throws Exception {
        String pat = buildToken();
        Signature signature = PatHelpers.signHashWithPAT(
            new ClientAPIConfig(baseUri + "/client-api", HttpClient.newHttpClient()),
            pat,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "EdDSA"
        );

        assertEquals("did:test:source#keys-1", signature.keyId());
    }

    @Test
    void submitTransactionWithPATUsesClaimsDefaults() throws Exception {
        String pat = buildToken();

        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr-1")
            .interactionId("intr-1")
            .targetDid("did:test:target")
            .signature(new Signature("EdDSA", "manual", "did:test:source#keys-1"))
            .payload("payload")
            .build();

        Transaction txn = PatHelpers.submitTransactionWithPAT(
            new ClientAPIConfig(baseUri + "/client-api", HttpClient.newHttpClient()),
            pat,
            request
        );

        assertNotNull(txn);
        assertEquals("txn-1", txn.id());

        JsonNode payload = Json.mapper().readTree(lastTransactionBody);
        assertEquals("wstr-1", payload.path("workstreamId").asText());
        assertEquals("did:test:source", payload.path("sourceDid").asText());
    }

    @Test
    void fetchWorkstreamInteractionsResolvesWorkstreamFromPAT() throws Exception {
        String pat = buildToken();

        WorkstreamInteractionsResponse response = PatHelpers.fetchWorkstreamInteractions(
            new WorkstreamDataConfig(baseUri + "/client-api", HttpClient.newHttpClient()),
            pat
        );

        assertEquals(1, response.interactions().size());
        assertEquals("wint-1", response.interactions().get(0).id());
    }

    @Test
    void validateSignatureWithPATRejectsHashMismatch() {
        String pat = buildToken();

        OperonException ex = assertThrows(OperonException.class, () -> PatHelpers.validateSignatureWithPAT(
            new ClientAPIConfig(baseUri + "/client-api", HttpClient.newHttpClient()),
            pat,
            "payload".getBytes(StandardCharsets.UTF_8),
            Map.of(
                OperonClient.HEADER_OPERON_DID, "did:test:source",
                OperonClient.HEADER_OPERON_PAYLOAD_HASH, "mismatch",
                OperonClient.HEADER_OPERON_SIGNATURE, "sig",
                OperonClient.HEADER_OPERON_SIGNATURE_KEY, "did:test:source#keys-1",
                OperonClient.HEADER_OPERON_SIGNATURE_ALGO, "EdDSA"
            )
        ));

        assertTrue(ex.getMessage().contains("payload hash mismatch"));
    }

    private final class TransactionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = exchange.getRequestBody().readAllBytes();
            lastTransactionBody = new String(body, StandardCharsets.UTF_8);
            respond(exchange, 200,
                "{\"id\":\"txn-1\",\"correlationId\":\"corr-1\",\"workstreamId\":\"wstr-1\",\"interactionId\":\"intr-1\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"sourceDid\":\"did:test:source\",\"targetDid\":\"did:test:target\",\"signature\":{\"algorithm\":\"EdDSA\",\"value\":\"manual\",\"keyId\":\"did:test:source#keys-1\"},\"payloadHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"status\":\"received\"}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String buildToken() {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payloadJson = "{\"participant_did\":\"did:test:source\",\"workstream_id\":\"wstr-1\"}";
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + '.' + payload + "._";
    }
}
