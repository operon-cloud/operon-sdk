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
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OperonClientTest {

    private HttpServer server;
    private URI baseUri;
    private volatile String lastTransactionBody;
    private final AtomicInteger tokenCalls = new AtomicInteger();

    private final DelegatingHandler tokenHandler = new DelegatingHandler();
    private final DelegatingHandler interactionsHandler = new DelegatingHandler();
    private final DelegatingHandler participantsHandler = new DelegatingHandler();
    private final DelegatingHandler transactionsHandler = new DelegatingHandler();
    private final DelegatingHandler signerHandler = new DelegatingHandler();
    private final DelegatingHandler verifyHandler = new DelegatingHandler();
    private final DelegatingHandler workstreamHandler = new DelegatingHandler();
    private final DelegatingHandler workstreamInteractionsHandler = new DelegatingHandler();
    private final DelegatingHandler workstreamParticipantsHandler = new DelegatingHandler();

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        tokenHandler.delegate = new TokenHandler();
        interactionsHandler.delegate = new InteractionsHandler();
        participantsHandler.delegate = new ParticipantsHandler();
        transactionsHandler.delegate = new TransactionHandler();
        signerHandler.delegate = new SigningHandler();
        verifyHandler.delegate = new VerifyHandler();
        workstreamHandler.delegate = new WorkstreamHandler();
        workstreamInteractionsHandler.delegate = new WorkstreamInteractionsHandler();
        workstreamParticipantsHandler.delegate = new WorkstreamParticipantsHandler();

        server.createContext("/oauth2/token", tokenHandler);
        server.createContext("/client-api/v1/interactions", interactionsHandler);
        server.createContext("/client-api/v1/participants", participantsHandler);
        server.createContext("/client-api/v1/transactions", transactionsHandler);
        server.createContext("/client-api/v1/dids/self/sign", signerHandler);
        server.createContext("/client-api/v1/dids/did:test:source/signature/verify", verifyHandler);
        server.createContext("/client-api/v1/workstreams/wstr-1", workstreamHandler);
        server.createContext("/client-api/v1/workstreams/wstr-1/interactions", workstreamInteractionsHandler);
        server.createContext("/client-api/v1/workstreams/wstr-1/participants", workstreamParticipantsHandler);
        server.start();

        baseUri = URI.create("http://localhost:" + server.getAddress().getPort());
        lastTransactionBody = null;
        tokenCalls.set(0);
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void submitTransactionResolvesInteractionMetadataAndSerializesParityFields() throws Exception {
        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("client-id")
            .clientSecret("client-secret")
            .httpClient(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build())
            .disableSelfSign(true)
            .build();

        OperonClient client = new OperonClient(config);
        client.init();

        TransactionRequest request = TransactionRequest.builder()
            .correlationId("corr-123")
            .interactionId("intr-1")
            .signature(new Signature("EdDSA", "base64sig", null))
            .label("Test submission")
            .tags(List.of(" priority: high ", ""))
            .payload("example payload")
            .state("open")
            .stateId("state-1")
            .stateLabel("Open")
            .roiBaseCost(7)
            .roiBaseTime(5)
            .roiCostSaving(3)
            .roiTimeSaving(2)
            .actorExternalId("agent-1")
            .actorExternalDisplayName("Agent One")
            .actorExternalSource("crm")
            .assigneeExternalId("owner-2")
            .assigneeExternalDisplayName("Owner Two")
            .assigneeExternalSource("crm")
            .customerId("cust-1")
            .workspaceId("wksp-1")
            .createdBy("user-1")
            .build();

        Transaction txn = client.submitTransaction(request);
        assertNotNull(txn);
        assertEquals("txn-1", txn.id());
        assertEquals("did:test:source", txn.sourceDid());
        assertEquals("did:test:target", txn.targetDid());

        assertNotNull(lastTransactionBody, "transaction payload not captured");
        JsonNode submission = Json.mapper().readTree(lastTransactionBody);
        assertEquals("corr-123", submission.path("correlationId").asText());
        assertEquals("wstr-1", submission.path("workstreamId").asText());
        assertEquals("intr-1", submission.path("interactionId").asText());
        assertEquals("did:test:source", submission.path("sourceDid").asText());
        assertEquals("did:test:target", submission.path("targetDid").asText());
        assertEquals("base64sig", submission.path("signature").path("value").asText());
        assertEquals("EdDSA", submission.path("signature").path("algorithm").asText());
        assertEquals("Test submission", submission.path("label").asText());
        assertEquals("priority: high", submission.path("tags").get(0).asText());
        assertEquals(7, submission.path("roiBaseCost").asInt());
        assertEquals("agent-1", submission.path("actorExternalId").asText());
        assertEquals("owner-2", submission.path("assigneeExternalId").asText());

        client.close();
    }

    @Test
    void workstreamEndpointsUseTokenScopedWorkstream() throws Exception {
        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("client-id")
            .clientSecret("client-secret")
            .httpClient(HttpClient.newHttpClient())
            .disableSelfSign(true)
            .build();

        OperonClient client = new OperonClient(config);
        client.init();

        Workstream workstream = client.getWorkstream();
        assertEquals("wstr-1", workstream.id());

        WorkstreamInteractionsResponse interactions = client.getWorkstreamInteractions();
        assertEquals(1, interactions.interactions().size());

        WorkstreamParticipantsResponse participants = client.getWorkstreamParticipants();
        assertEquals(1, participants.participants().size());

        client.close();
    }

    @Test
    void generateAndValidateSignatureHeaders() throws Exception {
        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("client-id")
            .clientSecret("client-secret")
            .httpClient(HttpClient.newHttpClient())
            .disableSelfSign(false)
            .signingAlgorithm("ES256")
            .build();

        OperonClient client = new OperonClient(config);
        client.init();

        byte[] payload = "{\"demo\":true}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = client.generateSignatureHeaders(payload, "");

        assertEquals("did:test:source", headers.get(OperonClient.HEADER_OPERON_DID));
        assertEquals("ES256", headers.get(OperonClient.HEADER_OPERON_SIGNATURE_ALGO));

        SignatureValidationResult result = client.validateSignatureHeaders(payload, headers);
        assertEquals("VALID", result.status());

        client.close();
    }

    @Test
    void throwsWhenInteractionMissingAfterReload() throws Exception {
        interactionsHandler.delegate = exchange -> respond(exchange, 200, "{\"data\":[]}");

        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("client-id")
            .clientSecret("client-secret")
            .httpClient(HttpClient.newHttpClient())
            .disableSelfSign(true)
            .build();

        OperonClient client = new OperonClient(config);
        client.init();

        TransactionRequest request = TransactionRequest.builder()
            .correlationId("missing")
            .interactionId("intr-unknown")
            .signature(new Signature("EdDSA", "sig", null))
            .payload("payload")
            .build();

        OperonException ex = assertThrows(OperonException.class, () -> client.submitTransaction(request));
        assertTrue(ex.getMessage().contains("interaction intr-unknown not found"));
    }

    private class TokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            tokenCalls.incrementAndGet();
            String token = buildToken();
            String body = "{\"access_token\":\"" + token + "\",\"expires_in\":3600}";
            respond(exchange, 200, body);
        }
    }

    private static class InteractionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String body = "{\"data\":[{\"id\":\"intr-1\",\"workstreamId\":\"wstr-1\",\"sourceParticipantId\":\"part-1\",\"targetParticipantId\":\"part-2\"}],\"totalCount\":1}";
            respond(exchange, 200, body);
        }
    }

    private static class ParticipantsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String body = "{\"data\":[{\"id\":\"part-1\",\"did\":\"did:test:source\"},{\"id\":\"part-2\",\"did\":\"did:test:target\"}],\"totalCount\":2}";
            respond(exchange, 200, body);
        }
    }

    private class TransactionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = exchange.getRequestBody().readAllBytes();
            lastTransactionBody = new String(body, StandardCharsets.UTF_8);
            String response = "{\"id\":\"txn-1\",\"correlationId\":\"corr-123\",\"workstreamId\":\"wstr-1\",\"interactionId\":\"intr-1\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"sourceDid\":\"did:test:source\",\"targetDid\":\"did:test:target\",\"signature\":{\"algorithm\":\"EdDSA\",\"value\":\"sig\",\"keyId\":\"did:test:source#keys-1\"},\"payloadHash\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"status\":\"received\"}";
            respond(exchange, 200, response);
        }
    }

    private static class SigningHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"signature\":{\"algorithm\":\"ES256\",\"value\":\"signed-value\",\"keyId\":\"did:test:source#keys-1\"}}";
            respond(exchange, 200, response);
        }
    }

    private static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"status\":\"VALID\",\"message\":\"ok\",\"did\":\"did:test:source\",\"payloadHash\":\"placeholder\",\"algorithm\":\"ES256\",\"keyId\":\"did:test:source#keys-1\"}";
            respond(exchange, 200, response);
        }
    }

    private static class WorkstreamHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"id\":\"wstr-1\",\"name\":\"Support\",\"status\":\"active\"}";
            respond(exchange, 200, response);
        }
    }

    private static class WorkstreamInteractionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"interactions\":[{\"id\":\"wint-1\",\"workstreamId\":\"wstr-1\"}],\"totalCount\":1,\"page\":1,\"pageSize\":1000,\"hasMore\":false}";
            respond(exchange, 200, response);
        }
    }

    private static class WorkstreamParticipantsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"participants\":[{\"id\":\"wp-1\",\"did\":\"did:test:source\"}],\"totalCount\":1,\"page\":1,\"pageSize\":1000,\"hasMore\":false}";
            respond(exchange, 200, response);
        }
    }

    private static class DelegatingHandler implements HttpHandler {
        volatile HttpHandler delegate;

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (delegate == null) {
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
                return;
            }
            delegate.handle(exchange);
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
