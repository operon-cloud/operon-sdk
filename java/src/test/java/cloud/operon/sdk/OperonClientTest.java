package cloud.operon.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.internal.Json;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.*;

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

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        tokenHandler.delegate = new TokenHandler();
        interactionsHandler.delegate = new InteractionsHandler();
        participantsHandler.delegate = new ParticipantsHandler();
        transactionsHandler.delegate = new TransactionHandler();
        signerHandler.delegate = new SigningHandler();

        server.createContext("/oauth2/token", tokenHandler);
        server.createContext("/client-api/v1/interactions", interactionsHandler);
        server.createContext("/client-api/v1/participants", participantsHandler);
        server.createContext("/client-api/v1/transactions", transactionsHandler);
        server.createContext("/client-api/v1/dids/self/sign", signerHandler);
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
    void submitTransactionResolvesInteractionMetadata() throws Exception {
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
            .build();

        Transaction txn = client.submitTransaction(request);
        assertNotNull(txn);
        assertEquals("txn-1", txn.id());
        assertEquals("did:test:source", txn.sourceDid());
        assertEquals("did:test:target", txn.targetDid());

        assertNotNull(lastTransactionBody, "transaction payload not captured");
        JsonNode submission = Json.mapper().readTree(lastTransactionBody);
        assertEquals("corr-123", submission.path("correlationId").asText());
        assertEquals("chan-1", submission.path("channelId").asText());
        assertEquals("intr-1", submission.path("interactionId").asText());
        assertEquals("did:test:source", submission.path("sourceDid").asText());
        assertEquals("did:test:target", submission.path("targetDid").asText());
        assertEquals("base64sig", submission.path("signature").path("value").asText());
        assertEquals("EdDSA", submission.path("signature").path("algorithm").asText());
        assertEquals("Test submission", submission.path("label").asText());
        assertTrue(submission.path("tags").isArray());
        assertEquals("priority: high", submission.path("tags").get(0).asText());

        client.close();
    }

    @Test
    void interactionsEndpointCachesResponse() throws Exception {
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

        List<InteractionSummary> interactions = client.interactions();
        assertEquals(1, interactions.size());
        InteractionSummary summary = interactions.get(0);
        assertEquals("intr-1", summary.id());
        assertEquals("chan-1", summary.channelId());
        assertEquals("did:test:source", summary.sourceDid());
        assertEquals("did:test:target", summary.targetDid());

        List<ParticipantSummary> participants = client.participants();
        assertEquals(2, participants.size());

        client.close();
    }

    @Test
    void initFailsWhenTokenEndpointReturnsError() {
        tokenHandler.delegate = exchange -> {
            tokenCalls.incrementAndGet();
            respond(exchange, 500, "{\"code\":\"INTERNAL\",\"message\":\"boom\"}");
        };

        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("broken")
            .clientSecret("broken")
            .httpClient(HttpClient.newHttpClient())
            .disableSelfSign(true)
            .build();

        OperonClient client = new OperonClient(config);
        OperonApiException ex = assertThrows(OperonApiException.class, client::init);
        assertEquals(500, ex.getStatusCode());
        assertEquals("INTERNAL", ex.getCode());
        assertEquals(1, tokenCalls.get());
    }

    @Test
    void submitTransactionSurfacesHttpErrors() throws Exception {
        transactionsHandler.delegate = exchange -> {
            respond(exchange, 403, "{\"code\":\"FORBIDDEN\",\"message\":\"denied\"}");
        };

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
            .correlationId("c1")
            .interactionId("intr-1")
            .signature(new Signature("EdDSA", "sig", null))
            .payload("payload")
            .build();

        OperonApiException ex = assertThrows(OperonApiException.class, () -> client.submitTransaction(request));
        assertEquals(403, ex.getStatusCode());
        assertEquals("FORBIDDEN", ex.getCode());
    }

    @Test
    void submitTransactionFailsWhenSelfSigningErrors() throws Exception {
        signerHandler.delegate = exchange -> respond(exchange, 500, "{\"code\":\"SIGNING_FAILED\",\"message\":\"sign error\"}");

        Config config = Config.builder()
            .baseUrl(baseUri + "/client-api")
            .tokenUrl(baseUri + "/oauth2/token")
            .clientId("client-id")
            .clientSecret("client-secret")
            .httpClient(HttpClient.newHttpClient())
            .disableSelfSign(false)
            .build();

        OperonClient client = new OperonClient(config);
        client.init();

        TransactionRequest request = TransactionRequest.builder()
            .correlationId("c1")
            .interactionId("intr-1")
            .payload("payload")
            .build();

        OperonApiException ex = assertThrows(OperonApiException.class, () -> client.submitTransaction(request));
        assertEquals("SIGNING_FAILED", ex.getCode());
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

    private class InteractionsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String body = "{\"data\":[{\"id\":\"intr-1\",\"channelId\":\"chan-1\",\"sourceParticipantId\":\"part-1\",\"targetParticipantId\":\"part-2\"}]}";
            respond(exchange, 200, body);
        }
    }

    private class ParticipantsHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String body = "{\"data\":[{\"id\":\"part-1\",\"did\":\"did:test:source\"},{\"id\":\"part-2\",\"did\":\"did:test:target\"}]}";
            respond(exchange, 200, body);
        }
    }

    private class TransactionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] body = exchange.getRequestBody().readAllBytes();
            lastTransactionBody = new String(body, StandardCharsets.UTF_8);
            String response = "{\"id\":\"txn-1\",\"correlationId\":\"corr-123\",\"sourceDid\":\"did:test:source\",\"targetDid\":\"did:test:target\"}";
            respond(exchange, 200, response);
        }
    }

    private class SigningHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = "{\"signature\":{\"algorithm\":\"EdDSA\",\"value\":\"signed-value\",\"keyId\":\"did:test:source#keys-1\"}}";
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
            } else {
                delegate.handle(exchange);
            }
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
        String payloadJson = "{\"participant_did\":\"did:test:source\",\"channel_id\":\"chan-1\"}";
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + '.' + payload + "._";
    }
}
