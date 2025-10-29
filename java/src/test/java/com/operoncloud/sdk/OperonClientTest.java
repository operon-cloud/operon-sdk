package com.operoncloud.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.operoncloud.sdk.internal.Json;
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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.*;

class OperonClientTest {

    private HttpServer server;
    private URI baseUri;
    private volatile String lastTransactionBody;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/oauth2/token", new TokenHandler());
        server.createContext("/client-api/v1/interactions", new InteractionsHandler());
        server.createContext("/client-api/v1/participants", new ParticipantsHandler());
        server.createContext("/client-api/v1/transactions", new TransactionHandler());
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

    private class TokenHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
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

    private void respond(HttpExchange exchange, int status, String body) throws IOException {
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
