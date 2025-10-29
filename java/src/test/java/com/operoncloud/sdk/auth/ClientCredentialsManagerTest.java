package com.operoncloud.sdk.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.operoncloud.sdk.OperonApiException;
import com.operoncloud.sdk.OperonException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.*;

class ClientCredentialsManagerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpServer server;
    private URI baseUri;
    private final AtomicInteger tokenRequestCount = new AtomicInteger();
    private volatile Token lastToken;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.start();
        baseUri = URI.create("http://localhost:" + server.getAddress().getPort());
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void fetchesModernTokenUsingFormPayload() throws Exception {
        registerTokenHandler("/oauth2/token", false, 3600);

        ClientCredentialsManager manager = new ClientCredentialsManager(
            HttpClient.newHttpClient(),
            baseUri.resolve("/oauth2/token").toString(),
            "client-id",
            "client-secret",
            "transactions:write",
            List.of("audience:A", "audience:B"),
            Duration.ofSeconds(30),
            Duration.ofSeconds(10)
        );

        Token token = manager.token();
        assertFalse(token.getAccessToken().isBlank());
        assertEquals("chan-1", token.getChannelId());
        assertEquals(List.of("tenant-1", "tenant-2"), token.getTenantIds());
        assertTrue(token.getExpiry().isAfter(Instant.now()));
        assertEquals(1, tokenRequestCount.get());

        Token cached = manager.token();
        assertEquals(token.getAccessToken(), cached.getAccessToken());
        assertEquals(1, tokenRequestCount.get(), "should not re-fetch token while still valid");
    }

    @Test
    void fetchesLegacyTokenUsingJsonPayload() throws Exception {
        registerTokenHandler("/v1/session/m2m/token", true, 120);

        ClientCredentialsManager manager = new ClientCredentialsManager(
            HttpClient.newHttpClient(),
            baseUri.resolve("/v1/session/m2m/token").toString(),
            "legacy-client",
            "legacy-secret",
            null,
            null,
            Duration.ofSeconds(30),
            Duration.ofSeconds(10)
        );

        Token token = manager.token();
        assertFalse(token.getAccessToken().isBlank());
        assertEquals("chan-1", token.getChannelId());
        assertEquals(List.of("tenant-1", "tenant-2"), token.getTenantIds());
    }

    @Test
    void refreshesTokenWhenLeewayExpires() throws Exception {
        registerTokenHandler("/oauth2/token", false, 3);

        ClientCredentialsManager manager = new ClientCredentialsManager(
            HttpClient.newHttpClient(),
            baseUri.resolve("/oauth2/token").toString(),
            "client",
            "secret",
            null,
            null,
            Duration.ofSeconds(2),
            Duration.ofSeconds(1)
        );

        Token first = manager.token();
        assertFalse(first.getAccessToken().isBlank());

        Thread.sleep(2500);

        Token second = manager.token();
        assertFalse(second.getAccessToken().isBlank());
        assertTrue(second.getExpiry().isAfter(first.getExpiry()));
        assertEquals(2, tokenRequestCount.get());
    }

    @Test
    void surfacesApiErrorsFromTokenEndpoint() throws Exception {
        server.createContext("/oauth2/token", exchange -> {
            tokenRequestCount.incrementAndGet();
            respond(exchange, 401, Map.of("code", "INVALID_CLIENT", "message", "invalid credentials"));
        });

        ClientCredentialsManager manager = new ClientCredentialsManager(
            HttpClient.newHttpClient(),
            baseUri.resolve("/oauth2/token").toString(),
            "wrong",
            "secret",
            null,
            null,
            Duration.ofSeconds(30),
            Duration.ofSeconds(10)
        );

        OperonApiException ex = assertThrows(OperonApiException.class, manager::token);
        assertEquals(401, ex.getStatusCode());
        assertEquals("INVALID_CLIENT", ex.getCode());
    }

    @Test
    void throwsWhenAccessTokenMissing() {
        server.createContext("/oauth2/token", exchange -> respond(exchange, 200, Map.of("expires_in", 3600)));

        ClientCredentialsManager manager = new ClientCredentialsManager(
            HttpClient.newHttpClient(),
            baseUri.resolve("/oauth2/token").toString(),
            "client",
            "secret",
            null,
            null,
            Duration.ofSeconds(30),
            Duration.ofSeconds(10)
        );

        OperonException ex = assertThrows(OperonException.class, manager::token);
        assertTrue(ex.getMessage().contains("access_token"));
    }

    private void registerTokenHandler(String path, boolean legacy, int expiresIn) {
        server.createContext(path, new TokenHandler(legacy, expiresIn));
    }

    private final class TokenHandler implements HttpHandler {
        private final boolean legacy;
        private final int expiresIn;

        private TokenHandler(boolean legacy, int expiresIn) {
            this.legacy = legacy;
            this.expiresIn = expiresIn;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            tokenRequestCount.incrementAndGet();

            if (!legacy) {
                assertEquals("application/x-www-form-urlencoded", exchange.getRequestHeaders().getFirst("Content-Type"));
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, String> params = parseForm(body);
                assertEquals("client_credentials", params.get("grant_type"));
                if (params.containsKey("scope")) {
                    assertEquals("transactions:write", params.get("scope"));
                }
                if (params.containsKey("audience")) {
                    assertTrue(params.get("audience").contains("audience:A"));
                }
            } else {
                assertEquals("application/json", exchange.getRequestHeaders().getFirst("Content-Type"));
                Map<?, ?> payload = MAPPER.readValue(exchange.getRequestBody(), Map.class);
                assertEquals("client_credentials", payload.get("grant_type"));
            }

            Map<String, Object> claims = new HashMap<>();
            claims.put("participant_did", "did:test:source");
            claims.put("channel_id", "chan-1");
            claims.put("customer_id", "cust-1");
            claims.put("workspace_id", "ws-1");
            claims.put("email", "user@example.com");
            claims.put("name", "Example User");
            claims.put("tenant_ids", List.of("tenant-1", "tenant-2"));
            claims.put("roles", List.of("role:write"));
            claims.put("member_id", "member-1");
            claims.put("session_id", "session-1");
            claims.put("org_id", "org-1");

            String tokenValue = buildToken(claims);

            lastToken = new Token(
                tokenValue,
                "did:test:source",
                "chan-1",
                "cust-1",
                "ws-1",
                "user@example.com",
                "Example User",
                List.of("tenant-1", "tenant-2"),
                List.of("role:write"),
                "member-1",
                "session-1",
                "org-1",
                Instant.now().plusSeconds(expiresIn)
            );

            respond(exchange, 200, Map.of(
                "access_token", tokenValue,
                "expires_in", expiresIn,
                "token_type", "Bearer"
            ));
        }
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> params = new HashMap<>();
        if (body == null || body.isEmpty()) {
            return params;
        }
        Arrays.stream(body.split("&"))
            .filter(part -> !part.isEmpty())
            .forEach(part -> {
                String[] pieces = part.split("=", 2);
                String key = URLDecoder.decode(pieces[0], StandardCharsets.UTF_8);
                String value = pieces.length > 1 ? URLDecoder.decode(pieces[1], StandardCharsets.UTF_8) : "";
                params.merge(key, value, (existing, newValue) -> existing + "," + newValue);
            });
        return params;
    }

    private static String buildToken(Map<String, Object> claims) throws IOException {
        String header = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MAPPER.writeValueAsBytes(claims));
        return header + "." + payload + "._";
    }

    private static void respond(HttpExchange exchange, int status, Map<String, ?> body) throws IOException {
        byte[] payload = MAPPER.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(payload);
        }
    }
}
