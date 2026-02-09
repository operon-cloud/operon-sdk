package cloud.operon.sdk;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionValidatorTest {

    private HttpServer server;
    private URI baseUri;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/client-api/v1/session/validate", exchange -> {
            String response = "{\"user_id\":\"user-1\",\"email\":\"user@example.com\",\"name\":\"User\",\"customer_id\":\"cust-1\",\"roles\":[\"sandbox\"],\"feature_flags\":{\"demo\":true}}";
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
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
    void validateSessionReturnsClaimsAndServerData() throws Exception {
        long exp = Instant.now().plusSeconds(600).getEpochSecond();
        String pat = buildToken(exp);

        SessionInfo info = SessionValidator.validateSession(
            new SessionValidationConfig(baseUri + "/client-api", HttpClient.newHttpClient()),
            pat
        );

        assertEquals("user-1", info.userId());
        assertEquals("wstr-1", info.workstreamId());
        assertEquals("did:test:source", info.participantDid());
        assertEquals("client-1", info.clientId());
        assertTrue(info.expiresInSeconds() > 0);
    }

    private static String buildToken(long exp) {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payloadJson = "{\"participant_did\":\"did:test:source\",\"participant_id\":\"part-1\",\"workstream_id\":\"wstr-1\",\"workspace_id\":\"wksp-1\",\"session_id\":\"sess-1\",\"client_id\":\"client-1\",\"exp\":" + exp + "}";
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        return header + '.' + payload + "._";
    }
}
