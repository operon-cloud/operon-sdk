package cloud.operon.sdk.auth;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.OperonApiException;
import cloud.operon.sdk.OperonException;
import cloud.operon.sdk.internal.ApiErrorDecoder;
import cloud.operon.sdk.internal.Json;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * TokenProvider implementation performing OAuth client credentials flows.
 */
public final class ClientCredentialsManager implements TokenProvider {

    private static final Duration DEFAULT_LEEWAY = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final List<String> audience;
    private final Duration leeway;
    private final Duration requestTimeout;
    private final boolean legacyEndpoint;

    private final ReentrantLock lock = new ReentrantLock();
    private volatile Token cached;

    public ClientCredentialsManager(
        HttpClient httpClient,
        String tokenUrl,
        String clientId,
        String clientSecret,
        String scope,
        List<String> audience,
        Duration leeway,
        Duration requestTimeout
    ) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.tokenUrl = Objects.requireNonNull(tokenUrl, "tokenUrl");
        this.clientId = Objects.requireNonNull(clientId, "clientId");
        this.clientSecret = Objects.requireNonNull(clientSecret, "clientSecret");
        this.scope = scope;
        this.audience = audience == null ? Collections.emptyList() : List.copyOf(audience);
        this.leeway = leeway == null || leeway.isZero() || leeway.isNegative() ? DEFAULT_LEEWAY : leeway;
        this.requestTimeout = requestTimeout == null || requestTimeout.isZero() || requestTimeout.isNegative()
            ? Duration.ofSeconds(30) : requestTimeout;
        this.legacyEndpoint = tokenUrl.contains("/v1/session/m2m");
    }

    @Override
    public Token token() throws OperonException {
        Token current = cached;
        if (current != null && isFresh(current)) {
            return current;
        }

        lock.lock();
        try {
            current = cached;
            if (current != null && isFresh(current)) {
                return current;
            }

            Token fresh = fetchToken();
            cached = fresh;
            return fresh;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void invalidate() {
        cached = null;
    }

    @Override
    public Token forceRefresh() throws OperonException {
        lock.lock();
        try {
            Token fresh = fetchToken();
            cached = fresh;
            return fresh;
        } finally {
            lock.unlock();
        }
    }

    private boolean isFresh(Token token) {
        Instant refreshAt = token.getExpiry().minus(leeway);
        return Instant.now().isBefore(refreshAt);
    }

    private Token fetchToken() throws OperonException {
        HttpResponse<java.io.InputStream> response;
        try {
            HttpRequest request = legacyEndpoint ? legacyRequest() : modernRequest();
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("request token interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("request token: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream bodyStream = response.body()) {
            if (response.statusCode() >= 400) {
                OperonApiException apiError = ApiErrorDecoder.decode(response.statusCode(), bodyStream);
                throw apiError;
            }

            JsonNode node = Json.mapper().readTree(bodyStream);
            String accessToken = node.path("access_token").asText();
            if (accessToken == null || accessToken.isBlank()) {
                throw new OperonException("token response missing access_token");
            }

            int expiresIn = node.path("expires_in").isInt() ? node.path("expires_in").asInt() : 60;
            if (expiresIn <= 0) {
                expiresIn = 60;
            }
            Instant expiry = Instant.now().plusSeconds(expiresIn);

            DecodedClaims claims = DecodedClaims.decode(accessToken);
            return new Token(
                accessToken,
                claims.participantDid(),
                claims.workstreamId(),
                claims.customerId(),
                claims.workspaceId(),
                claims.email(),
                claims.name(),
                claims.tenantIds(),
                claims.roles(),
                claims.memberId(),
                claims.sessionId(),
                claims.orgId(),
                claims.participantId(),
                claims.clientId(),
                claims.authorizedParty(),
                claims.expiresAtUnix(),
                expiry
            );
        } catch (IOException ex) {
            throw new OperonException("decode token response: " + ex.getMessage(), ex);
        }
    }

    private HttpRequest modernRequest() {
        StringBuilder form = new StringBuilder("grant_type=client_credentials");
        if (scope != null && !scope.isBlank()) {
            form.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        for (String aud : audience) {
            if (aud == null || aud.isBlank()) {
                continue;
            }
            form.append("&audience=").append(URLEncoder.encode(aud.trim(), StandardCharsets.UTF_8));
        }

        String credentials = Base64.getEncoder()
            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        return HttpRequest.newBuilder()
            .uri(URI.create(tokenUrl))
            .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", "Basic " + credentials)
            .timeout(requestTimeout)
            .build();
    }

    private HttpRequest legacyRequest() throws IOException {
        java.util.Map<String, Object> body = new java.util.HashMap<>();
        body.put("client_id", clientId);
        body.put("client_secret", clientSecret);
        body.put("grant_type", "client_credentials");
        if (scope != null && !scope.isBlank()) {
            body.put("scope", scope);
        }
        if (!audience.isEmpty()) {
            List<String> trimmedAudience = new ArrayList<>();
            for (String value : audience) {
                if (value != null && !value.isBlank()) {
                    trimmedAudience.add(value.trim());
                }
            }
            if (!trimmedAudience.isEmpty()) {
                body.put("audience", trimmedAudience);
            }
        }

        byte[] json = Json.mapper().writeValueAsBytes(body);
        return HttpRequest.newBuilder()
            .uri(URI.create(tokenUrl))
            .POST(HttpRequest.BodyPublishers.ofByteArray(json))
            .header("Content-Type", "application/json")
            .timeout(requestTimeout)
            .build();
    }
}
