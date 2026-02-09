package cloud.operon.sdk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.auth.DecodedClaims;
import cloud.operon.sdk.internal.ApiErrorDecoder;
import cloud.operon.sdk.internal.Json;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Session validation helper for PAT-based flows.
 */
public final class SessionValidator {

    private SessionValidator() {
    }

    public static SessionInfo validateSession(SessionValidationConfig cfg, String pat) throws OperonException {
        String normalizedPat = trimToNull(pat);
        if (normalizedPat == null) {
            throw new OperonException("pat is required");
        }

        String baseUrl = cfg == null ? null : trimToNull(cfg.baseUrl());
        if (baseUrl == null) {
            baseUrl = Config.DEFAULT_BASE_URL;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }

        HttpClient client = cfg == null ? null : cfg.httpClient();
        if (client == null) {
            client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
        }

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/v1/session/validate"))
            .header("Authorization", "Bearer " + normalizedPat)
            .header("Accept", "application/json")
            .GET()
            .build();

        HttpResponse<java.io.InputStream> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("perform validation request interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("perform validation request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }

            JsonNode payload = Json.mapper().readTree(stream);
            DecodedClaims claims = DecodedClaims.decode(normalizedPat);

            Instant expiresAt = null;
            if (claims.expiresAtUnix() > 0) {
                expiresAt = Instant.ofEpochSecond(claims.expiresAtUnix());
            }

            int expiresInSeconds = 0;
            if (expiresAt != null) {
                long delta = Duration.between(Instant.now(), expiresAt).getSeconds();
                expiresInSeconds = (int) Math.max(delta, 0L);
            }

            List<String> roles = new ArrayList<>();
            JsonNode rolesNode = payload.path("roles");
            if (rolesNode.isArray()) {
                rolesNode.forEach(item -> {
                    if (item.isTextual() && !item.asText().isBlank()) {
                        roles.add(item.asText());
                    }
                });
            }

            Map<String, Object> featureFlags = new HashMap<>();
            JsonNode flagsNode = payload.path("feature_flags");
            if (flagsNode.isObject()) {
                featureFlags = Json.mapper().convertValue(flagsNode, new TypeReference<Map<String, Object>>() {
                });
            }

            String clientId = firstNonEmpty(claims.clientId(), claims.authorizedParty());

            return new SessionInfo(
                payload.path("user_id").asText(""),
                payload.path("email").asText(""),
                payload.path("name").asText(""),
                payload.path("customer_id").asText(""),
                List.copyOf(roles),
                Map.copyOf(featureFlags),
                firstNonEmpty(claims.workstreamId()),
                firstNonEmpty(claims.workspaceId()),
                firstNonEmpty(claims.participantDid()),
                firstNonEmpty(claims.participantId()),
                clientId,
                firstNonEmpty(claims.sessionId()),
                expiresAt,
                expiresInSeconds
            );
        } catch (IOException ex) {
            throw new OperonException("decode validation response: " + ex.getMessage(), ex);
        }
    }

    private static String firstNonEmpty(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            String trimmed = trimToNull(value);
            if (trimmed != null) {
                return trimmed;
            }
        }
        return "";
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
