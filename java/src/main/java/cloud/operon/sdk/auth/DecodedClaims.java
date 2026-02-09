package cloud.operon.sdk.auth;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.internal.Json;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * Decoded JWT claims used across the SDK.
 */
public record DecodedClaims(
    String participantDid,
    String workstreamId,
    String customerId,
    String workspaceId,
    String email,
    String name,
    List<String> tenantIds,
    List<String> roles,
    String memberId,
    String sessionId,
    String orgId,
    String participantId,
    String clientId,
    String authorizedParty,
    long expiresAtUnix
) {

    public static DecodedClaims decode(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return empty();
            }

            byte[] payload = decodeBase64(parts[1]);
            JsonNode node = Json.mapper().readTree(payload);

            String workstream = text(node, "workstream_id");
            if (workstream == null || workstream.isBlank()) {
                workstream = text(node, "channel_id");
            }

            return new DecodedClaims(
                text(node, "participant_did"),
                workstream,
                text(node, "customer_id"),
                text(node, "workspace_id"),
                text(node, "email"),
                text(node, "name"),
                readArray(node, "tenant_ids"),
                readArray(node, "roles"),
                text(node, "member_id"),
                text(node, "session_id"),
                text(node, "org_id"),
                text(node, "participant_id"),
                text(node, "client_id"),
                text(node, "azp"),
                node.path("exp").isNumber() ? node.path("exp").asLong(0L) : 0L
            );
        } catch (IOException | IllegalArgumentException ex) {
            return empty();
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        String text = value.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private static List<String> readArray(JsonNode node, String field) {
        JsonNode arr = node.path(field);
        if (!arr.isArray()) {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>();
        arr.forEach(item -> {
            if (item.isTextual()) {
                String value = item.asText();
                if (!value.isBlank()) {
                    values.add(value);
                }
            }
        });
        return Collections.unmodifiableList(values);
    }

    private static byte[] decodeBase64(String value) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            return Base64.getDecoder().decode(value);
        }
    }

    private static DecodedClaims empty() {
        return new DecodedClaims(
            null,
            null,
            null,
            null,
            null,
            null,
            Collections.emptyList(),
            Collections.emptyList(),
            null,
            null,
            null,
            null,
            null,
            null,
            0L
        );
    }
}
