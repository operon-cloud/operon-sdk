package cloud.operon.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.auth.DecodedClaims;
import cloud.operon.sdk.internal.ApiErrorDecoder;
import cloud.operon.sdk.internal.HttpUtil;
import cloud.operon.sdk.internal.Json;
import cloud.operon.sdk.signing.SelfSigner;
import cloud.operon.sdk.signing.SigningResult;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * PAT-scoped helper methods matching Go SDK helper flows.
 */
public final class PatHelpers {

    private PatHelpers() {
    }

    public static Signature signHashWithPAT(
        ClientAPIConfig cfg,
        String pat,
        String payloadHash,
        String algorithm
    ) throws OperonException {
        String normalizedPat = requirePAT(pat);
        String normalizedHash = requirePayloadHash(payloadHash);
        String normalizedAlgorithm = requireAlgorithm(algorithm);

        NormalizedClientConfig normalized = normalizeClientConfig(cfg);
        SelfSigner signer = new SelfSigner(normalized.httpClient(), normalized.baseUrl());

        SigningResult result = signer.sign(normalizedPat, normalizedHash, normalizedAlgorithm);
        Signature signature = new Signature(result.algorithm(), result.value(), result.keyId());

        if (signature.keyId() == null || signature.keyId().isBlank()) {
            DecodedClaims claims = DecodedClaims.decode(normalizedPat);
            if (claims.participantDid() != null && !claims.participantDid().isBlank()) {
                signature = signature.withKeyId(claims.participantDid() + Config.DEFAULT_KEY_ID_SUFFIX);
            }
        }

        return signature;
    }

    public static Transaction submitTransactionWithPAT(
        ClientAPIConfig cfg,
        String pat,
        TransactionRequest request
    ) throws OperonException {
        Objects.requireNonNull(request, "request");
        String normalizedPat = requirePAT(pat);
        NormalizedClientConfig normalized = normalizeClientConfig(cfg);

        DecodedClaims claims = DecodedClaims.decode(normalizedPat);
        String resolvedWorkstream = trimToNull(request.getWorkstreamId());
        if (resolvedWorkstream == null) {
            resolvedWorkstream = trimToNull(claims.workstreamId());
        }

        String resolvedSource = trimToNull(request.getSourceDid());
        if (resolvedSource == null) {
            resolvedSource = trimToNull(claims.participantDid());
        }

        TransactionRequest.PayloadResolution payloadResolution = request.resolvePayload();
        String payloadHash = payloadResolution.payloadHash();

        TransactionRequest validated = TransactionRequest.builder()
            .correlationId(request.getCorrelationId())
            .workstreamId(resolvedWorkstream)
            .interactionId(request.getInteractionId())
            .timestamp(request.getTimestamp())
            .sourceDid(resolvedSource)
            .targetDid(request.getTargetDid())
            .roiClassification(request.getRoiClassification())
            .roiCost(request.getRoiCost())
            .roiTime(request.getRoiTime())
            .state(request.getState())
            .stateId(request.getStateId())
            .stateLabel(request.getStateLabel())
            .roiBaseCost(request.getRoiBaseCost())
            .roiBaseTime(request.getRoiBaseTime())
            .roiCostSaving(request.getRoiCostSaving())
            .roiTimeSaving(request.getRoiTimeSaving())
            .signature(request.getSignature())
            .label(request.getLabel())
            .tags(request.getTags())
            .payload(request.getPayload())
            .payloadHash(payloadHash)
            .actorExternalId(request.getActorExternalId())
            .actorExternalDisplayName(request.getActorExternalDisplayName())
            .actorExternalSource(request.getActorExternalSource())
            .assigneeExternalId(request.getAssigneeExternalId())
            .assigneeExternalDisplayName(request.getAssigneeExternalDisplayName())
            .assigneeExternalSource(request.getAssigneeExternalSource())
            .customerId(request.getCustomerId())
            .workspaceId(request.getWorkspaceId())
            .createdBy(request.getCreatedBy())
            .build();
        validated.validateForSubmit();

        Instant timestamp = validated.getTimestamp() == null ? Instant.now() : validated.getTimestamp();

        TransactionSubmission submission = new TransactionSubmission(
            validated.getCorrelationId(),
            validated.getWorkstreamId(),
            validated.getInteractionId(),
            DateTimeFormatter.ISO_INSTANT.format(timestamp),
            validated.getSourceDid(),
            validated.getTargetDid(),
            validated.getRoiClassification(),
            validated.getRoiCost(),
            validated.getRoiTime(),
            validated.getState(),
            validated.getStateId(),
            validated.getStateLabel(),
            validated.getRoiBaseCost(),
            validated.getRoiBaseTime(),
            validated.getRoiCostSaving(),
            validated.getRoiTimeSaving(),
            new SignaturePayload(
                validated.getSignature().algorithm(),
                validated.getSignature().value(),
                validated.getSignature().keyId()
            ),
            payloadHash,
            trimToNull(validated.getLabel()),
            sanitizeTags(validated.getTags()),
            trimToNull(validated.getActorExternalId()),
            trimToNull(validated.getActorExternalDisplayName()),
            trimToNull(validated.getActorExternalSource()),
            trimToNull(validated.getAssigneeExternalId()),
            trimToNull(validated.getAssigneeExternalDisplayName()),
            trimToNull(validated.getAssigneeExternalSource()),
            trimToNull(validated.getCustomerId()),
            trimToNull(validated.getWorkspaceId()),
            trimToNull(validated.getCreatedBy())
        );

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(
                normalized.httpClient(),
                "POST",
                normalized.baseUrl() + "/v1/transactions",
                submission,
                normalizedPat
            );
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("perform transaction request interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("perform transaction request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, Transaction.class);
        } catch (IOException ex) {
            throw new OperonException("decode transaction response: " + ex.getMessage(), ex);
        }
    }

    public static SignatureValidationResult validateSignatureWithPAT(
        ClientAPIConfig cfg,
        String pat,
        byte[] payload,
        Map<String, String> headers
    ) throws OperonException {
        String normalizedPat = requirePAT(pat);
        Map<String, String> sanitized = sanitizeOperonHeaders(headers);

        String computedHash = OperonClient.computePayloadHash(payload == null ? new byte[0] : payload);
        String expectedHash = sanitized.get(OperonClient.HEADER_OPERON_PAYLOAD_HASH);
        if (!computedHash.equalsIgnoreCase(expectedHash)) {
            throw new OperonException(
                "payload hash mismatch: expected " + computedHash + ", got " + expectedHash
            );
        }

        NormalizedClientConfig normalized = normalizeClientConfig(cfg);

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(
                normalized.baseUrl() + "/v1/dids/" + urlEncodePath(sanitized.get(OperonClient.HEADER_OPERON_DID))
                    + "/signature/verify"
            ))
            .POST(HttpRequest.BodyPublishers.ofByteArray(payload == null ? new byte[0] : payload))
            .header("Authorization", "Bearer " + normalizedPat);

        for (Map.Entry<String, String> entry : sanitized.entrySet()) {
            requestBuilder.header(entry.getKey(), entry.getValue());
        }

        HttpResponse<java.io.InputStream> response;
        try {
            response = normalized.httpClient().send(requestBuilder.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("perform signature validation request interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("perform signature validation request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, SignatureValidationResult.class);
        } catch (IOException ex) {
            throw new OperonException("decode signature validation response: " + ex.getMessage(), ex);
        }
    }

    public static SignatureValidationResult validateSignatureWithPATFromString(
        ClientAPIConfig cfg,
        String pat,
        String payload,
        Map<String, String> headers
    ) throws OperonException {
        byte[] bytes = payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
        return validateSignatureWithPAT(cfg, pat, bytes, headers);
    }

    public static byte[] decodePayloadBase64(String encoded) throws OperonException {
        String trimmed = trimToNull(encoded);
        if (trimmed == null) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(trimmed);
        } catch (IllegalArgumentException ex) {
            throw new OperonException("payloadData must be valid base64", ex);
        }
    }

    public static Workstream fetchWorkstream(
        WorkstreamDataConfig cfg,
        String pat,
        String... workstreamId
    ) throws OperonException {
        HttpResponse<java.io.InputStream> response = fetchWorkstreamDataset(cfg, pat, "", workstreamId);
        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, Workstream.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream response: " + ex.getMessage(), ex);
        }
    }

    public static WorkstreamInteractionsResponse fetchWorkstreamInteractions(
        WorkstreamDataConfig cfg,
        String pat,
        String... workstreamId
    ) throws OperonException {
        HttpResponse<java.io.InputStream> response = fetchWorkstreamDataset(cfg, pat, "interactions", workstreamId);
        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, WorkstreamInteractionsResponse.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream interactions response: " + ex.getMessage(), ex);
        }
    }

    public static WorkstreamParticipantsResponse fetchWorkstreamParticipants(
        WorkstreamDataConfig cfg,
        String pat,
        String... workstreamId
    ) throws OperonException {
        HttpResponse<java.io.InputStream> response = fetchWorkstreamDataset(cfg, pat, "participants", workstreamId);
        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, WorkstreamParticipantsResponse.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream participants response: " + ex.getMessage(), ex);
        }
    }

    private static HttpResponse<java.io.InputStream> fetchWorkstreamDataset(
        WorkstreamDataConfig cfg,
        String pat,
        String resource,
        String... override
    ) throws OperonException {
        String normalizedPat = requirePAT(pat);
        NormalizedClientConfig normalized = normalizeWorkstreamConfig(cfg);
        String workstreamId = resolveWorkstreamIdFromPAT(normalizedPat, override);

        String endpoint = normalized.baseUrl() + "/v1/workstreams/" + urlEncodePath(workstreamId);
        if (!resource.isBlank()) {
            endpoint = endpoint + "/" + resource;
        }

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(endpoint))
            .GET()
            .header("Authorization", "Bearer " + normalizedPat)
            .header("Accept", "application/json")
            .build();

        try {
            return normalized.httpClient().send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("perform request interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("perform request: " + ex.getMessage(), ex);
        }
    }

    static String resolveWorkstreamIdFromPAT(String pat, String... override) throws OperonException {
        if (override != null) {
            for (String candidate : override) {
                String trimmed = trimToNull(candidate);
                if (trimmed != null) {
                    return trimmed;
                }
            }
        }

        DecodedClaims claims = DecodedClaims.decode(pat);
        String workstream = trimToNull(claims.workstreamId());
        if (workstream != null) {
            return workstream;
        }

        throw new OperonException(
            "workstream ID is required: token not scoped to a workstream and no override provided"
        );
    }

    static Map<String, String> sanitizeOperonHeaders(Map<String, String> headers) throws OperonException {
        if (headers == null) {
            throw new OperonException("operon headers cannot be nil");
        }

        List<String> required = List.of(
            OperonClient.HEADER_OPERON_DID,
            OperonClient.HEADER_OPERON_PAYLOAD_HASH,
            OperonClient.HEADER_OPERON_SIGNATURE,
            OperonClient.HEADER_OPERON_SIGNATURE_KEY,
            OperonClient.HEADER_OPERON_SIGNATURE_ALGO
        );

        Map<String, String> out = new HashMap<>();
        for (String key : required) {
            String value = trimToNull(headers.get(key));
            if (value == null) {
                throw new OperonException("header " + key + " is required");
            }
            out.put(key, value);
        }
        return out;
    }

    private static String requirePAT(String pat) throws OperonException {
        String trimmed = trimToNull(pat);
        if (trimmed == null) {
            throw new OperonException("pat is required");
        }
        return trimmed;
    }

    private static String requirePayloadHash(String payloadHash) throws OperonException {
        String trimmed = trimToNull(payloadHash);
        if (trimmed == null) {
            throw new OperonException("payload hash is required");
        }
        TransactionRequest.validatePayloadHashFormat(trimmed);
        return trimmed;
    }

    private static String requireAlgorithm(String algorithm) throws OperonException {
        String canonical = Config.canonicalSigningAlgorithm(algorithm);
        if (canonical == null) {
            throw new OperonException("unsupported signing algorithm " + algorithm);
        }
        return canonical;
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static List<String> sanitizeTags(Collection<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (String tag : tags) {
            String trimmed = trimToNull(tag);
            if (trimmed != null) {
                out.add(trimmed);
            }
        }
        return out.isEmpty() ? null : out;
    }

    private static String urlEncodePath(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static NormalizedClientConfig normalizeClientConfig(ClientAPIConfig cfg) {
        String base = cfg == null ? null : cfg.baseUrl();
        String normalizedBase = trimToNull(base);
        if (normalizedBase == null) {
            normalizedBase = Config.DEFAULT_BASE_URL;
        }
        if (normalizedBase.endsWith("/")) {
            normalizedBase = normalizedBase.substring(0, normalizedBase.length() - 1);
        }

        HttpClient client = cfg == null ? null : cfg.httpClient();
        if (client == null) {
            client = HttpClient.newBuilder()
                .connectTimeout(Config.DEFAULT_HTTP_TIMEOUT)
                .build();
        }

        return new NormalizedClientConfig(normalizedBase, client);
    }

    private static NormalizedClientConfig normalizeWorkstreamConfig(WorkstreamDataConfig cfg) {
        String base = cfg == null ? null : cfg.baseUrl();
        String normalizedBase = trimToNull(base);
        if (normalizedBase == null) {
            normalizedBase = Config.DEFAULT_BASE_URL;
        }
        if (normalizedBase.endsWith("/")) {
            normalizedBase = normalizedBase.substring(0, normalizedBase.length() - 1);
        }

        HttpClient client = cfg == null ? null : cfg.httpClient();
        if (client == null) {
            client = HttpClient.newBuilder()
                .connectTimeout(Config.DEFAULT_HTTP_TIMEOUT)
                .build();
        }

        return new NormalizedClientConfig(normalizedBase, client);
    }

    private record NormalizedClientConfig(String baseUrl, HttpClient httpClient) {
    }

    private record SignaturePayload(String algorithm, String value, String keyId) {
    }

    private record TransactionSubmission(
        String correlationId,
        String workstreamId,
        String interactionId,
        String timestamp,
        String sourceDid,
        String targetDid,
        String roiClassification,
        Integer roiCost,
        Integer roiTime,
        String state,
        String stateId,
        String stateLabel,
        Integer roiBaseCost,
        Integer roiBaseTime,
        Integer roiCostSaving,
        Integer roiTimeSaving,
        SignaturePayload signature,
        String payloadHash,
        String label,
        List<String> tags,
        String actorExternalId,
        String actorExternalDisplayName,
        String actorExternalSource,
        String assigneeExternalId,
        String assigneeExternalDisplayName,
        String assigneeExternalSource,
        String customerId,
        String workspaceId,
        String createdBy
    ) {
    }
}
