package cloud.operon.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.auth.ClientCredentialsManager;
import cloud.operon.sdk.auth.Token;
import cloud.operon.sdk.auth.TokenProvider;
import cloud.operon.sdk.catalog.Interaction;
import cloud.operon.sdk.catalog.Participant;
import cloud.operon.sdk.catalog.Registry;
import cloud.operon.sdk.internal.ApiErrorDecoder;
import cloud.operon.sdk.internal.HttpUtil;
import cloud.operon.sdk.internal.Json;
import cloud.operon.sdk.signing.DisabledSigner;
import cloud.operon.sdk.signing.SelfSigner;
import cloud.operon.sdk.signing.Signer;
import cloud.operon.sdk.signing.SigningResult;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Primary entry point for interacting with Operon Platform services.
 */
public final class OperonClient implements AutoCloseable {

    public static final String HEADER_OPERON_DID = "X-Operon-DID";
    public static final String HEADER_OPERON_PAYLOAD_HASH = "X-Operon-Payload-Hash";
    public static final String HEADER_OPERON_SIGNATURE = "X-Operon-Signature";
    public static final String HEADER_OPERON_SIGNATURE_KEY = "X-Operon-Signature-KeyId";
    public static final String HEADER_OPERON_SIGNATURE_ALGO = "X-Operon-Signature-Alg";

    private static final Logger LOGGER = Logger.getLogger(OperonClient.class.getName());

    private final Config config;
    private final HttpClient httpClient;
    private final String baseUrl;
    private final TokenProvider tokenProvider;
    private final Signer signer;
    private final boolean selfSigning;
    private final Registry registry = new Registry();
    private final Duration heartbeatInterval;
    private final Duration heartbeatTimeout;
    private final String heartbeatUrl;

    private final Object initLock = new Object();
    private boolean initAttempted;
    private OperonException initFailure;

    private final Object referenceLock = new Object();
    private boolean referenceLoaded;

    private final Object participantLock = new Object();
    private String cachedParticipantDid;
    private String cachedWorkstreamId;
    private String cachedCustomerId;
    private String cachedWorkspaceId;
    private String cachedEmail;
    private String cachedName;
    private List<String> cachedTenantIds = List.of();
    private List<String> cachedRoles = List.of();
    private String cachedMemberId;
    private String cachedSessionId;
    private String cachedOrgId;

    private final Object heartbeatLock = new Object();
    private ScheduledExecutorService heartbeatExecutor;

    public OperonClient(Config config) {
        Objects.requireNonNull(config, "config");
        this.config = config.withDefaults();
        this.baseUrl = this.config.getBaseUrl();
        this.httpClient = this.config.getHttpClient();
        this.tokenProvider = new ClientCredentialsManager(
            this.httpClient,
            this.config.getTokenUrl(),
            this.config.getClientId(),
            this.config.getClientSecret(),
            this.config.getScope(),
            this.config.getAudience(),
            this.config.getTokenLeeway(),
            this.config.getHttpTimeout()
        );
        if (this.config.isDisableSelfSign()) {
            this.signer = new DisabledSigner();
            this.selfSigning = false;
        } else {
            this.signer = new SelfSigner(this.httpClient, this.baseUrl);
            this.selfSigning = true;
        }
        this.heartbeatInterval = this.config.getSessionHeartbeatInterval();
        this.heartbeatTimeout = this.config.getSessionHeartbeatTimeout();
        this.heartbeatUrl = this.config.getSessionHeartbeatUrl();
    }

    public void init() throws OperonException {
        synchronized (initLock) {
            if (initAttempted) {
                if (initFailure != null) {
                    throw initFailure;
                }
                return;
            }
            initAttempted = true;
            try {
                getToken();
                startHeartbeat();
            } catch (OperonException ex) {
                initFailure = ex;
                throw ex;
            }
        }
    }

    public List<InteractionSummary> interactions() throws OperonException {
        ensureInitialized();
        ensureReferenceData();

        List<InteractionSummary> summaries = new ArrayList<>();
        for (Interaction item : registry.interactions()) {
            summaries.add(new InteractionSummary(
                item.id(),
                item.workstreamId(),
                item.workstreamName(),
                item.name(),
                item.description(),
                item.status(),
                item.sourceParticipantId(),
                item.targetParticipantId(),
                item.sourceDid(),
                item.targetDid(),
                item.type(),
                item.actor(),
                item.states(),
                item.roiClassification(),
                item.roiCost(),
                item.roiTime()
            ));
        }
        return summaries;
    }

    public List<ParticipantSummary> participants() throws OperonException {
        ensureInitialized();
        ensureReferenceData();

        List<ParticipantSummary> summaries = new ArrayList<>();
        for (Participant item : registry.participants()) {
            summaries.add(new ParticipantSummary(
                item.id(),
                item.did(),
                item.name(),
                item.status(),
                item.customerId(),
                item.workstreamId(),
                item.workstreamName()
            ));
        }
        return summaries;
    }

    public Transaction submitTransaction(TransactionRequest request) throws OperonException {
        Objects.requireNonNull(request, "request");
        ensureInitialized();

        Token token = getToken();
        String bearer = token.getAccessToken();

        TransactionContext context = buildContext(request);

        TransactionRequest.PayloadResolution payloadResolution = request.resolvePayload();
        String payloadHash = payloadResolution.payloadHash();

        Signature signature = request.getSignature();
        if (signature == null) {
            signature = new Signature(null, null, null);
        }

        if (selfSigning && trimToNull(signature.value()) == null) {
            SigningResult result = signer.sign(bearer, payloadHash, config.getSigningAlgorithm());
            signature = new Signature(result.algorithm(), result.value(), result.keyId());
        }

        if (trimToNull(signature.algorithm()) == null) {
            signature = new Signature(config.getSigningAlgorithm(), signature.value(), signature.keyId());
        }
        if (trimToNull(signature.value()) == null) {
            throw new OperonException("Signature value is required");
        }

        if (trimToNull(signature.keyId()) == null) {
            String source = firstNonEmpty(context.sourceDid(), cachedParticipantDid());
            if (source != null) {
                signature = signature.withKeyId(source + Config.DEFAULT_KEY_ID_SUFFIX);
            }
        }

        List<String> sanitizedTags = sanitizeTags(request.getTags());
        String sanitizedLabel = trimToNull(request.getLabel());
        Instant timestamp = request.getTimestamp() == null ? Instant.now() : request.getTimestamp();

        TransactionRequest validated = TransactionRequest.builder()
            .correlationId(request.getCorrelationId())
            .workstreamId(context.workstreamId())
            .interactionId(context.interactionId())
            .timestamp(timestamp)
            .sourceDid(context.sourceDid())
            .targetDid(context.targetDid())
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
            .signature(signature)
            .label(sanitizedLabel)
            .tags(sanitizedTags)
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
            new SignaturePayload(signature.algorithm(), signature.value(), signature.keyId()),
            payloadHash,
            sanitizedLabel,
            sanitizedTags,
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
            response = HttpUtil.sendJson(httpClient, "POST", baseUrl + "/v1/transactions", submission, bearer);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("submit transaction interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("submit transaction request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream bodyStream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), bodyStream);
            }
            return Json.mapper().readValue(bodyStream, Transaction.class);
        } catch (IOException ex) {
            throw new OperonException("decode transaction response: " + ex.getMessage(), ex);
        }
    }

    public Workstream getWorkstream() throws OperonException {
        return getWorkstream((String) null);
    }

    public Workstream getWorkstream(String workstreamIdOverride) throws OperonException {
        ensureInitialized();
        String bearer = getToken().getAccessToken();
        String workstream = resolveWorkstreamId(workstreamIdOverride);

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(
                httpClient,
                "GET",
                baseUrl + "/v1/workstreams/" + urlEncodePath(workstream),
                null,
                bearer
            );
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("get workstream interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("get workstream request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, Workstream.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream response: " + ex.getMessage(), ex);
        }
    }

    public WorkstreamInteractionsResponse getWorkstreamInteractions(String... workstreamIdOverride)
        throws OperonException {
        ensureInitialized();
        String bearer = getToken().getAccessToken();
        String workstream = resolveWorkstreamId(workstreamIdOverride);

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(
                httpClient,
                "GET",
                baseUrl + "/v1/workstreams/" + urlEncodePath(workstream) + "/interactions",
                null,
                bearer
            );
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("get workstream interactions interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("get workstream interactions request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, WorkstreamInteractionsResponse.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream interactions response: " + ex.getMessage(), ex);
        }
    }

    public WorkstreamParticipantsResponse getWorkstreamParticipants(String... workstreamIdOverride)
        throws OperonException {
        ensureInitialized();
        String bearer = getToken().getAccessToken();
        String workstream = resolveWorkstreamId(workstreamIdOverride);

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(
                httpClient,
                "GET",
                baseUrl + "/v1/workstreams/" + urlEncodePath(workstream) + "/participants",
                null,
                bearer
            );
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("get workstream participants interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("get workstream participants request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }
            return Json.mapper().readValue(stream, WorkstreamParticipantsResponse.class);
        } catch (IOException ex) {
            throw new OperonException("decode workstream participants response: " + ex.getMessage(), ex);
        }
    }

    public Map<String, String> generateSignatureHeaders(byte[] payload, String algorithm) throws OperonException {
        ensureInitialized();

        String selectedAlgorithm = trimToNull(algorithm);
        if (selectedAlgorithm == null) {
            selectedAlgorithm = config.getSigningAlgorithm();
        } else {
            selectedAlgorithm = Config.canonicalSigningAlgorithm(selectedAlgorithm);
            if (selectedAlgorithm == null) {
                throw new OperonException("unsupported signing algorithm " + algorithm);
            }
        }

        String payloadHash = computePayloadHash(payload == null ? new byte[0] : payload);

        Token token = getToken();
        if (!selfSigning) {
            throw new OperonException("automatic signing disabled: enable self signing to generate headers");
        }

        SigningResult result = signer.sign(token.getAccessToken(), payloadHash, selectedAlgorithm);

        String did = trimToNull(cachedParticipantDid());
        if (did == null) {
            throw new OperonException("participant DID unavailable on access token");
        }

        String signatureValue = trimToNull(result.value());
        if (signatureValue == null) {
            throw new OperonException("signature value missing from signing response");
        }

        String keyId = trimToNull(result.keyId());
        if (keyId == null) {
            keyId = did + Config.DEFAULT_KEY_ID_SUFFIX;
        }

        String signatureAlgorithm = trimToNull(result.algorithm());
        if (signatureAlgorithm == null) {
            signatureAlgorithm = selectedAlgorithm;
        }

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HEADER_OPERON_DID, did);
        headers.put(HEADER_OPERON_PAYLOAD_HASH, payloadHash);
        headers.put(HEADER_OPERON_SIGNATURE, signatureValue);
        headers.put(HEADER_OPERON_SIGNATURE_KEY, keyId);
        headers.put(HEADER_OPERON_SIGNATURE_ALGO, signatureAlgorithm);
        return headers;
    }

    public Map<String, String> generateSignatureHeadersFromString(String payload, String algorithm)
        throws OperonException {
        byte[] bytes = payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
        return generateSignatureHeaders(bytes, algorithm);
    }

    public SignatureValidationResult validateSignatureHeaders(byte[] payload, Map<String, String> headers)
        throws OperonException {
        ensureInitialized();
        Map<String, String> sanitized = PatHelpers.sanitizeOperonHeaders(headers);

        String computedHash = computePayloadHash(payload == null ? new byte[0] : payload);
        String expectedHash = sanitized.get(HEADER_OPERON_PAYLOAD_HASH);
        if (!computedHash.equalsIgnoreCase(expectedHash)) {
            throw new OperonException(
                "payload hash mismatch: expected " + computedHash + ", got " + expectedHash
            );
        }

        String bearer = getToken().getAccessToken();

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(
                baseUrl + "/v1/dids/" + urlEncodePath(sanitized.get(HEADER_OPERON_DID)) + "/signature/verify"
            ))
            .POST(HttpRequest.BodyPublishers.ofByteArray(payload == null ? new byte[0] : payload))
            .header("Authorization", "Bearer " + bearer);

        for (Map.Entry<String, String> entry : sanitized.entrySet()) {
            requestBuilder.header(entry.getKey(), entry.getValue());
        }

        HttpResponse<java.io.InputStream> response;
        try {
            response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("POST /v1/dids/{did}/signature/verify interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("POST /v1/dids/{did}/signature/verify: " + ex.getMessage(), ex);
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

    public SignatureValidationResult validateSignatureHeadersFromString(String payload, Map<String, String> headers)
        throws OperonException {
        byte[] bytes = payload == null ? new byte[0] : payload.getBytes(StandardCharsets.UTF_8);
        return validateSignatureHeaders(bytes, headers);
    }

    @Override
    public void close() {
        stopHeartbeat();
    }

    private void ensureInitialized() throws OperonException {
        if (initAttempted && initFailure == null) {
            return;
        }
        init();
    }

    private void ensureReferenceData() throws OperonException {
        if (referenceLoaded) {
            return;
        }

        synchronized (referenceLock) {
            if (referenceLoaded) {
                return;
            }
            Token token = getToken();
            loadReferenceData(token.getAccessToken());
            referenceLoaded = true;
        }
    }

    private void reloadReferenceData() throws OperonException {
        synchronized (referenceLock) {
            Token token = getToken();
            loadReferenceData(token.getAccessToken());
            referenceLoaded = true;
        }
    }

    private void loadReferenceData(String bearer) throws OperonException {
        LOGGER.info("[operon-sdk] refreshing reference data cache");
        List<Interaction> interactions = fetchInteractions(bearer);
        List<Participant> participants = fetchParticipants(bearer);

        Map<String, String> participantDidLookup = new HashMap<>();
        for (Participant participant : participants) {
            participantDidLookup.put(participant.id(), participant.did());
        }

        List<Interaction> enriched = new ArrayList<>(interactions.size());
        for (Interaction interaction : interactions) {
            Interaction updated = interaction;
            String sourceDid = participantDidLookup.get(interaction.sourceParticipantId());
            String targetDid = participantDidLookup.get(interaction.targetParticipantId());
            if (sourceDid != null && !sourceDid.isBlank()) {
                updated = updated.withSourceDid(sourceDid);
            }
            if (targetDid != null && !targetDid.isBlank()) {
                updated = updated.withTargetDid(targetDid);
            }
            enriched.add(updated);
        }

        registry.replaceParticipants(participants);
        registry.replaceInteractions(enriched);
        LOGGER.info(() -> String.format(Locale.ROOT,
            "[operon-sdk] registry populated with %d interactions, %d participants",
            enriched.size(), participants.size()));
    }

    private List<Interaction> fetchInteractions(String bearer) throws OperonException {
        String path = "/v1/interactions";
        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "GET", baseUrl + path, null, bearer);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("fetch interactions interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("fetch interactions request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }

            JsonNode root = Json.mapper().readTree(stream);
            JsonNode data = root.path("data");
            List<Interaction> results = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    results.add(new Interaction(
                        node.path("id").asText(null),
                        firstNonEmpty(node.path("workstreamId").asText(null), node.path("channelId").asText(null)),
                        node.path("workstreamName").asText(null),
                        node.path("name").asText(null),
                        node.path("description").asText(null),
                        node.path("status").asText(null),
                        node.path("sourceParticipantId").asText(null),
                        node.path("targetParticipantId").asText(null),
                        node.path("sourceDid").asText(null),
                        node.path("targetDid").asText(null),
                        node.path("type").asText(null),
                        node.path("actor").asText(null),
                        readStringArray(node.path("states")),
                        node.path("roiClassification").asText(null),
                        node.path("roiCost").isInt() ? node.path("roiCost").asInt() : null,
                        node.path("roiTime").isInt() ? node.path("roiTime").asInt() : null
                    ));
                }
            }
            return results;
        } catch (IOException ex) {
            throw new OperonException("decode interactions response: " + ex.getMessage(), ex);
        }
    }

    private List<Participant> fetchParticipants(String bearer) throws OperonException {
        String path = "/v1/participants";
        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "GET", baseUrl + path, null, bearer);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new OperonException("fetch participants interrupted", ex);
        } catch (IOException ex) {
            throw new OperonException("fetch participants request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream stream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), stream);
            }

            JsonNode root = Json.mapper().readTree(stream);
            JsonNode data = root.path("data");
            List<Participant> results = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    String id = node.path("id").asText(null);
                    String did = node.path("did").asText(null);
                    if (trimToNull(id) == null || trimToNull(did) == null) {
                        continue;
                    }

                    results.add(new Participant(
                        id,
                        did,
                        node.path("name").asText(null),
                        node.path("status").asText(null),
                        node.path("customerId").asText(null),
                        firstNonEmpty(node.path("workstreamId").asText(null), node.path("channelId").asText(null)),
                        node.path("workstreamName").asText(null)
                    ));
                }
            }
            return results;
        } catch (IOException ex) {
            throw new OperonException("decode participants response: " + ex.getMessage(), ex);
        }
    }

    private TransactionContext buildContext(TransactionRequest request) throws OperonException {
        String workstreamId = trimToNull(request.getWorkstreamId());
        String interactionId = trimToNull(request.getInteractionId());
        String sourceDid = trimToNull(request.getSourceDid());
        String targetDid = trimToNull(request.getTargetDid());

        if (interactionId == null) {
            if (sourceDid == null) {
                sourceDid = cachedParticipantDid();
            }
            if (workstreamId == null) {
                workstreamId = cachedWorkstreamId();
            }
            return new TransactionContext(workstreamId, interactionId, sourceDid, targetDid);
        }

        Interaction interaction = registry.interaction(interactionId);
        if (interaction == null) {
            reloadReferenceData();
            interaction = registry.interaction(interactionId);
            if (interaction == null) {
                throw new OperonException("interaction " + interactionId + " not found");
            }
        }

        if (workstreamId == null) {
            workstreamId = firstNonEmpty(trimToNull(interaction.workstreamId()), cachedWorkstreamId());
        }

        if (sourceDid == null) {
            sourceDid = trimToNull(interaction.sourceDid());
            if (sourceDid == null) {
                throw new OperonException("interaction " + interactionId + " missing source DID");
            }
        }

        if (targetDid == null) {
            targetDid = trimToNull(interaction.targetDid());
            if (targetDid == null) {
                throw new OperonException("interaction " + interactionId + " missing target DID");
            }
        }

        if (sourceDid == null) {
            sourceDid = cachedParticipantDid();
        }

        return new TransactionContext(workstreamId, interactionId, sourceDid, targetDid);
    }

    private String resolveWorkstreamId(String... override) throws OperonException {
        if (override != null) {
            for (String value : override) {
                String trimmed = trimToNull(value);
                if (trimmed != null) {
                    return trimmed;
                }
            }
        }

        String cached = trimToNull(cachedWorkstreamId());
        if (cached != null) {
            return cached;
        }

        throw new OperonException(
            "workstream ID is required: token not scoped to a workstream and no override provided"
        );
    }

    private Token getToken() throws OperonException {
        Token token = tokenProvider.token();
        synchronized (participantLock) {
            cachedParticipantDid = emptyToNull(token.getParticipantDid());
            cachedWorkstreamId = emptyToNull(token.getWorkstreamId());
            cachedCustomerId = emptyToNull(token.getCustomerId());
            cachedWorkspaceId = emptyToNull(token.getWorkspaceId());
            cachedEmail = emptyToNull(token.getEmail());
            cachedName = emptyToNull(token.getName());
            cachedTenantIds = token.getTenantIds() == null ? List.of() : List.copyOf(token.getTenantIds());
            cachedRoles = token.getRoles() == null ? List.of() : List.copyOf(token.getRoles());
            cachedMemberId = emptyToNull(token.getMemberId());
            cachedSessionId = emptyToNull(token.getSessionId());
            cachedOrgId = emptyToNull(token.getOrgId());
        }
        return token;
    }

    private String cachedParticipantDid() {
        synchronized (participantLock) {
            return cachedParticipantDid;
        }
    }

    private String cachedWorkstreamId() {
        synchronized (participantLock) {
            return cachedWorkstreamId;
        }
    }

    private static List<String> sanitizeTags(Collection<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return null;
        }

        List<String> results = new ArrayList<>();
        for (String tag : tags) {
            String trimmed = trimToNull(tag);
            if (trimmed != null) {
                results.add(trimmed);
            }
        }
        return results.isEmpty() ? null : results;
    }

    private static List<String> readStringArray(JsonNode node) {
        if (!node.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        node.forEach(item -> {
            if (item.isTextual() && !item.asText().isBlank()) {
                values.add(item.asText());
            }
        });
        return List.copyOf(values);
    }

    private void startHeartbeat() {
        if (trimToNull(heartbeatUrl) == null || heartbeatInterval == null
            || heartbeatInterval.isZero() || heartbeatInterval.isNegative()) {
            return;
        }

        synchronized (heartbeatLock) {
            if (heartbeatExecutor != null) {
                return;
            }
            heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "operon-sdk-heartbeat");
                t.setDaemon(true);
                return t;
            });
            long intervalMillis = Math.max(heartbeatInterval.toMillis(), 1L);
            heartbeatExecutor.scheduleAtFixedRate(this::runHeartbeatSafely, 0, intervalMillis, TimeUnit.MILLISECONDS);
        }
    }

    private void stopHeartbeat() {
        synchronized (heartbeatLock) {
            if (heartbeatExecutor != null) {
                heartbeatExecutor.shutdownNow();
                heartbeatExecutor = null;
            }
        }
    }

    private void runHeartbeatSafely() {
        try {
            performHeartbeat();
        } catch (Exception ex) {
            LOGGER.log(Level.WARNING, "[operon-sdk] session heartbeat error", ex);
        }
    }

    private void performHeartbeat() throws OperonException, IOException, InterruptedException {
        if (trimToNull(heartbeatUrl) == null) {
            return;
        }

        Token token = tokenProvider.token();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(heartbeatUrl))
            .header("Authorization", "Bearer " + token.getAccessToken())
            .timeout(heartbeatTimeout)
            .GET()
            .build();

        HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
        int status = response.statusCode();
        if (status == 401) {
            LOGGER.warning("[operon-sdk] session heartbeat returned 401; forcing token refresh");
            tokenProvider.forceRefresh();
        } else if (status >= 400) {
            LOGGER.warning(() -> "[operon-sdk] session heartbeat unexpected status " + status);
        }
    }

    static String computePayloadHash(byte[] payload) throws OperonException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] sum = digest.digest(payload);
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sum);
        } catch (NoSuchAlgorithmException ex) {
            throw new OperonException("SHA-256 not available", ex);
        }
    }

    private static String urlEncodePath(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String firstNonEmpty(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            String trimmed = trimToNull(value);
            if (trimmed != null) {
                return trimmed;
            }
        }
        return null;
    }

    private static String emptyToNull(String value) {
        return trimToNull(value);
    }

    private record TransactionContext(String workstreamId, String interactionId, String sourceDid, String targetDid) {
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
