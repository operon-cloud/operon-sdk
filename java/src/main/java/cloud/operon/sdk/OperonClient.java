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
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * <p>
 * Primary entry point for interacting with Operon Platform services. The client is lightweight and thread-safe:
 * create a single instance per process, call {@link #init()} during startup (or let the first request initialise lazily),
 * and reuse it for the lifetime of the JVM.
 * </p>
 *
 * <h2>Key behaviours</h2>
 * <ul>
 *   <li>Caches OAuth client-credential tokens and refreshes them proactively using the leeway configured in {@link Config}.</li>
 *   <li>Optionally performs <em>self-signing</em> of payload hashes by delegating to Operon’s DID service. Disable this
 *       when you provide your own signatures.</li>
 *   <li>Maintains a local cache of interactions and participants so repeated submissions can resolve channel/DID metadata
 *       without hitting the network.</li>
 *   <li>Is defensive around concurrency: all caches and mutable state are guarded by synchronised blocks to keep behaviour
 *       deterministic even when multiple threads perform first-use initialisation simultaneously.</li>
 * </ul>
 */
public final class OperonClient implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(OperonClient.class.getName());

    private final Config config;
    private final HttpClient httpClient;
    private final String baseUrl;
    private final TokenProvider tokenProvider;
    private final Signer signer;
    private final boolean selfSigning;
    private final Registry registry = new Registry();

    private final Object initLock = new Object();
    private boolean initAttempted;
    private OperonException initFailure;

    private final Object referenceLock = new Object();
    private boolean referenceLoaded;

    private final Object participantLock = new Object();
    private String cachedParticipantDid;
    private String cachedChannelId;
    private String cachedCustomerId;
    private String cachedWorkspaceId;
    private String cachedEmail;
    private String cachedName;
    private List<String> cachedTenantIds = List.of();
    private List<String> cachedRoles = List.of();
    private String cachedMemberId;
    private String cachedSessionId;
    private String cachedOrgId;

    /**
     * Constructs a new Operon client using the supplied configuration.
     *
     * @param config caller-supplied configuration; only {@code clientId} and {@code clientSecret} are mandatory.
     *               The constructor captures a defensive copy with defaults applied, so subsequent mutations to the builder
     *               will not influence this client.
     */
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
    }

    /**
     * Eagerly initialises the client by obtaining an access token.
     *
     * <p>
     * The call is idempotent: multiple threads can safely invoke {@code init()} and only the first execution performs
     * the remote token request. If the initial token exchange fails, the exception is memoised and rethrown for each
     * subsequent attempt so that callers have a consistent failure mode.
     * </p>
     *
     * @throws OperonException when the identity broker cannot issue a token (network failure, invalid credentials, etc.).
     */
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
            } catch (OperonException ex) {
                initFailure = ex;
                throw ex;
            }
        }
    }

    /**
     * Retrieves the cached interaction catalogue, loading it on-demand if required.
     *
     * <p>
     * The first call fetches interactions from the platform and caches them in-memory. Later calls return a defensive copy,
     * allowing application code to iterate freely without worrying about concurrent modifications.
     * </p>
     *
     * @return immutable interaction summaries suitable for UI display or request pre-population.
     * @throws OperonException when the reference data cannot be loaded (for example, due to network failures).
     */
    public List<InteractionSummary> interactions() throws OperonException {
        ensureInitialized();
        ensureReferenceData();
        return registry.interactions().stream()
            .map(item -> new InteractionSummary(
                item.id(),
                item.channelId(),
                item.sourceParticipantId(),
                item.targetParticipantId(),
                item.sourceDid(),
                item.targetDid()
            ))
            .collect(Collectors.toList());
    }

    /**
     * Retrieves the cached participant directory (ID → DID).
     *
     * <p>
     * Participants are loaded alongside interactions because clients often need both to construct valid transactions.
     * The returned list is a snapshot; mutating it will not alter the internal cache.
     * </p>
     *
     * @return participant summaries keyed by Operon participant id.
     * @throws OperonException when the reference data cannot be loaded.
     */
    public List<ParticipantSummary> participants() throws OperonException {
        ensureInitialized();
        ensureReferenceData();
        return registry.participants().stream()
            .map(item -> new ParticipantSummary(item.id(), item.did()))
            .collect(Collectors.toList());
    }

    /**
     * Submits a transaction to the Operon Client API and returns the persisted record.
     *
     * <p>
     * Workflow:
     * </p>
     * <ol>
     *   <li>Ensures the client is initialised (minting a token if required).</li>
     *   <li>Resolves interaction metadata so callers can omit channel/source/target identifiers when convenient.</li>
     *   <li>Encodes payload bytes (or validates the supplied hash) and, when enabled, obtains a signature from the DID service.</li>
     *   <li>Performs the HTTP POST to {@code /v1/transactions} and maps the response body into a {@link Transaction}.</li>
     * </ol>
     *
     * <p>
     * The method performs comprehensive validation before talking to the network. Any {@link OperonApiException} thrown reflects
     * the exact error returned by the Operon backend (status code + error code + message).
     * </p>
     *
     * @param request transaction payload to send. Must include {@code correlationId}, {@code interactionId}, and signature material.
     *                When calling {@link TransactionRequest#payload(byte[])} the SDK derives the hash automatically; if you prefer
     *                to stream large objects externally provide the pre-computed {@link TransactionRequest#payloadHash(String)}.
     * @return the persisted transaction, exactly as recorded by the platform.
     * @throws OperonException when validation fails, when signing cannot be performed, or when the HTTP call encounters an error.
     */
    public Transaction submitTransaction(TransactionRequest request) throws OperonException {
        Objects.requireNonNull(request, "request");
        ensureInitialized();

        Token token = getToken();
        String bearer = token.getAccessToken();

        TransactionContext context = buildContext(request);

        TransactionRequest.PayloadResolution payloadResolution = request.resolvePayload();
        String payloadHash = payloadResolution.payloadHash();
        String payloadData = payloadResolution.payloadData();

        Signature signature = request.getSignature();
        if (signature == null) {
            signature = new Signature(null, null, null);
        }

        if (selfSigning && (signature.value() == null || signature.value().isBlank())) {
            SigningResult result = signer.sign(bearer, payloadHash, config.getSigningAlgorithm());
            signature = new Signature(result.algorithm(), result.value(), result.keyId());
        }

        if (signature.algorithm() == null || signature.algorithm().isBlank()) {
            signature = new Signature(config.getSigningAlgorithm(), signature.value(), signature.keyId());
        }

        if (signature.value() == null || signature.value().isBlank()) {
            throw new OperonException("Signature value is required");
        }

        if (signature.keyId() == null || signature.keyId().isBlank()) {
            String source = Optional.ofNullable(context.sourceDid).orElse(cachedParticipantDid());
            if (source != null && !source.isBlank()) {
                signature = signature.withKeyId(source + Config.DEFAULT_KEY_ID_SUFFIX);
            }
        }

        List<String> sanitizedTags = sanitizeTags(request.getTags());
        String sanitizedLabel = optionalTrim(request.getLabel());
        Instant timestamp = request.getTimestamp() == null ? Instant.now() : request.getTimestamp();

        TransactionRequest validated = TransactionRequest.builder()
            .correlationId(request.getCorrelationId())
            .channelId(context.channelId)
            .interactionId(context.interactionId)
            .timestamp(timestamp)
            .sourceDid(context.sourceDid)
            .targetDid(context.targetDid)
            .signature(signature)
            .label(sanitizedLabel)
            .tags(sanitizedTags)
            .payload(request.getPayload())
            .payloadHash(payloadHash)
            .build();
        validated.validateForSubmit();

        TransactionSubmission submission = new TransactionSubmission(
            validated.getCorrelationId(),
            validated.getChannelId(),
            validated.getInteractionId(),
            DateTimeFormatter.ISO_INSTANT.format(timestamp),
            validated.getSourceDid(),
            validated.getTargetDid(),
            new SignaturePayload(signature.algorithm(), signature.value(), signature.keyId()),
            payloadData,
            payloadHash,
            sanitizedLabel,
            sanitizedTags.isEmpty() ? null : sanitizedTags
        );

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "POST", baseUrl + "/v1/transactions", submission, bearer);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new OperonException("submit transaction interrupted", ex);
            }
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

    /**
     * Closes the client. Currently a no-op because the underlying {@link HttpClient} does not require explicit shutdown,
     * but the hook is retained for future transport strategies (for example, if we introduce Netty-based clients that need disposal).
     */
    @Override
    public void close() {
        // httpClient is managed externally; nothing to close.
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
        LOGGER.info(() -> "[operon-sdk] refreshing reference data cache");
        List<Interaction> interactions = fetchInteractions(bearer);
        List<Participant> participants = fetchParticipants(bearer);

        Map<String, String> participantDidLookup = new HashMap<>();
        for (Participant participant : participants) {
            participantDidLookup.put(participant.id(), participant.did());
        }

        List<Interaction> enriched = new ArrayList<>(interactions.size());
        for (Interaction interaction : interactions) {
            String sourceDid = participantDidLookup.get(interaction.sourceParticipantId());
            String targetDid = participantDidLookup.get(interaction.targetParticipantId());
            Interaction updated = interaction;
            if (sourceDid != null) {
                updated = updated.withSourceDid(sourceDid);
            }
            if (targetDid != null) {
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
        LOGGER.info(() -> "[operon-sdk] requesting /v1/interactions");
        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "GET", baseUrl + "/v1/interactions", null, bearer);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new OperonException("fetch interactions interrupted", ex);
            }
            throw new OperonException("fetch interactions request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream bodyStream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), bodyStream);
            }

            JsonNode root = Json.mapper().readTree(bodyStream);
            JsonNode data = root.path("data");
            List<Interaction> results = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    results.add(new Interaction(
                        node.path("id").asText(),
                        node.path("channelId").asText(),
                        node.path("sourceParticipantId").asText(),
                        node.path("targetParticipantId").asText(),
                        null,
                        null
                    ));
                }
            }
            LOGGER.info(() -> String.format(Locale.ROOT,
                "[operon-sdk] /v1/interactions returned %d records", results.size()));
            return results;
        } catch (IOException ex) {
            throw new OperonException("decode interactions response: " + ex.getMessage(), ex);
        }
    }

    private List<Participant> fetchParticipants(String bearer) throws OperonException {
        LOGGER.info(() -> "[operon-sdk] requesting /v1/participants");
        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "GET", baseUrl + "/v1/participants", null, bearer);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new OperonException("fetch participants interrupted", ex);
            }
            throw new OperonException("fetch participants request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream bodyStream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), bodyStream);
            }

            JsonNode root = Json.mapper().readTree(bodyStream);
            JsonNode data = root.path("data");
            List<Participant> results = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    String id = node.path("id").asText();
                    String did = node.path("did").asText();
                    if (id == null || id.isBlank() || did == null || did.isBlank()) {
                        continue;
                    }
                    results.add(new Participant(id, did));
                }
            }
            LOGGER.info(() -> String.format(Locale.ROOT,
                "[operon-sdk] /v1/participants returned %d records", results.size()));
            return results;
        } catch (IOException ex) {
            throw new OperonException("decode participants response: " + ex.getMessage(), ex);
        }
    }

    private TransactionContext buildContext(TransactionRequest request) throws OperonException {
        String correlationId = optionalTrim(request.getCorrelationId());
        if (correlationId == null) {
            throw new OperonException("CorrelationID is required");
        }

        String channelId = optionalTrim(request.getChannelId());
        String interactionId = optionalTrim(request.getInteractionId());
        String sourceDid = optionalTrim(request.getSourceDid());
        String targetDid = optionalTrim(request.getTargetDid());

        if (interactionId == null || interactionId.isBlank()) {
            if (sourceDid == null || sourceDid.isBlank()) {
                sourceDid = cachedParticipantDid();
            }
            if (channelId == null || channelId.isBlank()) {
                channelId = cachedChannelId();
            }
            return new TransactionContext(channelId, interactionId, sourceDid, targetDid);
        }

        Interaction interaction = registry.interaction(interactionId);
        if (interaction == null) {
            LOGGER.info(() -> String.format(Locale.ROOT,
                "[operon-sdk] interaction %s not found in cache; triggering reload", interactionId));
            reloadReferenceData();
            interaction = registry.interaction(interactionId);
            if (interaction == null) {
                throw new OperonException("interaction " + interactionId + " not found");
            }
        }

        Interaction resolved = interaction;
        LOGGER.info(() -> String.format(Locale.ROOT,
            "[operon-sdk] resolving interaction %s (channel %s, sourceParticipant %s, targetParticipant %s)",
            interactionId,
            resolved.channelId(),
            resolved.sourceParticipantId(),
            resolved.targetParticipantId()));

        if (channelId == null || channelId.isBlank()) {
            channelId = optionalTrim(resolved.channelId());
            if (channelId == null || channelId.isBlank()) {
                channelId = cachedChannelId();
            }
        }

        if (sourceDid == null || sourceDid.isBlank()) {
            sourceDid = optionalTrim(resolved.sourceDid());
            if (sourceDid == null || sourceDid.isBlank()) {
                throw new OperonException("interaction " + interactionId + " missing source DID");
            }
        }

        if (targetDid == null || targetDid.isBlank()) {
            targetDid = optionalTrim(resolved.targetDid());
            if (targetDid == null || targetDid.isBlank()) {
                throw new OperonException("interaction " + interactionId + " missing target DID");
            }
        }

        if (sourceDid == null || sourceDid.isBlank()) {
            sourceDid = cachedParticipantDid();
        }

        return new TransactionContext(channelId, interactionId, sourceDid, targetDid);
    }

    private Token getToken() throws OperonException {
        Token token = tokenProvider.token();
        synchronized (participantLock) {
            cachedParticipantDid = emptyToNull(token.getParticipantDid());
            cachedChannelId = emptyToNull(token.getChannelId());
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

    private String cachedChannelId() {
        synchronized (participantLock) {
            return cachedChannelId;
        }
    }

    private static List<String> sanitizeTags(Collection<String> tags) {
        if (tags == null || tags.isEmpty()) {
            return List.of();
        }
        return tags.stream()
            .filter(Objects::nonNull)
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .distinct()
            .collect(Collectors.toList());
    }

    private static String optionalTrim(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String emptyToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    private record TransactionContext(String channelId, String interactionId, String sourceDid, String targetDid) {
    }

    private record SignaturePayload(String algorithm, String value, String keyId) {
    }

    private record TransactionSubmission(
        String correlationId,
        String channelId,
        String interactionId,
        String timestamp,
        String sourceDid,
        String targetDid,
        SignaturePayload signature,
        String payloadData,
        String payloadHash,
        String label,
        List<String> tags
    ) {
    }
}
