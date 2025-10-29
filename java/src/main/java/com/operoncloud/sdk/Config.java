package com.operoncloud.sdk;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * <p>
 * Immutable configuration container used to bootstrap {@link OperonClient} instances.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 *   <li>Mirror the Go SDK defaults so behaviour stays aligned across languages.</li>
 *   <li>Expose a builder-style API that plays nicely with dependency-injection frameworks.</li>
 *   <li>Validate eagerly so misconfiguration is surfaced when the client is constructed rather than at call time.</li>
 * </ul>
 *
 * <p>
 * Only {@code clientId} and {@code clientSecret} are mandatory; every other field falls back to sensible defaults
 * (hosted production endpoints, 30 second HTTP timeouts, EdDSA signing, etc.).  Keeping the defaults centralised
 * here means the rest of the SDK can assume it is operating with fully-sanitised values and focus on network flows.
 * </p>
 */
public final class Config {

    public static final String DEFAULT_BASE_URL = "https://api.operon.cloud/client-api";
    public static final String DEFAULT_TOKEN_URL = "https://auth.operon.cloud/oauth2/token";
    public static final Duration DEFAULT_HTTP_TIMEOUT = Duration.ofSeconds(30);
    public static final Duration DEFAULT_TOKEN_LEEWAY = Duration.ofSeconds(30);
    public static final String DEFAULT_SIGNING_ALGORITHM = "EdDSA";
    static final String DEFAULT_KEY_ID_SUFFIX = "#keys-1";

    private final String baseUrl;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final List<String> audience;
    private final HttpClient httpClient;
    private final Duration httpTimeout;
    private final Duration tokenLeeway;
    private final boolean disableSelfSign;
    private final String signingAlgorithm;

    private Config(Builder builder) {
        this.baseUrl = builder.baseUrl;
        this.tokenUrl = builder.tokenUrl;
        this.clientId = builder.clientId;
        this.clientSecret = builder.clientSecret;
        this.scope = builder.scope;
        this.audience = builder.audience == null ? null : new ArrayList<>(builder.audience);
        this.httpClient = builder.httpClient;
        this.httpTimeout = builder.httpTimeout;
        this.tokenLeeway = builder.tokenLeeway;
        this.disableSelfSign = builder.disableSelfSign;
        this.signingAlgorithm = builder.signingAlgorithm;
    }

    /**
     * Creates a new {@link Builder}. Builders are single-use: call {@link Builder#build()} once and
     * obtain a fresh builder if you need to produce a variant.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Produces a defensive copy with all defaults applied. The builder defers to this method so that programmatic
     * callers (for example, DI containers) also receive a configuration with sanitised fields.
     */
    public Config withDefaults() {
        String resolvedBaseUrl = sanitizeUrl(Optional.ofNullable(baseUrl).orElse(DEFAULT_BASE_URL));
        String resolvedTokenUrl = sanitizeUrl(Optional.ofNullable(tokenUrl).orElse(DEFAULT_TOKEN_URL));

        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("ClientID is required");
        }
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("ClientSecret is required");
        }

        Duration resolvedTimeout = Optional.ofNullable(httpTimeout).orElse(DEFAULT_HTTP_TIMEOUT);
        if (resolvedTimeout.isNegative() || resolvedTimeout.isZero()) {
            resolvedTimeout = DEFAULT_HTTP_TIMEOUT;
        }

        Duration resolvedLeeway = Optional.ofNullable(tokenLeeway).orElse(DEFAULT_TOKEN_LEEWAY);
        if (resolvedLeeway.isNegative() || resolvedLeeway.isZero()) {
            resolvedLeeway = DEFAULT_TOKEN_LEEWAY;
        }

        String algorithm = Optional.ofNullable(signingAlgorithm).map(String::trim).filter(s -> !s.isEmpty())
            .orElse(DEFAULT_SIGNING_ALGORITHM);

        List<String> resolvedAudience;
        if (audience == null) {
            resolvedAudience = Collections.emptyList();
        } else {
            resolvedAudience = audience.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .distinct()
                .toList();
        }

        HttpClient resolvedClient = httpClient;
        if (resolvedClient == null) {
            resolvedClient = HttpClient.newBuilder()
                .connectTimeout(resolvedTimeout)
                .build();
        }

        return new Builder()
            .baseUrl(resolvedBaseUrl)
            .tokenUrl(resolvedTokenUrl)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .scope(scope)
            .audience(resolvedAudience)
            .httpClient(resolvedClient)
            .httpTimeout(resolvedTimeout)
            .tokenLeeway(resolvedLeeway)
            .disableSelfSign(disableSelfSign)
            .signingAlgorithm(algorithm)
            .buildInternal();
    }

    /**
     * Normalises API and token URLs: trims whitespace, verifies the URI is well-formed, and strips trailing slashes.
     */
    private static String sanitizeUrl(String url) {
        String trimmed = Optional.ofNullable(url).map(String::trim).orElse("");
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("URL must be non-empty");
        }
        try {
            URI uri = new URI(trimmed);
            if (uri.getScheme() == null || uri.getHost() == null) {
                throw new IllegalArgumentException("URL must include scheme and host");
            }
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("Invalid URL: " + trimmed, ex);
        }
        if (trimmed.endsWith("/")) {
            return trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getTokenUrl() {
        return tokenUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getScope() {
        return scope;
    }

    public List<String> getAudience() {
        return Collections.unmodifiableList(audience);
    }

    public HttpClient getHttpClient() {
        return httpClient;
    }

    public Duration getHttpTimeout() {
        return httpTimeout;
    }

    public Duration getTokenLeeway() {
        return tokenLeeway;
    }

    public boolean isDisableSelfSign() {
        return disableSelfSign;
    }

    public String getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public static final class Builder {
        private String baseUrl;
        private String tokenUrl;
        private String clientId;
        private String clientSecret;
        private String scope;
        private List<String> audience;
        private HttpClient httpClient;
        private Duration httpTimeout;
        private Duration tokenLeeway;
        private boolean disableSelfSign;
        private String signingAlgorithm;

        /**
         * Sets the Client API base URL. Leave unset to target {@link #DEFAULT_BASE_URL}. Accepts values with or without a trailing slash.
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        /**
         * Sets the OAuth token issuer URL. Leave unset to target {@link #DEFAULT_TOKEN_URL}.
         */
        public Builder tokenUrl(String tokenUrl) {
            this.tokenUrl = tokenUrl;
            return this;
        }

        /**
         * Sets the issued M2M client identifier. This field is required.
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the companion secret for the configured client id. This field is required.
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Overrides the OAuth scope. The platform auto-assigns defaults, so most consumers can omit this.
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Provides a list of OAuth audience values. Blank entries are removed automatically.
         */
        public Builder audience(List<String> audience) {
            this.audience = audience == null ? null : new ArrayList<>(audience);
            return this;
        }

        /**
         * Injects a pre-configured {@link HttpClient}. Supplying your own client allows fine-grained control over TLS, proxies,
         * observability, and retries. When omitted the SDK builds a client that uses the configured timeout.
         */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /**
         * Overrides the outbound HTTP timeout. Passing {@code null}, zero, or a negative duration reverts to the default.
         */
        public Builder httpTimeout(Duration httpTimeout) {
            this.httpTimeout = httpTimeout;
            return this;
        }

        /**
         * Controls the proactive refresh window used by the token cache. Tokens are renewed when the remaining validity
         * is less than this leeway—useful when intermediaries introduce additional latency.
         */
        public Builder tokenLeeway(Duration tokenLeeway) {
            this.tokenLeeway = tokenLeeway;
            return this;
        }

        /**
         * Disables automatic signature minting from the Operon DID service. Set this when your integration supplies
         * pre-computed signatures and only needs the SDK for transport concerns.
         */
        public Builder disableSelfSign(boolean disableSelfSign) {
            this.disableSelfSign = disableSelfSign;
            return this;
        }

        /**
         * Overrides the signing algorithm used when self-signing is enabled. Defaults to {@link #DEFAULT_SIGNING_ALGORITHM}.
         */
        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        /**
         * Finalises the configuration, applying defaults and validations. Subsequent builder mutations do not affect
         * previously constructed {@link Config} instances.
         */
        public Config build() {
            return new Config(this).withDefaults();
        }

        private Config buildInternal() {
            return new Config(this);
        }
    }
}
