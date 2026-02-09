package cloud.operon.sdk;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable configuration container used to bootstrap {@link OperonClient} instances.
 */
public final class Config {

    public static final String DEFAULT_BASE_URL = "https://api.operon.cloud/client-api";
    public static final String DEFAULT_TOKEN_URL = "https://auth.operon.cloud/oauth2/token";
    public static final Duration DEFAULT_HTTP_TIMEOUT = Duration.ofSeconds(30);
    public static final Duration DEFAULT_TOKEN_LEEWAY = Duration.ofSeconds(30);
    public static final String DEFAULT_SIGNING_ALGORITHM = "EdDSA";
    public static final String ALGORITHM_ED25519 = "EdDSA";
    public static final String ALGORITHM_ES256 = "ES256";
    public static final String ALGORITHM_ES256K = "ES256K";
    static final String DEFAULT_KEY_ID_SUFFIX = "#keys-1";
    private static final Duration DEFAULT_HEARTBEAT_TIMEOUT = Duration.ofSeconds(10);

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
    private final Duration sessionHeartbeatInterval;
    private final Duration sessionHeartbeatTimeout;
    private final String sessionHeartbeatUrl;

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
        this.sessionHeartbeatInterval = builder.sessionHeartbeatInterval;
        this.sessionHeartbeatTimeout = builder.sessionHeartbeatTimeout;
        this.sessionHeartbeatUrl = builder.sessionHeartbeatUrl;
    }

    public static Builder builder() {
        return new Builder();
    }

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

        String algorithm = Optional.ofNullable(signingAlgorithm)
            .map(String::trim)
            .filter(s -> !s.isEmpty())
            .orElse(DEFAULT_SIGNING_ALGORITHM);
        algorithm = canonicalSigningAlgorithm(algorithm);
        if (algorithm == null) {
            throw new IllegalArgumentException("unsupported SigningAlgorithm " + signingAlgorithm);
        }

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

        Duration resolvedHeartbeatInterval = Optional.ofNullable(sessionHeartbeatInterval).orElse(Duration.ZERO);
        if (resolvedHeartbeatInterval.isNegative()) {
            throw new IllegalArgumentException("SessionHeartbeatInterval cannot be negative");
        }

        Duration resolvedHeartbeatTimeout;
        String resolvedHeartbeatUrl;
        if (!resolvedHeartbeatInterval.isZero()) {
            resolvedHeartbeatTimeout = Optional.ofNullable(sessionHeartbeatTimeout).orElse(DEFAULT_HEARTBEAT_TIMEOUT);
            if (resolvedHeartbeatTimeout.isNegative() || resolvedHeartbeatTimeout.isZero()) {
                resolvedHeartbeatTimeout = DEFAULT_HEARTBEAT_TIMEOUT;
            }
            resolvedHeartbeatUrl = resolveHeartbeatUrl(Optional.ofNullable(sessionHeartbeatUrl).orElse(""), resolvedBaseUrl);
        } else {
            resolvedHeartbeatTimeout = Duration.ZERO;
            resolvedHeartbeatUrl = "";
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
            .sessionHeartbeatInterval(resolvedHeartbeatInterval)
            .sessionHeartbeatTimeout(resolvedHeartbeatTimeout)
            .sessionHeartbeatUrl(resolvedHeartbeatUrl)
            .buildInternal();
    }

    static String canonicalSigningAlgorithm(String value) {
        String trimmed = Optional.ofNullable(value).map(String::trim).orElse("");
        if (trimmed.isEmpty()) {
            return null;
        }

        for (String candidate : List.of(ALGORITHM_ED25519, ALGORITHM_ES256, ALGORITHM_ES256K)) {
            if (candidate.equalsIgnoreCase(trimmed)) {
                return candidate;
            }
        }
        return null;
    }

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

    private static String resolveHeartbeatUrl(String customUrl, String baseUrl) {
        String trimmed = Optional.ofNullable(customUrl).map(String::trim).orElse("");
        if (!trimmed.isEmpty()) {
            return sanitizeUrl(trimmed);
        }
        return baseUrl + "/v1/session/heartbeat";
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

    public Duration getSessionHeartbeatInterval() {
        return sessionHeartbeatInterval;
    }

    public Duration getSessionHeartbeatTimeout() {
        return sessionHeartbeatTimeout;
    }

    public String getSessionHeartbeatUrl() {
        return sessionHeartbeatUrl;
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
        private Duration sessionHeartbeatInterval;
        private Duration sessionHeartbeatTimeout;
        private String sessionHeartbeatUrl;

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder tokenUrl(String tokenUrl) {
            this.tokenUrl = tokenUrl;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder audience(List<String> audience) {
            this.audience = audience == null ? null : new ArrayList<>(audience);
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public Builder httpTimeout(Duration httpTimeout) {
            this.httpTimeout = httpTimeout;
            return this;
        }

        public Builder tokenLeeway(Duration tokenLeeway) {
            this.tokenLeeway = tokenLeeway;
            return this;
        }

        public Builder disableSelfSign(boolean disableSelfSign) {
            this.disableSelfSign = disableSelfSign;
            return this;
        }

        public Builder signingAlgorithm(String signingAlgorithm) {
            this.signingAlgorithm = signingAlgorithm;
            return this;
        }

        public Builder sessionHeartbeatInterval(Duration sessionHeartbeatInterval) {
            this.sessionHeartbeatInterval = sessionHeartbeatInterval;
            return this;
        }

        public Builder sessionHeartbeatTimeout(Duration sessionHeartbeatTimeout) {
            this.sessionHeartbeatTimeout = sessionHeartbeatTimeout;
            return this;
        }

        public Builder sessionHeartbeatUrl(String sessionHeartbeatUrl) {
            this.sessionHeartbeatUrl = sessionHeartbeatUrl;
            return this;
        }

        public Config build() {
            return new Config(this).withDefaults();
        }

        private Config buildInternal() {
            return new Config(this);
        }
    }
}
