package cloud.operon.sdk;

import java.net.http.HttpClient;

/**
 * Base configuration for PAT-scoped workstream dataset calls.
 */
public record WorkstreamDataConfig(
    String baseUrl,
    HttpClient httpClient
) {
}
