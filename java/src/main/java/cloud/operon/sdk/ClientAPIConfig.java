package cloud.operon.sdk;

import java.net.http.HttpClient;

/**
 * Base configuration for PAT-scoped Client API calls.
 */
public record ClientAPIConfig(
    String baseUrl,
    HttpClient httpClient
) {
}
