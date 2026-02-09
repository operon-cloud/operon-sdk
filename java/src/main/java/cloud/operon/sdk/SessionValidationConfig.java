package cloud.operon.sdk;

import java.net.http.HttpClient;

/**
 * Configuration for PAT session validation calls.
 */
public record SessionValidationConfig(
    String baseUrl,
    HttpClient httpClient
) {
}
