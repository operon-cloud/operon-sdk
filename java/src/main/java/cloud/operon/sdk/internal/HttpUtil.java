package cloud.operon.sdk.internal;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Helper methods for issuing HTTP requests with JSON payloads.
 */
public final class HttpUtil {

    private HttpUtil() {
    }

    public static HttpResponse<java.io.InputStream> sendJson(HttpClient client, String method, String url, Object payload, String bearerToken)
        throws IOException, InterruptedException {

        HttpRequest.Builder builder = HttpRequest.newBuilder()
            .uri(URI.create(url));

        if (payload == null) {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            byte[] body = Json.mapper().writeValueAsBytes(payload);
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
            builder.header("Content-Type", "application/json");
        }

        if (bearerToken != null && !bearerToken.isBlank()) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }

        builder.header("Accept", "application/json");

        HttpRequest request = builder.build();
        return client.send(request, HttpResponse.BodyHandlers.ofInputStream());
    }
}
