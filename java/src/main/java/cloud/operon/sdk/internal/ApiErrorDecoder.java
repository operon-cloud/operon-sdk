package cloud.operon.sdk.internal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import cloud.operon.sdk.OperonApiException;

import java.io.IOException;
import java.io.InputStream;

/**
 * Utility for decoding error payloads from Operon services.
 */
public final class ApiErrorDecoder {

    private static final ObjectMapper MAPPER = Json.mapper();

    private ApiErrorDecoder() {
    }

    public static OperonApiException decode(int statusCode, InputStream bodyStream) throws IOException {
        if (bodyStream == null) {
            return new OperonApiException(statusCode, null, null);
        }

        byte[] bytes = bodyStream.readAllBytes();
        if (bytes.length == 0) {
            return new OperonApiException(statusCode, null, null);
        }

        try {
            JsonNode node = MAPPER.readTree(bytes);
            String code = node.hasNonNull("code") ? node.get("code").asText() : null;
            String message = node.hasNonNull("message") ? node.get("message").asText() : null;
            return new OperonApiException(statusCode, code, message);
        } catch (IOException ex) {
            String fallback = new String(bytes);
            return new OperonApiException(statusCode, null, fallback);
        }
    }
}
