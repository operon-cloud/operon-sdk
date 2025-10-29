package cloud.operon.sdk.signing;

import com.fasterxml.jackson.databind.JsonNode;
import cloud.operon.sdk.OperonApiException;
import cloud.operon.sdk.OperonException;
import cloud.operon.sdk.internal.ApiErrorDecoder;
import cloud.operon.sdk.internal.HttpUtil;
import cloud.operon.sdk.internal.Json;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Signer implementation that delegates to the Operon DID service.
 */
public final class SelfSigner implements Signer {

    private final HttpClient httpClient;
    private final String baseUrl;

    public SelfSigner(HttpClient httpClient, String baseUrl) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
    }

    @Override
    public SigningResult sign(String bearerToken, String payloadHash, String algorithm) throws OperonException {
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("payloadHash", payloadHash);
        requestBody.put("hashAlgorithm", "SHA-256");
        requestBody.put("algorithm", algorithm);

        HttpResponse<java.io.InputStream> response;
        try {
            response = HttpUtil.sendJson(httpClient, "POST", baseUrl + "/v1/dids/self/sign", requestBody, bearerToken);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                throw new OperonException("self sign request interrupted", ex);
            }
            throw new OperonException("self sign request: " + ex.getMessage(), ex);
        }

        try (java.io.InputStream bodyStream = response.body()) {
            if (response.statusCode() >= 400) {
                throw ApiErrorDecoder.decode(response.statusCode(), bodyStream);
            }

            JsonNode node = Json.mapper().readTree(bodyStream);
            JsonNode signature = node.path("signature");
            String algorithmValue = signature.path("algorithm").asText();
            String value = signature.path("value").asText();
            String keyId = signature.path("keyId").asText();

            if (algorithmValue == null || algorithmValue.isBlank() || value == null || value.isBlank()) {
                throw new OperonException("sign response missing signature");
            }
            return new SigningResult(algorithmValue, value, keyId == null || keyId.isBlank() ? null : keyId);
        } catch (IOException ex) {
            throw new OperonException("decode sign response: " + ex.getMessage(), ex);
        }
    }
}
