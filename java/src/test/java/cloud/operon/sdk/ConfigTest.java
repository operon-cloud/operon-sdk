package cloud.operon.sdk;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ConfigTest {

    @Test
    void appliesDefaultsForOptionalFields() {
        Config config = Config.builder()
            .clientId("id")
            .clientSecret("secret")
            .build();

        assertEquals(Config.DEFAULT_BASE_URL, config.getBaseUrl());
        assertEquals(Config.DEFAULT_TOKEN_URL, config.getTokenUrl());
        assertEquals(Config.DEFAULT_HTTP_TIMEOUT, config.getHttpTimeout());
        assertEquals(Config.DEFAULT_TOKEN_LEEWAY, config.getTokenLeeway());
        assertEquals(Config.DEFAULT_SIGNING_ALGORITHM, config.getSigningAlgorithm());
        assertNotNull(config.getHttpClient());
        assertEquals(Duration.ZERO, config.getSessionHeartbeatInterval());
        assertEquals(Duration.ZERO, config.getSessionHeartbeatTimeout());
        assertEquals("", config.getSessionHeartbeatUrl());
    }

    @Test
    void rejectsUnsupportedSigningAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> Config.builder()
            .clientId("id")
            .clientSecret("secret")
            .signingAlgorithm("rsa")
            .build());
    }

    @Test
    void rejectsNegativeHeartbeatInterval() {
        assertThrows(IllegalArgumentException.class, () -> Config.builder()
            .clientId("id")
            .clientSecret("secret")
            .sessionHeartbeatInterval(Duration.ofSeconds(-1))
            .build());
    }

    @Test
    void appliesHeartbeatDefaultsWhenEnabled() {
        Config config = Config.builder()
            .clientId("id")
            .clientSecret("secret")
            .baseUrl("https://example.com/client-api/")
            .sessionHeartbeatInterval(Duration.ofSeconds(60))
            .build();

        assertEquals(Duration.ofSeconds(60), config.getSessionHeartbeatInterval());
        assertEquals(Duration.ofSeconds(10), config.getSessionHeartbeatTimeout());
        assertEquals("https://example.com/client-api/v1/session/heartbeat", config.getSessionHeartbeatUrl());
    }
}
