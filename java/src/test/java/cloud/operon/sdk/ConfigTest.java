package cloud.operon.sdk;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

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
    }

    @Test
    void rejectsInvalidUrls() {
        Config.Builder builder = Config.builder()
            .baseUrl("invalid")
            .tokenUrl("invalid")
            .clientId("id")
            .clientSecret("secret");

        assertThrows(IllegalArgumentException.class, builder::build);
    }

    @Test
    void honoursCustomTimeouts() {
        Config config = Config.builder()
            .clientId("id")
            .clientSecret("secret")
            .httpTimeout(Duration.ofSeconds(5))
            .tokenLeeway(Duration.ofSeconds(10))
            .build();

        assertEquals(Duration.ofSeconds(5), config.getHttpTimeout());
        assertEquals(Duration.ofSeconds(10), config.getTokenLeeway());
    }
}
