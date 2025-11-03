package operon

import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"
)

func TestConfigValidateFillsDefaults(t *testing.T) {
    cfg := Config{
        ClientID:     "client",
        ClientSecret: "secret",
    }

    require.NoError(t, cfg.Validate())
    require.Equal(t, DefaultBaseURL, cfg.BaseURL)
    require.Equal(t, DefaultTokenURL, cfg.TokenURL)
    require.Equal(t, defaultTokenLeeway, cfg.TokenLeeway)
    require.Equal(t, AlgorithmEd25519, cfg.SigningAlgorithm)
}

func TestConfigValidateRejectsMissingCredentials(t *testing.T) {
    cfg := Config{ClientID: ""}
    err := cfg.Validate()
    require.Error(t, err)

    cfg = Config{ClientID: "client"}
    err = cfg.Validate()
    require.Error(t, err)
}

func TestConfigValidateRespectsCustomValues(t *testing.T) {
    cfg := Config{
        BaseURL:          "https://example/api",
        TokenURL:         "https://example/token",
        ClientID:         "client",
        ClientSecret:     "secret",
        TokenLeeway:      10 * time.Second,
        SigningAlgorithm: AlgorithmES256,
    }

    require.NoError(t, cfg.Validate())
    require.Equal(t, "https://example/api", cfg.BaseURL)
    require.Equal(t, "https://example/token", cfg.TokenURL)
    require.Equal(t, 10*time.Second, cfg.TokenLeeway)
    require.Equal(t, AlgorithmES256, cfg.SigningAlgorithm)
}

func TestConfigValidateRejectsUnsupportedAlgorithm(t *testing.T) {
    cfg := Config{
        ClientID:         "client",
        ClientSecret:     "secret",
        SigningAlgorithm: "unsupported",
    }

    err := cfg.Validate()
    require.Error(t, err)
}
