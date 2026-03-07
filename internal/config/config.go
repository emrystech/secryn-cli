package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDirName  = "secryn"
	defaultConfigFileName = "config.yaml"
)

// Config stores local CLI configuration.
type Config struct {
	BaseURL   string `yaml:"base_url" json:"base_url"`
	VaultID   string `yaml:"vault_id" json:"vault_id"`
	AccessKey string `yaml:"access_key" json:"access_key"`
}

// Overrides captures explicit CLI flag overrides.
type Overrides struct {
	BaseURL      string
	VaultID      string
	AccessKey    string
	BaseURLSet   bool
	VaultIDSet   bool
	AccessKeySet bool
}

func DefaultPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config directory: %w", err)
	}
	return filepath.Join(cfgDir, defaultConfigDirName, defaultConfigFileName), nil
}

func ResolvePath(flagValue string, flagChanged bool, envLookup func(string) string) (string, error) {
	if flagChanged {
		return flagValue, nil
	}
	if envLookup != nil {
		if fromEnv := strings.TrimSpace(envLookup("SECRYN_CONFIG")); fromEnv != "" {
			return fromEnv, nil
		}
	}
	return DefaultPath()
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	payload, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func Merge(fileCfg Config, envCfg Config, overrides Overrides) Config {
	merged := fileCfg

	if envCfg.BaseURL != "" {
		merged.BaseURL = envCfg.BaseURL
	}
	if envCfg.VaultID != "" {
		merged.VaultID = envCfg.VaultID
	}
	if envCfg.AccessKey != "" {
		merged.AccessKey = envCfg.AccessKey
	}

	if overrides.BaseURLSet {
		merged.BaseURL = overrides.BaseURL
	}
	if overrides.VaultIDSet {
		merged.VaultID = overrides.VaultID
	}
	if overrides.AccessKeySet {
		merged.AccessKey = overrides.AccessKey
	}

	return merged
}

func NormalizeBaseURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("parse base url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("base url must include scheme and host")
	}
	clean := strings.TrimRight(parsed.String(), "/")
	return clean, nil
}
