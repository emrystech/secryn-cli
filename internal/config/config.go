package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigDirName  = "secryn"
	defaultConfigFileName = "config.yaml"
)

// Config stores local CLI configuration.
type Config struct {
	BaseURL              string `yaml:"base_url" json:"base_url"`
	VaultID              string `yaml:"vault_id" json:"vault_id"`
	AccessKey            string `yaml:"access_key" json:"access_key"`
	RecipientID          string `yaml:"recipient_id,omitempty" json:"recipient_id,omitempty"`
	RecipientPrivateKey  string `yaml:"recipient_private_key,omitempty" json:"-"`
	E2EEBootstrapPending bool   `yaml:"e2ee_bootstrap_pending,omitempty" json:"e2ee_bootstrap_pending,omitempty"`
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
	if runtime.GOOS != "windows" && (cfg.AccessKey != "" || cfg.RecipientPrivateKey != "") {
		info, err := os.Stat(path)
		if err != nil {
			return Config{}, fmt.Errorf("inspect config permissions: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return Config{}, fmt.Errorf("config file containing credentials must use permissions 0600")
		}
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
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("secure config permissions: %w", err)
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
	if envCfg.RecipientID != "" {
		merged.RecipientID = envCfg.RecipientID
	}
	if envCfg.RecipientPrivateKey != "" {
		merged.RecipientPrivateKey = envCfg.RecipientPrivateKey
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

// EncryptionMode resolves the CLI's local behavior without probing or falling
// back between protocol versions. A partial E2EE identity is always an error.
func (c Config) EncryptionMode() (string, error) {
	hasRecipientID := strings.TrimSpace(c.RecipientID) != ""
	hasPrivateKey := strings.TrimSpace(c.RecipientPrivateKey) != ""
	if hasRecipientID != hasPrivateKey {
		return "", fmt.Errorf("recipient_id and recipient_private_key must be configured together")
	}
	if c.E2EEBootstrapPending {
		if !hasRecipientID {
			return "", fmt.Errorf("pending E2EE bootstrap requires a complete recipient identity")
		}
		return "e2ee_pending", nil
	}
	if hasRecipientID {
		return "e2ee", nil
	}
	return "legacy", nil
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
