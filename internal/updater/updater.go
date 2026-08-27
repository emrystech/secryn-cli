package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultLatestReleaseURL = "https://api.github.com/repos/emrystech/secryn-cli/releases/latest"
	defaultReleaseBaseURL   = "https://github.com/emrystech/secryn-cli/releases/download"
	maxDownloadSize         = 100 << 20
)

type Manager struct {
	HTTPClient       *http.Client
	LatestReleaseURL string
	ReleaseBaseURL   string
	GOOS             string
	GOARCH           string
}

type Options struct {
	CurrentVersion string
	TargetVersion  string
	ExecutablePath string
	CheckOnly      bool
	Force          bool
}

type Result struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	Updated         bool   `json:"updated"`
	Path            string `json:"path,omitempty"`
}

func New(httpClient *http.Client) *Manager {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Manager{
		HTTPClient:       httpClient,
		LatestReleaseURL: defaultLatestReleaseURL,
		ReleaseBaseURL:   defaultReleaseBaseURL,
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
	}
}

func (m *Manager) Run(ctx context.Context, opts Options) (Result, error) {
	targetVersion := strings.TrimSpace(opts.TargetVersion)
	if targetVersion == "" {
		var err error
		targetVersion, err = m.latestVersion(ctx)
		if err != nil {
			return Result{}, err
		}
	} else {
		targetVersion = normalizeVersion(targetVersion)
		if err := ValidateVersion(targetVersion); err != nil {
			return Result{}, err
		}
	}

	result := Result{
		CurrentVersion: strings.TrimSpace(opts.CurrentVersion),
		LatestVersion:  targetVersion,
	}
	result.UpdateAvailable = shouldUpdate(result.CurrentVersion, targetVersion, opts.TargetVersion != "")
	if opts.CheckOnly || (!result.UpdateAvailable && !opts.Force) {
		return result, nil
	}

	archiveName, err := m.archiveName()
	if err != nil {
		return Result{}, err
	}
	releaseURL := strings.TrimRight(m.ReleaseBaseURL, "/") + "/" + targetVersion
	checksums, err := m.download(ctx, releaseURL+"/checksums.txt")
	if err != nil {
		return Result{}, fmt.Errorf("download checksums: %w", err)
	}
	expected, err := checksumFor(checksums, archiveName)
	if err != nil {
		return Result{}, err
	}
	archive, err := m.download(ctx, releaseURL+"/"+archiveName)
	if err != nil {
		return Result{}, fmt.Errorf("download %s: %w", archiveName, err)
	}
	actual := sha256.Sum256(archive)
	if hex.EncodeToString(actual[:]) != expected {
		return Result{}, fmt.Errorf("checksum verification failed for %s", archiveName)
	}

	binary, err := extractBinary(archive, m.GOOS)
	if err != nil {
		return Result{}, err
	}
	path, err := replaceExecutable(opts.ExecutablePath, binary)
	if err != nil {
		return Result{}, err
	}
	result.Updated = true
	result.UpdateAvailable = false
	result.Path = path
	return result, nil
}

func (m *Manager) latestVersion(ctx context.Context) (string, error) {
	payload, err := m.download(ctx, m.LatestReleaseURL)
	if err != nil {
		return "", fmt.Errorf("check latest release: %w", err)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(payload, &release); err != nil {
		return "", fmt.Errorf("decode latest release: %w", err)
	}
	release.TagName = normalizeVersion(release.TagName)
	if _, ok := parseVersion(release.TagName); !ok {
		return "", fmt.Errorf("latest release returned invalid version %q", release.TagName)
	}
	return release.TagName, nil
}

func (m *Manager) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "secryn-cli-updater")
	resp, err := m.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxDownloadSize {
		return nil, fmt.Errorf("download exceeds %d bytes", maxDownloadSize)
	}
	return payload, nil
}

func (m *Manager) archiveName() (string, error) {
	if m.GOOS != "linux" && m.GOOS != "darwin" {
		return "", fmt.Errorf("self-update is not supported on %s; use the installer or GitHub Releases", m.GOOS)
	}
	if m.GOARCH != "amd64" && m.GOARCH != "arm64" {
		return "", fmt.Errorf("self-update is not supported on %s/%s", m.GOOS, m.GOARCH)
	}
	return fmt.Sprintf("secryn_%s_%s.tar.gz", m.GOOS, m.GOARCH), nil
}

func checksumFor(payload []byte, archiveName string) (string, error) {
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != archiveName {
			continue
		}
		checksum := strings.ToLower(fields[0])
		if len(checksum) != sha256.Size*2 {
			break
		}
		if _, err := hex.DecodeString(checksum); err != nil {
			break
		}
		return checksum, nil
	}
	return "", fmt.Errorf("checksum entry not found for %s", archiveName)
}

func extractBinary(payload []byte, goos string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("open release archive: %w", err)
	}
	defer gz.Close()
	wanted := "secryn"
	if goos == "windows" {
		wanted += ".exe"
	}
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read release archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != wanted {
			continue
		}
		binary, err := io.ReadAll(io.LimitReader(tr, maxDownloadSize+1))
		if err != nil {
			return nil, fmt.Errorf("extract binary: %w", err)
		}
		if len(binary) > maxDownloadSize {
			return nil, fmt.Errorf("extracted binary exceeds %d bytes", maxDownloadSize)
		}
		return binary, nil
	}
	return nil, fmt.Errorf("secryn binary not found in release archive")
}

func replaceExecutable(path string, binary []byte) (string, error) {
	if strings.TrimSpace(path) == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate current executable: %w", err)
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect current executable: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(resolved), ".secryn-update-*")
	if err != nil {
		return "", fmt.Errorf("create update beside %s: %w", resolved, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write updated binary: %w", err)
	}
	if err := tmp.Chmod(info.Mode().Perm() | 0o111); err != nil {
		tmp.Close()
		return "", fmt.Errorf("make updated binary executable: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("sync updated binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close updated binary: %w", err)
	}
	if err := os.Rename(tmpPath, resolved); err != nil {
		return "", fmt.Errorf("replace %s: %w (check directory permissions)", resolved, err)
	}
	return resolved, nil
}

func normalizeVersion(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw != "" && !strings.HasPrefix(raw, "v") {
		return "v" + raw
	}
	return raw
}

func ValidateVersion(raw string) error {
	if _, ok := parseVersion(normalizeVersion(raw)); !ok {
		return fmt.Errorf("invalid version %q; expected vX.Y.Z", raw)
	}
	return nil
}

type semanticVersion struct {
	major, minor, patch int
	prerelease          string
}

func parseVersion(raw string) (semanticVersion, bool) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	core := raw
	prerelease := ""
	if idx := strings.IndexByte(core, '+'); idx >= 0 {
		core = core[:idx]
	}
	if idx := strings.IndexByte(core, '-'); idx >= 0 {
		prerelease = core[idx+1:]
		if prerelease == "" {
			return semanticVersion{}, false
		}
		core = core[:idx]
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return semanticVersion{}, false
	}
	values := make([]int, 3)
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return semanticVersion{}, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return semanticVersion{}, false
		}
		values[i] = value
	}
	return semanticVersion{major: values[0], minor: values[1], patch: values[2], prerelease: prerelease}, true
}

func shouldUpdate(current, target string, explicit bool) bool {
	if normalizeVersion(current) == normalizeVersion(target) {
		return false
	}
	if explicit {
		return true
	}
	currentVersion, currentOK := parseVersion(current)
	targetVersion, targetOK := parseVersion(target)
	if !currentOK || !targetOK {
		return true
	}
	return compareVersions(currentVersion, targetVersion) < 0
}

func compareVersions(left, right semanticVersion) int {
	leftParts := []int{left.major, left.minor, left.patch}
	rightParts := []int{right.major, right.minor, right.patch}
	for i := range leftParts {
		if leftParts[i] < rightParts[i] {
			return -1
		}
		if leftParts[i] > rightParts[i] {
			return 1
		}
	}
	if left.prerelease == right.prerelease {
		return 0
	}
	if left.prerelease == "" {
		return 1
	}
	if right.prerelease == "" {
		return -1
	}
	return strings.Compare(left.prerelease, right.prerelease)
}
