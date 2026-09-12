package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

const (
	suiteBootstrapDiscoveryPath       = "/.well-known/ant-farm/bootstrap.json"
	maxSuiteBootstrapBodyBytes        = 64 << 10
	maxSuiteBootstrapHeaderBytes      = 32 << 10
	maxSuiteBootstrapCapabilities     = 64
	maxSuiteBootstrapCapabilityBytes  = 80
	maxSuiteBootstrapAllowlist        = 16
	suiteBootstrapTotalTimeout        = 15 * time.Second
	FarmSuiteBootstrapProtocolVersion = "3.0.0"
)

var (
	ErrSuiteBootstrapConfig        = errors.New("suite bootstrap configuration invalid")
	ErrSuiteBootstrapTransport     = errors.New("suite bootstrap transport unavailable")
	ErrSuiteBootstrapTLS           = errors.New("suite bootstrap TLS verification failed")
	ErrSuiteBootstrapRedirect      = errors.New("suite bootstrap redirect rejected")
	ErrSuiteBootstrapHTTPStatus    = errors.New("suite bootstrap HTTP status rejected")
	ErrSuiteBootstrapResponse      = errors.New("suite bootstrap response invalid")
	ErrSuiteBootstrapCompatibility = errors.New("suite bootstrap version incompatible")
)

var suiteBootstrapCapabilityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)

type SuiteBootstrapUpdate struct {
	ManifestURL            string `json:"manifest_url"`
	PublicKeyEd25519Base64 string `json:"public_key_ed25519_b64"`
	Channel                string `json:"channel"`
}

type SuiteBootstrapDiscovery struct {
	SchemaVersion          int                   `json:"schema_version"`
	DeploymentUID          string                `json:"deployment_uid"`
	MinimumSuiteVersion    string                `json:"minimum_suite_version"`
	MinimumProtocolVersion string                `json:"minimum_protocol_version"`
	EnrollmentEndpoint     string                `json:"enrollment_endpoint"`
	ControlEndpoint        string                `json:"control_endpoint"`
	SupportedCapabilities  []string              `json:"supported_capabilities"`
	EndpointAllowlist      []string              `json:"endpoint_allowlist"`
	Update                 *SuiteBootstrapUpdate `json:"update,omitempty"`
}

// FetchSuiteBootstrapDiscovery fetches and validates discovery using the
// compiled Suite and protocol versions and the operating system trust store.
func FetchSuiteBootstrapDiscovery(ctx context.Context, bootstrap BootstrapConfig) (SuiteBootstrapDiscovery, error) {
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		MaxResponseHeaderBytes: maxSuiteBootstrapHeaderBytes,
		ResponseHeaderTimeout:  10 * time.Second,
		DisableCompression:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	return fetchSuiteBootstrapDiscoveryWithClient(ctx, bootstrap, FarmClientVersion, FarmSuiteBootstrapProtocolVersion, client)
}

// fetchSuiteBootstrapDiscoveryWithClient is a test seam for a pinned local CA.
// Production callers cannot provide a transport or disable certificate checks.
func fetchSuiteBootstrapDiscoveryWithClient(ctx context.Context, bootstrap BootstrapConfig, currentSuiteVersion, currentProtocolVersion string, supplied *http.Client) (SuiteBootstrapDiscovery, error) {
	if supplied == nil || bootstrap.Validate() != nil || ctx == nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapConfig
	}
	origin, err := canonicalSuiteBootstrapOrigin(bootstrap.ServerURL, "https")
	if err != nil || !validSuiteReleaseSemver(currentSuiteVersion) || !validSuiteReleaseSemver(currentProtocolVersion) {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapConfig
	}
	ctx, cancel := context.WithTimeout(ctx, suiteBootstrapTotalTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+suiteBootstrapDiscoveryPath, nil)
	if err != nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapConfig
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	client := *supplied
	client.Timeout = suiteBootstrapTotalTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrSuiteBootstrapRedirect }
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, ErrSuiteBootstrapRedirect) {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapRedirect
		}
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) || strings.Contains(strings.ToLower(err.Error()), "x509:") || strings.Contains(strings.ToLower(err.Error()), "tls:") {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapTLS
		}
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapTransport
	}
	defer response.Body.Close()
	if suiteBootstrapHeaderSize(response.Header) > maxSuiteBootstrapHeaderBytes {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if response.StatusCode != http.StatusOK {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapHTTPStatus
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxSuiteBootstrapBodyBytes+1))
	if readErr != nil || len(body) == 0 || len(body) > maxSuiteBootstrapBodyBytes {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	discovery, parseErr := parseSuiteBootstrapDiscovery(body, origin, currentSuiteVersion, currentProtocolVersion)
	if parseErr != nil {
		return SuiteBootstrapDiscovery{}, parseErr
	}
	return discovery, nil
}

func parseSuiteBootstrapDiscovery(raw []byte, requestOrigin, currentSuiteVersion, currentProtocolVersion string) (SuiteBootstrapDiscovery, error) {
	if len(raw) == 0 || len(raw) > maxSuiteBootstrapBodyBytes || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || !exactFarmClientIPCKeysOptional(keys,
		[]string{"schema_version", "deployment_uid", "minimum_suite_version", "minimum_protocol_version", "enrollment_endpoint", "control_endpoint", "supported_capabilities", "endpoint_allowlist"}, []string{"update"}) {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if updateRaw, ok := keys["update"]; ok {
		var updateKeys map[string]json.RawMessage
		if json.Unmarshal(updateRaw, &updateKeys) != nil || !exactFarmClientIPCKeys(updateKeys, []string{"manifest_url", "public_key_ed25519_b64", "channel"}) {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var discovery SuiteBootstrapDiscovery
	if decoder.Decode(&discovery) != nil || requireJSONEOF(decoder) != nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if discovery.SchemaVersion != 3 || uuid.Validate(discovery.DeploymentUID) != nil || uuid.MustParse(discovery.DeploymentUID).String() != discovery.DeploymentUID ||
		!validSuiteReleaseSemver(discovery.MinimumSuiteVersion) || !validSuiteReleaseSemver(discovery.MinimumProtocolVersion) {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if discovery.SupportedCapabilities == nil || len(discovery.SupportedCapabilities) > maxSuiteBootstrapCapabilities || !strictSortedUniqueSuiteBootstrapCapabilities(discovery.SupportedCapabilities) ||
		len(discovery.EndpointAllowlist) == 0 || len(discovery.EndpointAllowlist) > maxSuiteBootstrapAllowlist || !sort.StringsAreSorted(discovery.EndpointAllowlist) {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	allowed := make(map[string]struct{}, len(discovery.EndpointAllowlist))
	for index, rawOrigin := range discovery.EndpointAllowlist {
		canonical, err := canonicalSuiteBootstrapOrigin(rawOrigin, "https")
		if err != nil || canonical != rawOrigin || (index > 0 && discovery.EndpointAllowlist[index-1] == rawOrigin) {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
		}
		allowed[canonical] = struct{}{}
	}
	if _, ok := allowed[requestOrigin]; !ok {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	enrollmentOrigin, err := validateSuiteBootstrapEndpoint(discovery.EnrollmentEndpoint, "https", "/api/farm/v3/bootstrap/enroll")
	if err != nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	controlOrigin, err := validateSuiteBootstrapEndpoint(discovery.ControlEndpoint, "wss", "/control/ws")
	if err != nil {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if _, ok := allowed[enrollmentOrigin]; !ok {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if _, ok := allowed[controlOrigin]; !ok {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
	}
	if discovery.Update != nil {
		updateOrigin, err := validateSuiteBootstrapUpdate(*discovery.Update)
		if err != nil {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
		}
		if _, ok := allowed[updateOrigin]; !ok {
			return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
		}
	}
	if compareSuiteBootstrapSemver(currentSuiteVersion, discovery.MinimumSuiteVersion) < 0 || compareSuiteBootstrapSemver(currentProtocolVersion, discovery.MinimumProtocolVersion) < 0 {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapCompatibility
	}
	return discovery, nil
}

func exactFarmClientIPCKeysOptional(value map[string]json.RawMessage, required, optional []string) bool {
	if len(value) < len(required) || len(value) > len(required)+len(optional) {
		return false
	}
	for _, key := range required {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	allowed := map[string]bool{}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func strictSortedUniqueSuiteBootstrapCapabilities(values []string) bool {
	if !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if len(value) == 0 || len(value) > maxSuiteBootstrapCapabilityBytes || !suiteBootstrapCapabilityPattern.MatchString(value) || (index > 0 && values[index-1] == value) {
			return false
		}
	}
	return true
}

func suiteBootstrapHeaderSize(header http.Header) int {
	total := 0
	for name, values := range header {
		for _, value := range values {
			total += len(name) + len(value) + 4
			if total > maxSuiteBootstrapHeaderBytes {
				return total
			}
		}
	}
	return total
}

func canonicalSuiteBootstrapOrigin(raw, scheme string) (string, error) {
	if raw == "" || containsUnsafeSuiteBootstrapURLRune(raw) {
		return "", ErrSuiteBootstrapResponse
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" {
		return "", ErrSuiteBootstrapResponse
	}
	hostname := strings.ToLower(parsed.Hostname())
	canonicalHost := hostname
	address, addressErr := netip.ParseAddr(hostname)
	if addressErr == nil {
		canonicalHost = address.String()
	} else {
		if strings.Contains(hostname, "%") || looksLikeSuiteBootstrapIPv4(hostname) || !validSuiteBootstrapDNSName(hostname) {
			return "", ErrSuiteBootstrapResponse
		}
	}
	port := parsed.Port()
	if port != "" {
		portNumber, conversionErr := strconv.Atoi(port)
		if conversionErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
			return "", ErrSuiteBootstrapResponse
		}
	}
	if port == "443" {
		port = ""
	}
	authority := canonicalHost
	if addressErr == nil && address.Is6() {
		authority = "[" + canonicalHost + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	canonical := scheme + "://" + authority
	if raw != canonical {
		return "", ErrSuiteBootstrapResponse
	}
	return canonical, nil
}

func looksLikeSuiteBootstrapIPv4(hostname string) bool {
	if !strings.Contains(hostname, ".") {
		return false
	}
	for _, character := range hostname {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validSuiteBootstrapDNSName(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 || strings.HasSuffix(hostname, ".") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validateSuiteBootstrapEndpoint(raw, scheme, exactPath string) (string, error) {
	if containsUnsafeSuiteBootstrapURLRune(raw) {
		return "", ErrSuiteBootstrapResponse
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != exactPath {
		return "", ErrSuiteBootstrapResponse
	}
	origin, err := canonicalSuiteBootstrapOrigin(scheme+"://"+parsed.Host, scheme)
	if err != nil || raw != origin+exactPath {
		return "", ErrSuiteBootstrapResponse
	}
	if scheme == "wss" {
		origin = "https" + strings.TrimPrefix(origin, "wss")
	}
	return origin, nil
}

func validateSuiteBootstrapUpdate(update SuiteBootstrapUpdate) (string, error) {
	if containsUnsafeSuiteBootstrapURLRune(update.ManifestURL) || strings.Contains(update.ManifestURL, "%") {
		return "", ErrSuiteBootstrapResponse
	}
	parsed, err := url.Parse(update.ManifestURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" || parsed.ForceQuery {
		return "", ErrSuiteBootstrapResponse
	}
	origin, err := canonicalSuiteBootstrapOrigin("https://"+parsed.Host, "https")
	expected := origin + parsed.EscapedPath()
	if parsed.RawQuery != "" {
		expected += "?" + parsed.RawQuery
	}
	if err != nil || update.ManifestURL != expected {
		return "", ErrSuiteBootstrapResponse
	}
	key, err := base64.StdEncoding.Strict().DecodeString(update.PublicKeyEd25519Base64)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != update.PublicKeyEd25519Base64 || (update.Channel != "stable" && update.Channel != "beta") {
		return "", ErrSuiteBootstrapResponse
	}
	return origin, nil
}

func containsUnsafeSuiteBootstrapURLRune(value string) bool {
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || unicode.IsSpace(character) {
			return true
		}
	}
	return false
}

func compareSuiteBootstrapSemver(left, right string) int {
	left = strings.SplitN(left, "+", 2)[0]
	right = strings.SplitN(right, "+", 2)[0]
	leftParts := strings.SplitN(left, "-", 2)
	rightParts := strings.SplitN(right, "-", 2)
	for index := 0; index < 3; index++ {
		comparison := compareSuiteBootstrapNumeric(strings.Split(leftParts[0], ".")[index], strings.Split(rightParts[0], ".")[index])
		if comparison != 0 {
			return comparison
		}
	}
	if len(leftParts) == 1 && len(rightParts) == 1 {
		return 0
	}
	if len(leftParts) == 1 {
		return 1
	}
	if len(rightParts) == 1 {
		return -1
	}
	leftPre, rightPre := strings.Split(leftParts[1], "."), strings.Split(rightParts[1], ".")
	for index := 0; index < len(leftPre) && index < len(rightPre); index++ {
		leftNumeric, rightNumeric := allSuiteBootstrapDigits(leftPre[index]), allSuiteBootstrapDigits(rightPre[index])
		if leftNumeric && rightNumeric {
			if comparison := compareSuiteBootstrapNumeric(leftPre[index], rightPre[index]); comparison != 0 {
				return comparison
			}
		} else if leftNumeric != rightNumeric {
			if leftNumeric {
				return -1
			}
			return 1
		} else if leftPre[index] < rightPre[index] {
			return -1
		} else if leftPre[index] > rightPre[index] {
			return 1
		}
	}
	if len(leftPre) < len(rightPre) {
		return -1
	}
	if len(leftPre) > len(rightPre) {
		return 1
	}
	return 0
}

func compareSuiteBootstrapNumeric(left, right string) int {
	left, right = strings.TrimLeft(left, "0"), strings.TrimLeft(right, "0")
	if left == "" {
		left = "0"
	}
	if right == "" {
		right = "0"
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func allSuiteBootstrapDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}
