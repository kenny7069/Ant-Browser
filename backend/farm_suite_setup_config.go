package backend

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// BootstrapConfig contains only information available before enrollment. In
// particular it has no node UID, private key, one-time code or update fields.
type BootstrapConfig struct {
	ServerURL string `json:"server_url" yaml:"server_url"`
	StatePath string `json:"state_path" yaml:"state_path"`
	NodeName  string `json:"node_name" yaml:"node_name"`
}

// Validate rejects insecure or ambiguous origins. TLS trust is verified by the
// transport before discovery; this type cannot grant trust to a certificate.
func (c *BootstrapConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: bootstrap config is nil", ErrFarmClientConfig)
	}
	parsed, err := url.Parse(strings.TrimSpace(c.ServerURL))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return fmt.Errorf("%w: server URL must be an https origin", ErrFarmClientConfig)
	}
	if err := validateFarmClientNodeName(c.NodeName); err != nil {
		return err
	}
	statePath, err := validateAbsoluteFarmClientRoot(c.StatePath, "setup state path")
	if err != nil {
		return err
	}
	if filepath.Base(statePath) == "." {
		return fmt.Errorf("%w: setup state path is invalid", ErrFarmClientRoots)
	}
	c.ServerURL = parsed.String()
	c.StatePath = statePath
	c.NodeName = strings.TrimSpace(c.NodeName)
	return nil
}
