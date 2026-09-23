package browser

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrProfileExactConflict = errors.New("persisted profile conflicts with manager state")

// InsertProfileExactTx inserts one caller-allocated profile without update or
// fallback semantics. The caller owns the transaction and can atomically pair
// this row with its operation journal.
func InsertProfileExactTx(tx *sql.Tx, profile *Profile) error {
	if tx == nil || profile == nil || strings.TrimSpace(profile.ProfileId) == "" || strings.TrimSpace(profile.IncarnationID) == "" || profile.UserDataDir != profile.ProfileId || strings.TrimSpace(profile.CoreId) == "" || profile.DeletedAt != "" || profile.CreatedAt == "" || profile.UpdatedAt == "" {
		return ErrProfileExactConflict
	}
	fingerprintArgs, err := json.Marshal(profile.FingerprintArgs)
	if err != nil {
		return ErrProfileExactConflict
	}
	launchArgs, err := json.Marshal(profile.LaunchArgs)
	if err != nil {
		return ErrProfileExactConflict
	}
	tags, err := json.Marshal(profile.Tags)
	if err != nil {
		return ErrProfileExactConflict
	}
	keywords, err := json.Marshal(profile.Keywords)
	if err != nil {
		return ErrProfileExactConflict
	}
	_, err = tx.Exec(`INSERT INTO browser_profiles
		(profile_id, profile_name, user_data_dir, core_id, fingerprint_args, proxy_id, proxy_config,
		 proxy_bind_source_id, proxy_bind_source_url, proxy_bind_name, proxy_bind_updated_at,
		 memory_limit_mb, launch_args, tags, keywords, group_id, created_at, updated_at,
		 restore_last_session, deleted_at, incarnation_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profile.ProfileId, profile.ProfileName, profile.UserDataDir, profile.CoreId, string(fingerprintArgs), profile.ProxyId, profile.ProxyConfig,
		profile.ProxyBindSourceID, profile.ProxyBindSourceURL, profile.ProxyBindName, profile.ProxyBindUpdatedAt,
		profile.MemoryLimitMB, string(launchArgs), string(tags), string(keywords), profile.GroupId, profile.CreatedAt, profile.UpdatedAt,
		profile.RestoreLastSession, profile.DeletedAt, profile.IncarnationID)
	if err != nil {
		return fmt.Errorf("insert exact browser profile: %w", err)
	}
	return nil
}

// AdoptPersistedProfileExact publishes a Profile that has already committed to
// SQLite into the one resident Manager. It never writes storage and never
// replaces a different in-memory incarnation.
func (m *Manager) AdoptPersistedProfileExact(profile *Profile) error {
	if m == nil || profile == nil || strings.TrimSpace(profile.ProfileId) == "" || strings.TrimSpace(profile.IncarnationID) == "" {
		return ErrProfileExactConflict
	}
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	if m.Profiles == nil {
		m.Profiles = make(map[string]*Profile)
	}
	if current := m.Profiles[profile.ProfileId]; current != nil {
		if current.IncarnationID != profile.IncarnationID || current.ProfileName != profile.ProfileName || current.CoreId != profile.CoreId || current.UserDataDir != profile.UserDataDir || current.DeletedAt != "" {
			return ErrProfileExactConflict
		}
		return nil
	}
	copy := *profile
	copy.FingerprintArgs = append([]string(nil), profile.FingerprintArgs...)
	copy.LaunchArgs = append([]string(nil), profile.LaunchArgs...)
	copy.Tags = append([]string(nil), profile.Tags...)
	copy.Keywords = append([]string(nil), profile.Keywords...)
	m.Profiles[copy.ProfileId] = &copy
	return nil
}
