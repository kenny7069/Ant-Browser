package backend

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	appbrowser "ant-chrome/backend/internal/browser"

	"github.com/google/uuid"
)

const (
	farmProfileCreateCommand          = "profile_create_v1"
	FarmClientCapabilityProfileCreate = "profile.create.v1"
)

func FarmClientProfileCreateCapabilities() []string {
	return []string{FarmClientCapabilityProfileCreate}
}

var (
	ErrFarmProfileCreateConflict = errors.New("farm profile create idempotency conflict")
	farmProfileCoreRefPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	farmProfileDigestPattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type FarmProfileCreateRequest struct {
	OperationUID  string `json:"operation_uid"`
	RequestUID    string `json:"request_uid"`
	PayloadDigest string `json:"payload_digest"`
	DisplayName   string `json:"display_name"`
	CoreRef       string `json:"core_ref"`
}

type FarmProfileCreateResult struct {
	OperationUID       string `json:"operation_uid"`
	RequestUID         string `json:"request_uid"`
	Status             string `json:"status"`
	AntProfileID       string `json:"ant_profile_id"`
	DisplayName        string `json:"display_name"`
	ProfileIncarnation string `json:"profile_incarnation"`
	CoreRef            string `json:"core_ref"`
}

type farmProfileCreatePayload struct {
	DisplayName string `json:"display_name"`
	CoreRef     string `json:"core_ref"`
}

type farmProfileCreateRecord struct {
	OperationUID         string
	RequestUID           string
	Status               string
	ProfileID            string
	DisplayName          string
	ProfileIncarnationID string
	CoreRef              string
	Command              string
	NodeUID              string
	PayloadDigest        string
}

func NewFarmProfileCreateRequest(operationUID, requestUID, displayName, coreRef string) (FarmProfileCreateRequest, error) {
	digest, err := FarmProfileCreatePayloadDigest(displayName, coreRef)
	if err != nil {
		return FarmProfileCreateRequest{}, err
	}
	request := FarmProfileCreateRequest{OperationUID: operationUID, RequestUID: requestUID, PayloadDigest: digest, DisplayName: displayName, CoreRef: coreRef}
	if !validFarmProfileCreateRequest(request) {
		return FarmProfileCreateRequest{}, ErrFarmClientIPCInvalid
	}
	return request, nil
}

func FarmProfileCreatePayloadDigest(displayName, coreRef string) (string, error) {
	if !validFarmProfileCreateFields(displayName, coreRef) {
		return "", ErrFarmClientIPCInvalid
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(farmProfileCreatePayload{DisplayName: displayName, CoreRef: coreRef}); err != nil {
		return "", ErrFarmClientIPCInvalid
	}
	raw := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func validFarmProfileCreateRequest(request FarmProfileCreateRequest) bool {
	if !canonicalFarmProfileUUID(request.OperationUID) || !canonicalFarmProfileUUID(request.RequestUID) || !farmProfileDigestPattern.MatchString(request.PayloadDigest) || !validFarmProfileCreateFields(request.DisplayName, request.CoreRef) {
		return false
	}
	digest, err := FarmProfileCreatePayloadDigest(request.DisplayName, request.CoreRef)
	return err == nil && digest == request.PayloadDigest
}

func validFarmProfileCreateResult(result FarmProfileCreateResult) bool {
	return canonicalFarmProfileUUID(result.OperationUID) && canonicalFarmProfileUUID(result.RequestUID) && result.Status == "COMPLETED" && canonicalFarmProfileUUID(result.AntProfileID) && farmProfileDigestPattern.MatchString(result.ProfileIncarnation) && validFarmProfileCreateFields(result.DisplayName, result.CoreRef)
}

func validFarmProfileCreateFields(displayName, coreRef string) bool {
	return strings.TrimSpace(displayName) == displayName && displayName != "" && utf8.ValidString(displayName) && utf8.RuneCountInString(displayName) <= 100 && farmProfileCoreRefPattern.MatchString(coreRef)
}

func canonicalFarmProfileUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func deterministicFarmProfileUUID(domain, nodeUID, requestUID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(domain+"\x00"+nodeUID+"\x00"+requestUID)).String()
}

func (management *farmProfileManagement) Create(request FarmProfileCreateRequest) (FarmProfileCreateResult, error) {
	if management == nil || management.host == nil || management.host.db == nil || management.host.manager == nil || !validFarmProfileCreateRequest(request) {
		return FarmProfileCreateResult{}, ErrFarmClientIPCInvalid
	}
	management.createMu.Lock()
	defer management.createMu.Unlock()

	nodeUID := management.host.identity.NodeUID
	if !farmClientNodeUIDPattern.MatchString(nodeUID) {
		return FarmProfileCreateResult{}, ErrFarmClientIPCInvalid
	}
	profileID := deterministicFarmProfileUUID("ant-farm-profile-v1", nodeUID, request.RequestUID)
	incarnation := deterministicFarmProfileUUID("ant-farm-profile-incarnation-v1", nodeUID, request.RequestUID)
	result, err := transactFarmProfileCreate(management.host.db, nodeUID, request, profileID, incarnation)
	if err != nil {
		return FarmProfileCreateResult{}, err
	}
	profile, err := appbrowser.NewSQLiteProfileDAO(management.host.db).GetById(result.AntProfileID)
	if err != nil || profile.IncarnationID != incarnation || profile.ProfileName != result.DisplayName || profile.CoreId != result.CoreRef || profile.UserDataDir != result.AntProfileID || profile.DeletedAt != "" {
		return FarmProfileCreateResult{}, ErrFarmProfileCreateConflict
	}
	if err := management.host.manager.AdoptPersistedProfileExact(profile); err != nil {
		return FarmProfileCreateResult{}, ErrFarmProfileCreateConflict
	}
	return result, nil
}

func transactFarmProfileCreate(db *sql.DB, nodeUID string, request FarmProfileCreateRequest, profileID, incarnation string) (FarmProfileCreateResult, error) {
	tx, err := db.Begin()
	if err != nil {
		return FarmProfileCreateResult{}, fmt.Errorf("profile create transaction: %w", err)
	}
	defer tx.Rollback()

	records, err := findFarmProfileCreateRecords(tx, request.OperationUID, request.RequestUID)
	if err != nil {
		return FarmProfileCreateResult{}, err
	}
	if len(records) != 0 {
		if len(records) != 1 || !farmProfileCreateRecordMatches(records[0], nodeUID, request, profileID, incarnation) || !farmProfileRowMatches(tx, records[0]) {
			return FarmProfileCreateResult{}, ErrFarmProfileCreateConflict
		}
		if err := tx.Commit(); err != nil {
			return FarmProfileCreateResult{}, fmt.Errorf("profile create replay commit: %w", err)
		}
		return records[0].result()
	}

	if !farmProfileCreateCoreRefIsCanonical(tx, request.CoreRef) {
		return FarmProfileCreateResult{}, ErrFarmClientIPCInvalid
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO farm_profile_create_operations
		(operation_uid, request_uid, command, node_uid, payload_digest, profile_id, profile_incarnation, display_name, core_ref, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?, ?)`, request.OperationUID, request.RequestUID, farmProfileCreateCommand, nodeUID, request.PayloadDigest, profileID, incarnation, request.DisplayName, request.CoreRef, now, now); err != nil {
		return FarmProfileCreateResult{}, classifyFarmProfileCreateInsertError(err)
	}
	profile := &appbrowser.Profile{ProfileId: profileID, IncarnationID: incarnation, ProfileName: request.DisplayName, UserDataDir: profileID, CoreId: request.CoreRef, CreatedAt: now, UpdatedAt: now}
	if err := appbrowser.InsertProfileExactTx(tx, profile); err != nil {
		return FarmProfileCreateResult{}, classifyFarmProfileCreateInsertError(err)
	}
	if err := tx.Commit(); err != nil {
		return FarmProfileCreateResult{}, fmt.Errorf("profile create commit: %w", err)
	}
	safeIncarnation, err := farmClientProfileIncarnation(profileID, incarnation)
	if err != nil {
		return FarmProfileCreateResult{}, ErrFarmProfileCreateConflict
	}
	return FarmProfileCreateResult{OperationUID: request.OperationUID, RequestUID: request.RequestUID, Status: "COMPLETED", AntProfileID: profileID, DisplayName: request.DisplayName, ProfileIncarnation: safeIncarnation, CoreRef: request.CoreRef}, nil
}

func farmProfileCreateCoreRefIsCanonical(tx *sql.Tx, coreRef string) bool {
	if tx == nil || strings.EqualFold(coreRef, "default") {
		return false
	}
	rows, err := tx.Query(`SELECT core_id FROM browser_cores WHERE core_id = ? COLLATE NOCASE`, coreRef)
	if err != nil {
		return false
	}
	defer rows.Close()
	count := 0
	canonical := ""
	for rows.Next() {
		count++
		if rows.Scan(&canonical) != nil {
			return false
		}
	}
	return rows.Err() == nil && count == 1 && canonical == coreRef
}

func findFarmProfileCreateRecords(tx *sql.Tx, operationUID, requestUID string) ([]farmProfileCreateRecord, error) {
	rows, err := tx.Query(`SELECT operation_uid, request_uid, status, profile_id, display_name, profile_incarnation, core_ref, command, node_uid, payload_digest
		FROM farm_profile_create_operations WHERE operation_uid = ? OR request_uid = ?`, operationUID, requestUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []farmProfileCreateRecord
	for rows.Next() {
		var record farmProfileCreateRecord
		if err := rows.Scan(&record.OperationUID, &record.RequestUID, &record.Status, &record.ProfileID, &record.DisplayName, &record.ProfileIncarnationID, &record.CoreRef, &record.Command, &record.NodeUID, &record.PayloadDigest); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func farmProfileCreateRecordMatches(record farmProfileCreateRecord, nodeUID string, request FarmProfileCreateRequest, profileID, incarnation string) bool {
	return record.OperationUID == request.OperationUID && record.RequestUID == request.RequestUID && record.Command == farmProfileCreateCommand && record.NodeUID == nodeUID && record.PayloadDigest == request.PayloadDigest && record.Status == "COMPLETED" && record.ProfileID == profileID && record.ProfileIncarnationID == incarnation && record.DisplayName == request.DisplayName && record.CoreRef == request.CoreRef
}

func farmProfileRowMatches(tx *sql.Tx, record farmProfileCreateRecord) bool {
	var id, name, dataDir, core, deleted, incarnation string
	err := tx.QueryRow(`SELECT profile_id, profile_name, user_data_dir, core_id, COALESCE(deleted_at, ''), incarnation_id FROM browser_profiles WHERE profile_id = ?`, record.ProfileID).Scan(&id, &name, &dataDir, &core, &deleted, &incarnation)
	return err == nil && id == record.ProfileID && name == record.DisplayName && dataDir == record.ProfileID && core == record.CoreRef && deleted == "" && incarnation == record.ProfileIncarnationID
}

func (record farmProfileCreateRecord) result() (FarmProfileCreateResult, error) {
	safeIncarnation, err := farmClientProfileIncarnation(record.ProfileID, record.ProfileIncarnationID)
	if err != nil {
		return FarmProfileCreateResult{}, ErrFarmProfileCreateConflict
	}
	return FarmProfileCreateResult{OperationUID: record.OperationUID, RequestUID: record.RequestUID, Status: record.Status, AntProfileID: record.ProfileID, DisplayName: record.DisplayName, ProfileIncarnation: safeIncarnation, CoreRef: record.CoreRef}, nil
}

func classifyFarmProfileCreateInsertError(err error) error {
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "constraint") {
		return ErrFarmProfileCreateConflict
	}
	return err
}
