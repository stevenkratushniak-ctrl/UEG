package identity

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const (
	markerName       = ".ueg-bplus.json"
	identityDirName  = "identity"
	genesisName      = "genesis.json"
	lifecycleName    = "lifecycle.ndjson"
	pendingName      = ".lifecycle.pending.json"
	migrationPending = ".ueg-bplus-migration.pending.json"
	migrationLock    = ".ueg-bplus-migration.lock"
)

func markerPath(home string) string    { return filepath.Join(home, markerName) }
func identityDir(home string) string   { return filepath.Join(home, identityDirName) }
func genesisPath(home string) string   { return filepath.Join(identityDir(home), genesisName) }
func lifecyclePath(home string) string { return filepath.Join(identityDir(home), lifecycleName) }
func pendingPath(home string) string   { return filepath.Join(identityDir(home), pendingName) }
func epochDir(home string, epoch int) string {
	return filepath.Join(identityDir(home), "epochs", fmt.Sprintf("%06d", epoch))
}
func epochPrivatePath(home string, epoch int) string {
	return filepath.Join(epochDir(home, epoch), "operational_private.pem")
}
func epochPublicPath(home string, epoch int) string {
	return filepath.Join(epochDir(home, epoch), "operational_public.pem")
}
func legacyPublicPath(home string) string  { return filepath.Join(home, "keys", "ed25519_public.pem") }
func legacyPrivatePath(home string) string { return filepath.Join(home, "keys", "ed25519_private.pem") }

// IsBPlus reports whether home carries the explicit B+ format marker. It does
// not create or repair anything.
func IsBPlus(home string) bool {
	info, err := os.Lstat(markerPath(home))
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

// Initialize creates a new B+ identity only after the encrypted recovery
// package and staged evidence home independently verify.
func Initialize(home, recoveryDestination string, passphrase []byte, label string) (_ *State, err error) {
	home, recoveryDestination, err = normalizeInitializationPaths(home, recoveryDestination)
	if err != nil {
		return nil, err
	}
	if pending, pendingErr := InitializationPending(home); pendingErr != nil {
		return nil, pendingErr
	} else if pending {
		state, recoverErr := RecoverPendingInitialization(home, passphrase)
		if recoverErr == nil {
			return state, nil
		}
		if !errors.Is(recoverErr, ErrInitializationRolledBack) {
			return nil, recoverErr
		}
	}
	if err = ensureInitializationDestinationsAbsent(home, recoveryDestination); err != nil {
		return nil, err
	}
	root, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	defer zero(root.Private)
	epochZero, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	genesis, firstRecord, err := NewGenesis(root, epochZero, label, ActionGenesis, LedgerBoundary{SequenceNo: -1})
	if err != nil {
		return nil, err
	}
	packageBytes, err := encryptRecoveryPackage(genesis.IdentityID, root, passphrase)
	if err != nil {
		return nil, err
	}
	defer zero(packageBytes)

	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	stageHome := filepath.Join(filepath.Dir(home), "."+filepath.Base(home)+".ueg-init-"+suffix)
	packageTemp := filepath.Join(filepath.Dir(recoveryDestination), "."+filepath.Base(recoveryDestination)+".ueg-init-"+suffix+".partial")
	txn := &initializationTransaction{
		Schema: initializationPendingSchema, Home: home, IdentityID: genesis.IdentityID,
		StageHome: stageHome, RecoveryTemporary: packageTemp, RecoveryDestination: recoveryDestination,
		RecoverySHA256: canon.SHA256Hex(append(append([]byte{}, packageBytes...), '\n')),
	}
	if err = writeInitializationJournal(txn); err != nil {
		return nil, err
	}
	if err = keys.WriteProtectedFile(packageTemp, append(packageBytes, '\n')); err != nil {
		return nil, fmt.Errorf("identity: write recovery package: %w", err)
	}
	if _, verifyErr := VerifyRecoveryPackage(packageTemp, passphrase, genesis.IdentityID); verifyErr != nil {
		return nil, fmt.Errorf("identity: recovery package self-test failed: %w", verifyErr)
	}
	reachedInitializationBoundary("recovery_package_self_tested")
	if err = writeStagedHome(stageHome, genesis, firstRecord, epochZero); err != nil {
		return nil, err
	}
	reachedInitializationBoundary("authority_staged")
	return completeInitialization(txn, passphrase)
}

func normalizeInitializationPaths(home, recoveryDestination string) (string, string, error) {
	if strings.TrimSpace(home) == "" || strings.TrimSpace(recoveryDestination) == "" {
		return "", "", fmt.Errorf("identity: evidence home and recovery-package destination are required")
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return "", "", err
	}
	recoveryDestination, err = filepath.Abs(recoveryDestination)
	if err != nil {
		return "", "", err
	}
	for _, parent := range []string{filepath.Dir(home), filepath.Dir(recoveryDestination)} {
		info, statErr := os.Stat(parent)
		if statErr != nil || !info.IsDir() {
			return "", "", fmt.Errorf("identity: destination parent is not an existing directory: %s", parent)
		}
	}
	relative, err := filepath.Rel(home, recoveryDestination)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("identity: recovery package must be outside the evidence home")
	}
	return home, recoveryDestination, nil
}

func ensureInitializationDestinationsAbsent(home, recoveryDestination string) error {
	if _, err := os.Lstat(home); err == nil {
		return fmt.Errorf("identity: evidence home already exists: %s", home)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(recoveryDestination); err == nil {
		return fmt.Errorf("identity: recovery-package destination already exists: %s", recoveryDestination)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeStagedHome(stage string, genesis *Genesis, firstRecord *LifecycleRecord, epochZero *keys.Pair) error {
	if err := os.Mkdir(stage, 0o700); err != nil {
		return fmt.Errorf("identity: create staged evidence home: %w", err)
	}
	if err := os.MkdirAll(epochDir(stage, 0), 0o700); err != nil {
		return err
	}
	if err := writeNewFile(filepath.Join(stage, ".ueg.lock"), nil, 0o600); err != nil {
		return fmt.Errorf("identity: create evidence-home lock: %w", err)
	}
	if err := epochZero.WritePair(epochPrivatePath(stage, 0), epochPublicPath(stage, 0)); err != nil {
		return fmt.Errorf("identity: write epoch-zero operational key: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(stage, "keys"), 0o700); err != nil {
		return err
	}
	if err := epochZero.WritePublicFile(legacyPublicPath(stage)); err != nil {
		return fmt.Errorf("identity: write downgrade-refusal public marker: %w", err)
	}
	marker := Marker{Schema: MarkerSchema, ProtocolVersion: ProtocolVersion, IdentityID: genesis.IdentityID}
	if err := writeNewJSON(markerPath(stage), marker, 0o600); err != nil {
		return err
	}
	if err := writeNewJSON(genesisPath(stage), genesis, 0o644); err != nil {
		return err
	}
	line, err := json.Marshal(firstRecord)
	if err != nil {
		return err
	}
	if err := writeNewFile(lifecyclePath(stage), append(line, '\n'), 0o600); err != nil {
		return err
	}
	_, err = LoadSigning(stage)
	return err
}

// LoadPublic verifies a B+ home without loading operational private material.
func LoadPublic(home string) (*State, error) {
	markerRaw, err := readBoundedRegular(markerPath(home), 64*1024)
	if err != nil {
		return nil, fmt.Errorf("identity: read B+ marker: %w", err)
	}
	var marker Marker
	if err := strictjson.UnmarshalExact(markerRaw, &marker); err != nil || marker.Schema != MarkerSchema || marker.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("identity: invalid B+ evidence-home marker")
	}
	genesisRaw, err := readBoundedRegular(genesisPath(home), 1024*1024)
	if err != nil {
		return nil, fmt.Errorf("identity: read genesis: %w", err)
	}
	var genesis Genesis
	if err := strictjson.UnmarshalExact(genesisRaw, &genesis); err != nil {
		return nil, fmt.Errorf("identity: invalid genesis: %w", err)
	}
	records, err := readLifecycle(lifecyclePath(home))
	if err != nil {
		return nil, err
	}
	state, err := DeriveState(home, &genesis, records)
	if err != nil {
		return nil, err
	}
	if marker.IdentityID != genesis.IdentityID {
		return nil, fmt.Errorf("identity: evidence-home marker names a different identity")
	}
	legacyPublic, err := keys.LoadPublicFile(legacyPublicPath(home))
	if err != nil || legacyPublic.ValidateKeyID(genesis.EpochZeroKeyID, false) != nil {
		return nil, fmt.Errorf("identity: downgrade-refusal public marker does not match epoch zero")
	}
	if info, statErr := os.Lstat(pendingPath(home)); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("identity: lifecycle transaction marker is not a regular file")
		}
		state.PendingMutation = true
	} else if !os.IsNotExist(statErr) {
		return nil, statErr
	}
	return state, nil
}

// LoadSigning loads exactly the lifecycle-authorized active private key.
func LoadSigning(home string) (*State, error) {
	state, err := LoadPublic(home)
	if err != nil {
		return nil, err
	}
	if state.PendingMutation {
		return nil, fmt.Errorf("identity: interrupted lifecycle mutation requires transaction recovery")
	}
	active := state.Active()
	if active == nil || active.Status != StatusActive {
		return nil, fmt.Errorf("identity: no ACTIVE operational epoch; signing is not authorized")
	}
	pair, err := keys.LoadExisting(epochPrivatePath(home, active.EpochNumber), epochPublicPath(home, active.EpochNumber))
	if err != nil {
		return nil, fmt.Errorf("identity: load active operational key: %w", err)
	}
	if pair.ValidateKeyID(active.OperationalKeyID, false) != nil {
		return nil, fmt.Errorf("identity: active private key does not match lifecycle authority")
	}
	state.ActivePair = pair
	return state, nil
}

func readLifecycle(path string) ([]*LifecycleRecord, error) {
	raw, err := readBoundedRegular(path, 10*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("identity: read lifecycle: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	records := []*LifecycleRecord{}
	for scanner.Scan() {
		line := scanner.Bytes()
		if strings.TrimSpace(string(line)) == "" {
			continue
		}
		var record LifecycleRecord
		if err := strictjson.UnmarshalExact(line, &record); err != nil {
			return nil, fmt.Errorf("identity: invalid lifecycle record: %w", err)
		}
		records = append(records, &record)
		if len(records) > 10000 {
			return nil, fmt.Errorf("identity: lifecycle exceeds 10000 records")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("identity: lifecycle line exceeds 1 MiB or cannot be read: %w", err)
	}
	return records, nil
}

func marshalLifecycle(records []*LifecycleRecord) ([]byte, error) {
	var builder strings.Builder
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		builder.Write(line)
		builder.WriteByte('\n')
	}
	return []byte(builder.String()), nil
}

func writeNewJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeNewFile(path, append(data, '\n'), mode)
}

func writeNewFile(path string, data []byte, mode os.FileMode) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	remove = false
	return nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return os.ReadFile(path)
}

func randomSuffix() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func renameNew(source, destination string) error {
	return publishNewPath(source, destination)
}

func writeJSONAtomicReplace(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicReplace(path, append(data, '\n'), mode)
}

func writeAtomicReplace(path string, data []byte, mode os.FileMode) error {
	suffix, err := randomSuffix()
	if err != nil {
		return err
	}
	temp := path + "." + suffix + ".tmp"
	if err := writeNewFile(temp, data, mode); err != nil {
		return err
	}
	if err := replacePath(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func copyPrivateBytes(pair *keys.Pair) []byte {
	if pair == nil {
		return nil
	}
	return append([]byte(nil), pair.Private...)
}
