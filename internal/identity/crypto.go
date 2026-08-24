package identity

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

var (
	hex64Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDPattern      = regexp.MustCompile(`^ueg:sha256:[0-9a-f]{64}$`)
	identityIDPattern = regexp.MustCompile(`^ueg:identity:sha256:[0-9a-f]{64}$`)
)

func genesisCore(g *Genesis) map[string]any {
	return map[string]any{
		"advisory_label":            g.AdvisoryLabel,
		"canonicalization":          g.Canonicalization,
		"epoch_zero_key_id":         g.EpochZeroKeyID,
		"epoch_zero_public_key_pem": g.EpochZeroPublicKeyPEM,
		"genesis_policy": map[string]any{
			"concurrent_signing":         g.GenesisPolicy.ConcurrentSigning,
			"one_active_operational_key": g.GenesisPolicy.OneActiveOperationalKey,
			"recovery_root_rotation":     g.GenesisPolicy.RecoveryRootRotation,
		},
		"identity_nonce_b64":           g.IdentityNonceB64,
		"protocol_version":             g.ProtocolVersion,
		"recovery_root_key_id":         g.RecoveryRootKeyID,
		"recovery_root_public_key_pem": g.RecoveryRootPublicKeyPEM,
		"schema":                       g.Schema,
	}
}

func genesisSigned(g *Genesis) map[string]any {
	value := genesisCore(g)
	value["identity_id"] = g.IdentityID
	return value
}

func boundaryMap(boundary LedgerBoundary) map[string]any {
	var receipt any
	if boundary.ReceiptID != nil {
		receipt = *boundary.ReceiptID
	}
	return map[string]any{"receipt_id": receipt, "sequence_no": boundary.SequenceNo}
}

func previousEpochMap(previous *PreviousEpoch) any {
	if previous == nil {
		return nil
	}
	return map[string]any{
		"epoch_number":          previous.EpochNumber,
		"final_ledger_boundary": boundaryMap(previous.FinalLedgerBoundary),
		"operational_key_id":    previous.OperationalKeyID,
		"operational_status":    previous.OperationalStatus,
	}
}

func recordCore(record *LifecycleRecord) map[string]any {
	var previousDigest any
	if record.PreviousRecordDigest != nil {
		previousDigest = *record.PreviousRecordDigest
	}
	var anchor any
	if record.EvidenceAnchorDigest != nil {
		anchor = *record.EvidenceAnchorDigest
	}
	return map[string]any{
		"action":                     record.Action,
		"epoch_number":               record.EpochNumber,
		"evidence_anchor_digest":     anchor,
		"identity_id":                record.IdentityID,
		"ledger_boundary":            boundaryMap(record.LedgerBoundary),
		"lifecycle_sequence":         record.LifecycleSequence,
		"operational_key_id":         record.OperationalKeyID,
		"operational_public_key_pem": record.OperationalPublicKeyPEM,
		"operational_status":         record.OperationalStatus,
		"previous_epoch":             previousEpochMap(record.PreviousEpoch),
		"previous_record_digest":     previousDigest,
		"protocol_version":           record.ProtocolVersion,
		"reason_code":                record.ReasonCode,
		"schema":                     record.Schema,
	}
}

func recordSigned(record *LifecycleRecord) map[string]any {
	value := recordCore(record)
	value["record_digest"] = record.RecordDigest
	return value
}

func anchorCore(anchor *EvidenceAnchor) map[string]any {
	return map[string]any{
		"epoch_number":            anchor.EpochNumber,
		"identity_id":             anchor.IdentityID,
		"ledger_boundary":         boundaryMap(anchor.LedgerBoundary),
		"lifecycle_record_digest": anchor.LifecycleRecordDigest,
		"lifecycle_sequence":      anchor.LifecycleSequence,
		"operational_key_id":      anchor.OperationalKeyID,
		"protocol_version":        anchor.ProtocolVersion,
		"schema":                  anchor.Schema,
	}
}

func anchorSigned(anchor *EvidenceAnchor) map[string]any {
	value := anchorCore(anchor)
	value["anchor_digest"] = anchor.AnchorDigest
	return value
}

func domainPayload(domain string, value map[string]any) ([]byte, error) {
	canonical, err := canon.Canonicalize(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain+"\x00"), canonical...), nil
}

func signDomain(pair *keys.Pair, domain string, value map[string]any) (string, error) {
	payload, err := domainPayload(domain, value)
	if err != nil {
		return "", err
	}
	return pair.SignB64(payload)
}

func verifyDomain(pair *keys.Pair, domain string, value map[string]any, signature string) bool {
	payload, err := domainPayload(domain, value)
	return err == nil && pair.VerifyB64(payload, signature)
}

func computeIdentityID(g *Genesis) (string, error) {
	digest, err := canon.HashJCS(genesisCore(g))
	if err != nil {
		return "", err
	}
	return "ueg:identity:sha256:" + digest, nil
}

func computeRecordDigest(record *LifecycleRecord) (string, error) {
	return canon.HashJCS(recordCore(record))
}

func computeAnchorDigest(anchor *EvidenceAnchor) (string, error) {
	return canon.HashJCS(anchorCore(anchor))
}

func validateBoundary(boundary LedgerBoundary) error {
	if boundary.SequenceNo == -1 {
		if boundary.ReceiptID != nil {
			return fmt.Errorf("empty ledger boundary must have a null receipt_id")
		}
		return nil
	}
	if boundary.SequenceNo < 0 || boundary.ReceiptID == nil || !hex64Pattern.MatchString(*boundary.ReceiptID) {
		return fmt.Errorf("ledger boundary must name a non-negative sequence and 64-hex receipt id")
	}
	return nil
}

func validateReason(reason string) error {
	if strings.TrimSpace(reason) == "" || len(reason) > 128 {
		return fmt.Errorf("reason_code must contain 1 to 128 characters")
	}
	return nil
}

func validateSignatureEncoding(value string) error {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 64 {
		return fmt.Errorf("signature is not one standard-base64 Ed25519 signature")
	}
	return nil
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}
