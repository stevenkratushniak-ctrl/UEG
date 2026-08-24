package ledger

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const (
	pendingName = ".ueg.pending.json"
	pendingTemp = ".ueg.pending.tmp"
)

type pendingPair struct {
	ReceiptLine  string `json:"receipt_line"`
	PetitionLine string `json:"petition_line"`
}

func pendingExists(home string) (bool, error) {
	_, err := os.Stat(filepath.Join(home, pendingName))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// RecoveryPending reports whether a paired evidence write was interrupted.
func RecoveryPending(home string) (bool, error) {
	return pendingExists(home)
}

func beginPending(home string, receiptLine, petitionLine []byte) error {
	pendingPath := filepath.Join(home, pendingName)
	tempPath := filepath.Join(home, pendingTemp)
	if exists, err := pendingExists(home); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("ledger: an interrupted evidence write requires recovery")
	}
	_ = os.Remove(tempPath)
	data, err := marshalSorted(pendingPair{
		ReceiptLine:  string(receiptLine),
		PetitionLine: string(petitionLine),
	})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := replaceRecoveryPath(tempPath, pendingPath); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func clearPending(home string) error {
	if err := removeRecoveryPath(filepath.Join(home, pendingName)); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(filepath.Join(home, pendingTemp))
	return nil
}

func recoverPendingFiles(l *Ledger, pair *keys.Pair) error {
	pendingPath := filepath.Join(l.Home, pendingName)
	raw, err := os.ReadFile(pendingPath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = os.Remove(filepath.Join(l.Home, pendingTemp))
			return nil
		}
		return err
	}
	var pending pendingPair
	if err := strictjson.Unmarshal(raw, &pending); err != nil {
		return fmt.Errorf("ledger: invalid recovery record: %w", err)
	}
	receiptLine := []byte(pending.ReceiptLine)
	petitionLine := []byte(pending.PetitionLine)
	receipt, err := ParseReceiptStrict(receiptLine)
	if err != nil {
		return fmt.Errorf("ledger: recovery receipt is invalid: %w", err)
	}
	computed, err := receipt.ComputeID()
	if err != nil || computed != receipt.ReceiptID {
		return fmt.Errorf("ledger: recovery receipt id does not match its contents")
	}
	if err := pair.ValidateKeyID(receipt.SigningKeyID, true); err != nil || !pair.VerifyB64([]byte(receipt.ReceiptID), receipt.SignatureB64) {
		return fmt.Errorf("ledger: recovery receipt signature is invalid")
	}
	var petition Petition
	if err := strictjson.Unmarshal(petitionLine, &petition); err != nil {
		return fmt.Errorf("ledger: recovery petition is invalid: %w", err)
	}
	if id, _ := petition["receipt_id"].(string); id != receipt.ReceiptID {
		return fmt.Errorf("ledger: recovery petition names a different receipt")
	}
	if bind := VerifyPetitions([]*Receipt{receipt}, []Petition{petition}); !bind.OK {
		return fmt.Errorf("ledger: recovery petition does not bind to its receipt: %s", strings.Join(bind.Findings, "; "))
	}

	receiptPlan, receiptsAfter, err := planReceiptRecovery(l.ReceiptsPath, receiptLine, receipt)
	if err != nil {
		return err
	}
	petitionPlan, petitionsAfter, err := planPetitionRecovery(l.PetitionsPath, petitionLine, receipt.ReceiptID)
	if err != nil {
		return err
	}
	trust := map[string]*keys.Pair{receipt.SigningKeyID: pair}
	if legacy, legacyErr := pair.LegacyKeyID(); legacyErr == nil {
		trust[legacy] = pair
	}
	if chain := Verify(receiptsAfter, trust); !chain.OK {
		return fmt.Errorf("ledger: planned recovery receipt chain is invalid: %s", strings.Join(chain.Findings, "; "))
	}
	if bind := VerifyPetitions(receiptsAfter, petitionsAfter); !bind.OK {
		return fmt.Errorf("ledger: planned recovery request binding is invalid: %s", strings.Join(bind.Findings, "; "))
	}
	if err := applyRecoveryPlan(receiptPlan); err != nil {
		return err
	}
	if err := applyRecoveryPlan(petitionPlan); err != nil {
		return err
	}
	return clearPending(l.Home)
}

type recoveryFilePlan struct {
	path          string
	existed       bool
	before, after []byte
}

func planReceiptRecovery(path string, pendingLine []byte, pendingReceipt *Receipt) (recoveryFilePlan, []*Receipt, error) {
	plan, normalized, err := readRecoveryData(path, pendingLine)
	if err != nil {
		return plan, nil, err
	}
	receipts, present, err := parseRecoveryReceipts(normalized, pendingLine, pendingReceipt.ReceiptID)
	if err != nil {
		return plan, nil, err
	}
	if !present {
		expectedSequence := 0
		var expectedPrevious *string
		if len(receipts) > 0 {
			last := receipts[len(receipts)-1]
			expectedSequence = last.SequenceNo + 1
			id := last.ReceiptID
			expectedPrevious = &id
		}
		if pendingReceipt.SequenceNo != expectedSequence || !sameStringPointer(pendingReceipt.PrevReceiptID, expectedPrevious) {
			return plan, nil, fmt.Errorf("ledger: recovery receipt does not continue the current chain")
		}
		normalized = appendRecord(normalized, pendingLine)
	}
	plan.after = normalized
	receipts, _, err = parseRecoveryReceipts(plan.after, pendingLine, pendingReceipt.ReceiptID)
	if err != nil {
		return plan, nil, err
	}
	return plan, receipts, nil
}

func parseRecoveryReceipts(data, pendingLine []byte, pendingID string) ([]*Receipt, bool, error) {
	var receipts []*Receipt
	present := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		receipt, err := ParseReceiptStrict(line)
		if err != nil {
			return nil, false, fmt.Errorf("ledger: corrupt receipt during recovery: %w", err)
		}
		if receipt.ReceiptID == pendingID {
			if !bytes.Equal(line, pendingLine) {
				return nil, false, fmt.Errorf("ledger: recovery receipt id collides with different bytes")
			}
			present = true
		}
		receipts = append(receipts, receipt)
	}
	return receipts, present, nil
}

func planPetitionRecovery(path string, pendingLine []byte, receiptID string) (recoveryFilePlan, []Petition, error) {
	plan, normalized, err := readRecoveryData(path, pendingLine)
	if err != nil {
		return plan, nil, err
	}
	petitions, present, err := parseRecoveryPetitions(normalized, pendingLine, receiptID)
	if err != nil {
		return plan, nil, err
	}
	if !present {
		normalized = appendRecord(normalized, pendingLine)
	}
	plan.after = normalized
	petitions, _, err = parseRecoveryPetitions(plan.after, pendingLine, receiptID)
	if err != nil {
		return plan, nil, err
	}
	return plan, petitions, nil
}

func parseRecoveryPetitions(data, pendingLine []byte, receiptID string) ([]Petition, bool, error) {
	var petitions []Petition
	present := false
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var petition Petition
		if err := strictjson.Unmarshal(line, &petition); err != nil {
			return nil, false, fmt.Errorf("ledger: corrupt petition during recovery: %w", err)
		}
		if id, _ := petition["receipt_id"].(string); id == receiptID {
			if !bytes.Equal(line, pendingLine) {
				return nil, false, fmt.Errorf("ledger: recovery petition receipt id collides with different bytes")
			}
			present = true
		}
		petitions = append(petitions, petition)
	}
	return petitions, present, nil
}

func readRecoveryData(path string, pendingLine []byte) (recoveryFilePlan, []byte, error) {
	plan := recoveryFilePlan{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			plan.after = []byte{}
			return plan, []byte{}, nil
		}
		return plan, nil, err
	}
	plan.existed = true
	plan.before = append([]byte(nil), data...)
	if len(data) == 0 || data[len(data)-1] == '\n' {
		return plan, append([]byte(nil), data...), nil
	}
	lastNewline := bytes.LastIndexByte(data, '\n')
	partial := data[lastNewline+1:]
	if !bytes.HasPrefix(pendingLine, partial) {
		return plan, nil, fmt.Errorf("ledger: trailing partial record does not match the recovery record")
	}
	return plan, append([]byte(nil), data[:lastNewline+1]...), nil
}

func appendRecord(data, line []byte) []byte {
	out := append([]byte(nil), data...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, line...)
	return append(out, '\n')
}

func applyRecoveryPlan(plan recoveryFilePlan) error {
	if bytes.Equal(plan.before, plan.after) {
		return nil
	}
	current, err := os.ReadFile(plan.path)
	currentExists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if currentExists != plan.existed || !bytes.Equal(current, plan.before) {
		return fmt.Errorf("ledger: evidence changed while recovery was being planned; retry recovery")
	}
	mode := os.FileMode(0o644)
	if plan.existed {
		if info, err := os.Stat(plan.path); err == nil {
			mode = info.Mode().Perm()
		} else {
			return err
		}
	}
	return replaceRecoveryFile(plan.path, plan.after, mode)
}

func replaceRecoveryFile(path string, data []byte, mode os.FileMode) (err error) {
	parent := filepath.Dir(path)
	temp, err := os.CreateTemp(parent, ".ueg-recovery-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return replaceRecoveryPath(tempPath, path)
}

func sameStringPointer(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
