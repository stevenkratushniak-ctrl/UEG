package identity

import (
	"encoding/json"
	"testing"

	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
)

func TestLifecycleAuthorityAndChainAdversarialMatrix(t *testing.T) {
	_, recovery, initial := initializeTestIdentity(t)
	root, _, err := OpenRecoveryPackage(recovery, []byte(testPassphrase), initial.Genesis.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(root.Private)
	newOperational, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	request := MutationRequest{Action: ActionRotate, ReasonCode: "ADVERSARIAL_MATRIX", Boundary: LedgerBoundary{SequenceNo: -1}}

	t.Run("old key alone", func(t *testing.T) {
		if _, err := NewLifecycleRecord(initial, nil, initial.ActivePair, newOperational, request); err == nil {
			t.Fatal("old and proposed operational keys authorized a transition without the recovery root")
		}
	})
	t.Run("attacker old and new with another root", func(t *testing.T) {
		attackerRoot, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewLifecycleRecord(initial, attackerRoot, initial.ActivePair, newOperational, request); err == nil {
			t.Fatal("attacker root authorized another identity's transition")
		}
	})

	record, err := NewLifecycleRecord(initial, root, initial.ActivePair, newOperational, request)
	if err != nil {
		t.Fatal(err)
	}
	official, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], record})
	if err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"operational proof", "retiring signature", "recovery signature", "boundary"} {
		t.Run(field+" mutation", func(t *testing.T) {
			mutated := cloneRecord(t, record)
			switch field {
			case "operational proof":
				value := mutateBase64(*mutated.OperationalProofB64)
				mutated.OperationalProofB64 = &value
			case "retiring signature":
				value := mutateBase64(*mutated.RetiringSignatureB64)
				mutated.RetiringSignatureB64 = &value
			case "recovery signature":
				mutated.RecoverySignatureB64 = mutateBase64(mutated.RecoverySignatureB64)
			case "boundary":
				id := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				mutated.LedgerBoundary = LedgerBoundary{SequenceNo: 0, ReceiptID: &id}
				mutated.PreviousEpoch.FinalLedgerBoundary = mutated.LedgerBoundary
			}
			if _, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], mutated}); err == nil {
				t.Fatalf("%s mutation was accepted", field)
			}
		})
	}

	t.Run("replay and duplicate", func(t *testing.T) {
		if _, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], record, record}); err == nil {
			t.Fatal("replayed lifecycle record was accepted")
		}
	})

	nextOperational, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewLifecycleRecord(official, root, newOperational, nextOperational, MutationRequest{
		Action: ActionRotate, ReasonCode: "SECOND_ROTATION", Boundary: LedgerBoundary{SequenceNo: -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("skipped and reordered", func(t *testing.T) {
		if _, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], second}); err == nil {
			t.Fatal("skipped lifecycle sequence was accepted")
		}
		if _, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], second, record}); err == nil {
			t.Fatal("reordered lifecycle chain was accepted")
		}
	})

	alternateOperational, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	alternateRecord, err := NewLifecycleRecord(initial, root, initial.ActivePair, alternateOperational, request)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], alternateRecord})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("conflict and fork", func(t *testing.T) {
		if _, err := DeriveState("", initial.Genesis, []*LifecycleRecord{initial.Records[0], record, alternateRecord}); err == nil {
			t.Fatal("same-sequence conflicting records were accepted in one chain")
		}
		if _, err := CompareLifecycleStates(official, alternate); err == nil {
			t.Fatal("two valid but conflicting lifecycle descendants were treated as one history")
		}
	})
}

func cloneRecord(t *testing.T, record *LifecycleRecord) *LifecycleRecord {
	t.Helper()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var result LifecycleRecord
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

func mutateBase64(value string) string {
	if value[0] == 'A' {
		return "B" + value[1:]
	}
	return "A" + value[1:]
}
