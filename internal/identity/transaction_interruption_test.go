package identity

import (
	"fmt"
	"testing"
)

func TestRotationRecoversAtEveryDurableMutationBoundary(t *testing.T) {
	boundaries := []string{
		"journal_durable",
		"new_private_staged",
		"new_pair_staged",
		"new_private_published",
		"new_public_published",
		"lifecycle_published",
		"old_private_removed",
		"before_journal_clear",
	}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			home, recovery, original := initializeTestIdentity(t)
			interrupted := false
			func() {
				defer func() {
					if recover() != nil {
						interrupted = true
					}
				}()
				lifecycleMutationBoundary = func(reached string) {
					if reached == boundary {
						panic(fmt.Sprintf("simulated process loss at %s", reached))
					}
				}
				defer func() { lifecycleMutationBoundary = nil }()
				_, _, _ = ApplyMutation(home, recovery, []byte(testPassphrase), MutationRequest{
					Action: ActionRotate, ReasonCode: "INTERRUPTION_QUALIFICATION", Boundary: LedgerBoundary{SequenceNo: -1},
				})
			}()
			lifecycleMutationBoundary = nil
			if !interrupted {
				t.Fatalf("test did not reach mutation boundary %s", boundary)
			}
			if pending, err := MutationPending(home); err != nil || !pending {
				t.Fatalf("interruption did not preserve a recovery journal: pending=%v err=%v", pending, err)
			}
			recovered, err := RecoverPendingMutation(home)
			if err != nil {
				t.Fatalf("RecoverPendingMutation: %v", err)
			}
			activeCount := 0
			for _, epoch := range recovered.Epochs {
				if epoch.Status == StatusActive {
					activeCount++
				}
			}
			if activeCount != 1 || recovered.Active() == nil {
				t.Fatalf("recovery did not establish exactly one active epoch: %#v", recovered.Epochs)
			}
			if recovered.Genesis.IdentityID != original.Genesis.IdentityID {
				t.Fatal("recovery changed the stable identity")
			}
			if boundary == "journal_durable" || boundary == "new_private_staged" {
				if recovered.LastSequence != 0 || recovered.Active().EpochNumber != 0 {
					t.Fatalf("incomplete key staging should roll back to epoch zero: seq=%d active=%d", recovered.LastSequence, recovered.Active().EpochNumber)
				}
			} else if recovered.LastSequence != 1 || recovered.Active().EpochNumber != 1 {
				t.Fatalf("complete staged transition should finish epoch one: seq=%d active=%d", recovered.LastSequence, recovered.Active().EpochNumber)
			}
			if pending, err := MutationPending(home); err != nil || pending {
				t.Fatalf("recovery left a transaction journal: pending=%v err=%v", pending, err)
			}
		})
	}
}
