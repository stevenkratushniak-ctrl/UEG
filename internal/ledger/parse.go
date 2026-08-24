package ledger

import (
	"fmt"
	"sort"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

// receiptFields is the exact key set Receipt v1 permits. The schema declares
// additionalProperties:false, so a receipt carrying anything else is not a
// Receipt v1 — and, since receipt_id is computed over a fixed field list, an
// unnoticed extra field would be an unsigned place to hide data.
var receiptFields = []string{
	"actor", "adapter_degraded", "admission_outcome", "clause_ids",
	"engine_version", "evaluation_hash", "expression_outcome", "passport_ref",
	"petition_hash", "petition_summary", "policy_hash", "prev_receipt_id",
	"receipt_id", "sequence_no", "signature_b64", "signing_key_id",
	"time_source", "timestamp_iso8601",
}

var summaryFields = []string{"action", "surface", "target"}

// ParseReceiptStrict decodes one receipt, rejecting unknown fields, missing
// fields, duplicate keys, and non-integer sequence numbers.
func ParseReceiptStrict(line []byte) (*Receipt, error) {
	var generic map[string]any
	if err := strictjson.Unmarshal(line, &generic); err != nil {
		return nil, err
	}
	if err := exactKeys(generic, receiptFields, "receipt"); err != nil {
		return nil, err
	}
	summary, ok := generic["petition_summary"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("receipt: petition_summary must be an object")
	}
	if err := exactKeys(summary, summaryFields, "petition_summary"); err != nil {
		return nil, err
	}

	var r Receipt
	if err := strictjson.UnmarshalExact(line, &r); err != nil {
		return nil, err
	}
	if r.ClauseIDs == nil {
		r.ClauseIDs = []string{}
	}
	return &r, nil
}

func exactKeys(obj map[string]any, want []string, what string) error {
	got := make([]string, 0, len(obj))
	for k := range obj {
		got = append(got, k)
	}
	sort.Strings(got)
	expected := append([]string{}, want...)
	sort.Strings(expected)
	if strings.Join(got, ",") != strings.Join(expected, ",") {
		missing, extra := diff(expected, got)
		return fmt.Errorf("%s: field set does not match Receipt v1 (missing %v, unexpected %v)", what, missing, extra)
	}
	return nil
}

func diff(expected, got []string) (missing, extra []string) {
	has := map[string]bool{}
	for _, g := range got {
		has[g] = true
	}
	for _, e := range expected {
		if !has[e] {
			missing = append(missing, e)
		}
	}
	want := map[string]bool{}
	for _, e := range expected {
		want[e] = true
	}
	for _, g := range got {
		if !want[g] {
			extra = append(extra, g)
		}
	}
	return missing, extra
}
