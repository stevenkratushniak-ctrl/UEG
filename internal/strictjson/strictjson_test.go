package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateAcceptsUnambiguousJSON(t *testing.T) {
	for _, raw := range []string{`null`, `true`, `42`, `[]`, `{}`, `{"a":[{"b":1}]}`} {
		if err := Validate([]byte(raw)); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestValidateRejectsAmbiguousOrMalformedJSON(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"a":1,"a":1}`),
		[]byte(`{"a":{"b":1,"b":2}}`),
		[]byte(`{} {}`),
		[]byte(`{"a":NaN}`),
		[]byte(`{"a":`),
		{0xff, '{', '}'},
	}
	for _, raw := range cases {
		if err := Validate(raw); err == nil {
			t.Errorf("invalid JSON was accepted: %q", raw)
		}
	}
}

func TestUnmarshalPreservesNumbers(t *testing.T) {
	var value map[string]any
	if err := Unmarshal([]byte(`{"n":9007199254740993}`), &value); err != nil {
		t.Fatal(err)
	}
	if got, ok := value["n"].(json.Number); !ok || got.String() != "9007199254740993" {
		t.Fatalf("number was not preserved exactly: %#v", value["n"])
	}
}

func TestUnmarshalExactRejectsUnknownFields(t *testing.T) {
	var value struct {
		A string `json:"a"`
	}
	err := UnmarshalExact([]byte(`{"a":"ok","extra":true}`), &value)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field was not rejected: %v", err)
	}
}
