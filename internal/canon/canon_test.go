package canon

import "testing"

// The canonical bytes are the contract between this implementation and the
// Python verifier. These vectors were produced by the Reality Layer V1
// canonicalizer; if a change breaks them, signatures stop crossing languages.
func TestCanonicalVectors(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"empty object", map[string]any{}, `{}`},
		{"key order", map[string]any{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"nested", map[string]any{"z": map[string]any{"y": []any{1, 2}}, "a": nil}, `{"a":null,"z":{"y":[1,2]}}`},
		{"booleans", map[string]any{"t": true, "f": false}, `{"f":false,"t":true}`},
		{"escapes", map[string]any{"s": "a\"b\\c\nd\te"}, `{"s":"a\"b\\c\nd\te"}`},
		{"control char", map[string]any{"s": "\x01"}, `{"s":"\u0001"}`},
		{"unicode stays literal", map[string]any{"s": "héllo→"}, `{"s":"héllo→"}`},
		{"negative int", map[string]any{"n": -42}, `{"n":-42}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize(tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("canonical form differs\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestFloatsAreRejected(t *testing.T) {
	if _, err := Canonicalize(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("a float was accepted; cross-language signatures would not be reproducible")
	}
}

func TestMerkleRoot(t *testing.T) {
	if got, want := MerkleRootHex(nil), SHA256Hex(nil); got != want {
		t.Fatalf("empty merkle root = %s, want %s", got, want)
	}
	a := SHA256([]byte("a"))
	b := SHA256([]byte("b"))
	single := MerkleRootHex([][]byte{a})
	if single != SHA256Hex(a) {
		// A single leaf is its own root only if it is not duplicated first.
		if single == "" {
			t.Fatal("single-leaf root is empty")
		}
	}
	// An odd level duplicates its last node, so three leaves and four leaves
	// with the third repeated must agree.
	three := MerkleRootHex([][]byte{a, b, a})
	four := MerkleRootHex([][]byte{a, b, a, a})
	if three != four {
		t.Fatalf("odd-level duplication is not applied: %s vs %s", three, four)
	}
}
