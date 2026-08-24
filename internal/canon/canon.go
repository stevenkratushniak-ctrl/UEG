// Package canon provides the canonical byte forms every hash and signature in
// UEG is taken over: RFC 8785 JSON canonicalization, SHA-256, and the Merkle
// construction used by Reality Layer V1 bundles.
//
// Floats are rejected. Two implementations that disagree on how to print a
// float cannot agree on a signature, and a signature that only verifies under
// one implementation is not evidence.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Value is the set of types that can be canonicalized: nil, bool, string,
// int/int64, map[string]any and []any built from the same.
type Value = any

// Canonicalize returns the RFC 8785 canonical UTF-8 JSON encoding of v.
func Canonicalize(v Value) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// MustCanonicalize is Canonicalize for values known to be well-formed.
func MustCanonicalize(v Value) []byte {
	out, err := Canonicalize(v)
	if err != nil {
		panic(err)
	}
	return out
}

func encode(b *strings.Builder, v Value) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case int:
		b.WriteString(strconv.FormatInt(int64(t), 10))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case string:
		encodeString(b, t)
	case []string:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, item)
		}
		b.WriteByte(']')
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			encodeString(b, k)
			b.WriteByte(':')
			if err := encode(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case float32, float64:
		return fmt.Errorf("canon: floats are forbidden (%v)", v)
	default:
		return fmt.Errorf("canon: unsupported type %T", v)
	}
	return nil
}

// encodeString writes a JSON string with the escaping RFC 8785 requires:
// the short escapes for the seven named characters, \u00xx for the remaining
// control characters, and literal UTF-8 for everything else.
func encodeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else if r == utf8.RuneError {
				b.WriteString(`\ufffd`)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256 returns the raw SHA-256 of data.
func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// HashJCS returns the hex SHA-256 of the canonical encoding of v.
func HashJCS(v Value) (string, error) {
	data, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(data), nil
}

// MerkleRootHex builds a binary Merkle tree over 32-byte digests: parents are
// sha256(left||right), a lone node at the end of a level is duplicated, and an
// empty list hashes to sha256 of no bytes.
func MerkleRootHex(leaves [][]byte) string {
	if len(leaves) == 0 {
		return SHA256Hex(nil)
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			joined := append(append([]byte{}, level[i]...), level[i+1]...)
			next = append(next, SHA256(joined))
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}
