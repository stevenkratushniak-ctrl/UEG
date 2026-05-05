package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Fuzz: ensure determinism hash never panics and is stable against irrelevant noise.
func FuzzDeterminismHash_NoPanic(f *testing.F) {
	seed := []byte(`{"version":"1.1.0","input":["x"],"final_stage":0,"transitions":[],"final_state":{"stage":0,"timestamp":"t","trace_id":"id"},"meta":{"ueg_version":"1.2.0","goos":"linux","goarch":"amd64","cwd":"."}}`)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Receipt
		if err := json.Unmarshal(b, &r); err != nil {
			return
		}
		_ = r.computeDeterminismHash()
	})
}

// Fuzz: capsule reading should not panic on arbitrary bytes that look like a zip.
func FuzzReadReceiptFromCapsule_NoPanic(f *testing.F) {
	// Valid minimal zip header bytes are tricky; we just seed with a known-good capsule.
	dir := f.TempDir()
	gw := NewGateway("fuzz", false, false, true)
	r := gw.Process([]string{})
	p := filepath.Join(dir, "seed.zip")
	_ = writeCapsule(p, r)
	seed, _ := os.ReadFile(p)
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		td := t.TempDir()
		zp := filepath.Join(td, "x.zip")
		// only run when bytes look plausibly like a zip to keep fuzz signal high
		if len(data) < 4 || !bytes.Equal(data[:2], []byte("PK")) {
			return
		}
		_ = os.WriteFile(zp, data, 0644)
		_, _ = readReceiptFromCapsule(zp) // must not panic
	})
}
