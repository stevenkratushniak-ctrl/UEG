package keys

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateRoundTripsAndUsesBoundKeyID(t *testing.T) {
	home := t.TempDir()
	privatePath := filepath.Join(home, "keys", "ed25519_private.pem")
	publicPath := filepath.Join(home, "keys", "ed25519_public.pem")

	first, err := LoadOrCreate(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Public.Equal(second.Public) {
		t.Fatal("reopening the key path loaded a different key")
	}
	id, err := first.KeyID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "ueg:sha256:") || len(id) != len("ueg:sha256:")+64 {
		t.Fatalf("unexpected complete key id %q", id)
	}
	if err := first.ValidateKeyID(id, false); err != nil {
		t.Fatalf("complete key id did not bind to its key: %v", err)
	}
	legacy, err := first.LegacyKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.ValidateKeyID(legacy, false); err == nil {
		t.Fatal("legacy key id was accepted when legacy compatibility was disabled")
	}
	if err := first.ValidateKeyID(legacy, true); err != nil {
		t.Fatalf("legacy key id was not accepted in legacy compatibility mode: %v", err)
	}
}

func TestLoadOrCreateRefusesToReplaceLostPrivateIdentity(t *testing.T) {
	home := t.TempDir()
	privatePath := filepath.Join(home, "keys", "ed25519_private.pem")
	publicPath := filepath.Join(home, "keys", "ed25519_public.pem")
	if _, err := LoadOrCreate(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	publicBefore, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreate(privatePath, publicPath); err == nil {
		t.Fatal("missing private key silently created a replacement identity")
	} else if !strings.Contains(err.Error(), "private key is missing") {
		t.Fatalf("missing private key returned an unclear error: %v", err)
	}
	if _, err := os.Stat(privatePath); !os.IsNotExist(err) {
		t.Fatalf("missing private key was recreated: %v", err)
	}
	publicAfter, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(publicAfter) != string(publicBefore) {
		t.Fatal("surviving public trust anchor was modified")
	}
}

func TestPEMParsingRejectsWrongTypeHeadersAndTrailingData(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if _, err := LoadPublicPEMText(string(publicPEM)); err != nil {
		t.Fatalf("valid public PEM was rejected: %v", err)
	}
	if _, err := loadPrivatePEM(privatePEM); err != nil {
		t.Fatalf("valid private PEM was rejected: %v", err)
	}

	cases := []struct {
		name string
		data []byte
		load func([]byte) error
	}{
		{"public wrong type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicDER}), func(b []byte) error { _, err := LoadPublicPEMText(string(b)); return err }},
		{"public trailing", append(append([]byte{}, publicPEM...), []byte("not whitespace")...), func(b []byte) error { _, err := LoadPublicPEMText(string(b)); return err }},
		{"private wrong type", pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: privateDER}), func(b []byte) error { _, err := loadPrivatePEM(b); return err }},
		{"private trailing", append(append([]byte{}, privatePEM...), []byte("not whitespace")...), func(b []byte) error { _, err := loadPrivatePEM(b); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.load(tc.data); err == nil {
				t.Fatal("ambiguous PEM was accepted")
			}
		})
	}
}

func TestNewPrivateFileIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "private.pem")
	if err := preparePrivateDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewPrivateFile(path, []byte("replacement")); err == nil {
		t.Fatal("exclusive private-key creation replaced an existing file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatal("existing private-key bytes were modified")
	}
}

func TestProtectedFileDoesNotChangeExistingParentMode(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "owner-selected")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "recovery.json")
	if err := WriteProtectedFile(path, []byte("synthetic encrypted package")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Fatalf("protected file write changed parent mode from %04o to %04o", before.Mode().Perm(), after.Mode().Perm())
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("protected file does not meet platform privacy requirements: %v", err)
	}
}
