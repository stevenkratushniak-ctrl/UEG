// Package keys owns Ed25519 key loading, generation, signing, and verification.
package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
)

// Pair is an Ed25519 keypair. Private is nil when the pair was loaded from a
// public trust root and can verify but not sign.
type Pair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

// Generate returns a new Ed25519 pair using crypto/rand through the standard
// library. It does not write either key to disk.
func Generate() (*Pair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Pair{Private: priv, Public: pub}, nil
}

// LoadOrCreate loads an existing private key or creates a new Ed25519 pair at
// the supplied private/public PEM paths.
func LoadOrCreate(privatePath, publicPath string) (*Pair, error) {
	if _, err := os.Lstat(privatePath); err == nil {
		return loadExistingPair(privatePath, publicPath, true)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if _, err := os.Lstat(publicPath); err == nil {
		return nil, fmt.Errorf("keys: private key is missing while its public trust anchor remains; restore the original private key from backup or use a new evidence home")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("keys: inspect public key: %w", err)
	}
	if err := preparePrivateDirectory(filepath.Dir(privatePath)); err != nil {
		return nil, fmt.Errorf("keys: secure private-key directory: %w", err)
	}

	pair, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := writePrivatePEM(privatePath, pair.Private); err != nil {
		return nil, err
	}
	if err := writePublicPEM(publicPath, pair.Public, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return nil, err
	}
	return pair, nil
}

// LoadExisting loads an existing private/public pair without creating files,
// rewriting the public key, or changing permissions.
func LoadExisting(privatePath, publicPath string) (*Pair, error) {
	return loadExistingPair(privatePath, publicPath, false)
}

// LoadPublicFile loads an existing public key without accessing private key
// material. It is used by information-only ledger operations.
func LoadPublicFile(publicPath string) (*Pair, error) {
	info, err := os.Lstat(publicPath)
	if err != nil {
		return nil, fmt.Errorf("keys: read public key metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("keys: %s is not a regular public-key file", publicPath)
	}
	data, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("keys: read public key: %w", err)
	}
	pair, err := LoadPublicPEMText(string(data))
	if err != nil {
		return nil, err
	}
	return pair, nil
}

func loadExistingPair(privatePath, publicPath string, repairMissingPublic bool) (*Pair, error) {
	if err := checkPrivateDirectory(filepath.Dir(privatePath)); err != nil {
		return nil, fmt.Errorf("keys: private-key directory is not secure: %w", err)
	}
	if err := checkPrivateFile(privatePath); err != nil {
		return nil, fmt.Errorf("keys: private key is not securely accessible: %w", err)
	}
	data, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("keys: read private key: %w", err)
	}
	pair, err := loadPrivatePEM(data)
	if err != nil {
		return nil, err
	}

	publicPair, publicErr := LoadPublicFile(publicPath)
	if publicErr != nil && repairMissingPublic && os.IsNotExist(rootCause(publicErr)) {
		if err := writePublicPEM(publicPath, pair.Public, 0o644); err != nil {
			return nil, err
		}
		return pair, nil
	}
	if publicErr != nil {
		return nil, publicErr
	}
	if !bytes.Equal(pair.Public, publicPair.Public) {
		return nil, fmt.Errorf("keys: public key does not match the private key")
	}
	return pair, nil
}

type unwrapper interface {
	Unwrap() error
}

func rootCause(err error) error {
	for {
		next, ok := err.(unwrapper)
		if !ok || next.Unwrap() == nil {
			return err
		}
		err = next.Unwrap()
	}
}

// LoadPublicPEMText loads a public-only pair from a PEM string.
func LoadPublicPEMText(pemText string) (*Pair, error) {
	block, err := decodePEM([]byte(pemText), "PUBLIC KEY")
	if err != nil {
		return nil, fmt.Errorf("keys: invalid public PEM: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse public key: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keys: not an Ed25519 public key")
	}
	return &Pair{Public: ed}, nil
}

// LoadPrivatePEMText strictly parses one PKCS#8 Ed25519 private key.
func LoadPrivatePEMText(pemText string) (*Pair, error) {
	return loadPrivatePEM([]byte(pemText))
}

// KeyID is the complete SHA-256 fingerprint of the canonical public PEM.
func (p *Pair) KeyID() (string, error) {
	pemBytes, err := p.PublicPEM()
	if err != nil {
		return "", err
	}
	return "ueg:sha256:" + canon.SHA256Hex(pemBytes), nil
}

// LegacyKeyID is the truncated identifier emitted by reconstructed UEG v2
// before the complete fingerprint became part of the bundle contract.
func (p *Pair) LegacyKeyID() (string, error) {
	pemBytes, err := p.PublicPEM()
	if err != nil {
		return "", err
	}
	return "ueg:" + canon.SHA256Hex(pemBytes)[:16], nil
}

// ValidateKeyID proves that id names p. Legacy ids are accepted only when a
// caller is validating evidence produced under the legacy v1 bundle contract.
func (p *Pair) ValidateKeyID(id string, allowLegacy bool) error {
	want, err := p.KeyID()
	if err != nil {
		return err
	}
	if id == want {
		return nil
	}
	if allowLegacy {
		legacy, legacyErr := p.LegacyKeyID()
		if legacyErr != nil {
			return legacyErr
		}
		if id == legacy {
			return nil
		}
	}
	return fmt.Errorf("key id does not match the public-key fingerprint")
}

// PublicPEM returns the public key in SubjectPublicKeyInfo PEM format.
func (p *Pair) PublicPEM() ([]byte, error) {
	if len(p.Public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("keys: missing Ed25519 public key")
	}
	der, err := x509.MarshalPKIXPublicKey(p.Public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// PrivatePEM returns the private key in unencrypted PKCS#8 PEM form. Callers
// must keep the returned bytes in memory only or write them through
// WriteProtectedFile.
func (p *Pair) PrivatePEM() ([]byte, error) {
	if len(p.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keys: missing Ed25519 private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(p.Private)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if data == nil {
		return nil, fmt.Errorf("keys: PEM encode failed")
	}
	return data, nil
}

// WritePair writes a new private/public pair without replacing existing key
// files. The private path receives the platform-specific protection enforced
// by this package.
func (p *Pair) WritePair(privatePath, publicPath string) error {
	if err := writePrivatePEM(privatePath, p.Private); err != nil {
		return err
	}
	if err := writePublicPEM(publicPath, p.Public, 0o644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

// WritePublicFile writes one public key in canonical PEM form.
func (p *Pair) WritePublicFile(path string) error {
	return writePublicPEM(path, p.Public, 0o644)
}

// WriteProtectedFile writes sensitive bytes to a new owner-protected file.
// It never truncates or replaces an existing path, and it does not change the
// permissions of an owner-selected existing parent directory.
func WriteProtectedFile(path string, data []byte) error {
	return writeNewProtectedFile(path, data, false)
}

// PrepareProtectedDirectory creates or restricts a UEG-owned private
// directory. It must not be used on an owner-selected recovery-package parent.
func PrepareProtectedDirectory(path string) error {
	return preparePrivateDirectory(path)
}

// CheckProtectedFile verifies that path has the private-file protection UEG
// requires on the current platform.
func CheckProtectedFile(path string) error {
	return checkPrivateFile(path)
}

// SignB64 signs message and returns a standard-base64 Ed25519 signature.
func (p *Pair) SignB64(message []byte) (string, error) {
	if len(p.Private) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("keys: private key required")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(p.Private, message)), nil
}

// VerifyB64 verifies a standard-base64 Ed25519 signature over message.
func (p *Pair) VerifyB64(message []byte, signatureB64 string) bool {
	if len(p.Public) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(p.Public, message, sig)
}

func loadPrivatePEM(data []byte) (*Pair, error) {
	block, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, fmt.Errorf("keys: invalid private PEM: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: not an Ed25519 private key")
	}
	privateCopy := append(ed25519.PrivateKey(nil), priv...)
	publicCopy := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
	return &Pair{Private: privateCopy, Public: publicCopy}, nil
}

func decodePEM(data []byte, expectedType string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("PEM block not found")
	}
	if block.Type != expectedType {
		return nil, fmt.Errorf("PEM block type is %q, want %q", block.Type, expectedType)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("PEM headers are not permitted")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("trailing data after PEM block")
	}
	return block, nil
}

func writePrivatePEM(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if data == nil {
		return fmt.Errorf("keys: PEM encode failed")
	}
	if err := writeNewPrivateFile(path, data); err != nil {
		return err
	}
	return nil
}

func writePublicPEM(path string, pub ed25519.PublicKey, mode os.FileMode) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writePEM(path, &pem.Block{Type: "PUBLIC KEY", Bytes: der}, mode)
}

func writePEM(path string, block *pem.Block, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data := pem.EncodeToMemory(block)
	if data == nil {
		return fmt.Errorf("keys: PEM encode failed")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
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
	removeOnFailure = false
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	return writeNewProtectedFile(path, data, true)
}

func writeNewProtectedFile(path string, data []byte, protectParent bool) (err error) {
	parent := filepath.Dir(path)
	if protectParent {
		if err := preparePrivateDirectory(parent); err != nil {
			return fmt.Errorf("keys: secure private-key directory: %w", err)
		}
	} else {
		info, inspectErr := os.Lstat(parent)
		if inspectErr != nil {
			return fmt.Errorf("keys: inspect protected-file parent: %w", inspectErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("keys: protected-file parent is not a regular directory: %s", parent)
		}
	}
	f, err := openPrivateFileExclusive(path)
	if err != nil {
		return fmt.Errorf("keys: create private key: %w", err)
	}
	removeOnFailure := true
	defer func() {
		if removeOnFailure {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("keys: write private key: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("keys: sync private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("keys: close private key: %w", err)
	}
	if err := securePrivateFile(path); err != nil {
		return fmt.Errorf("keys: secure private key: %w", err)
	}
	removeOnFailure = false
	return nil
}
