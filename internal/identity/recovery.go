package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"

	"github.com/stevenkratushniak-ctrl/ueg/internal/canon"
	"github.com/stevenkratushniak-ctrl/ueg/internal/keys"
	"github.com/stevenkratushniak-ctrl/ueg/internal/strictjson"
)

const (
	recoveryPayloadSchema = "ueg.recovery-payload.v1"
	argonTime             = uint32(3)
	argonMemoryKiB        = uint32(64 * 1024)
	argonKeyBytes         = uint32(32)
)

func recoveryParallelism() uint8 {
	count := runtime.NumCPU()
	if count < 1 {
		count = 1
	}
	if count > 4 {
		count = 4
	}
	return uint8(count)
}

func recoveryAAD(pkg *RecoveryPackage) map[string]any {
	return map[string]any{
		"cipher": map[string]any{
			"name":      pkg.Cipher.Name,
			"nonce_b64": pkg.Cipher.NonceB64,
		},
		"identity_id": pkg.IdentityID,
		"kdf": map[string]any{
			"key_bytes":   int(pkg.KDF.KeyBytes),
			"memory_kib":  int(pkg.KDF.MemoryKiB),
			"name":        pkg.KDF.Name,
			"parallelism": int(pkg.KDF.Parallelism),
			"salt_b64":    pkg.KDF.SaltB64,
			"time":        int(pkg.KDF.Time),
		},
		"protocol_version":     pkg.ProtocolVersion,
		"recovery_root_key_id": pkg.RecoveryRootKeyID,
		"schema":               pkg.Schema,
	}
}

func encryptRecoveryPackage(identityID string, root *keys.Pair, passphrase []byte) ([]byte, error) {
	if len(passphrase) < 12 {
		return nil, fmt.Errorf("recovery passphrase must contain at least 12 characters")
	}
	keyID, err := root.KeyID()
	if err != nil {
		return nil, err
	}
	privatePEM, err := root.PrivatePEM()
	if err != nil {
		return nil, err
	}
	defer zero(privatePEM)
	payload, err := json.Marshal(recoveryPayload{
		Schema: recoveryPayloadSchema, IdentityID: identityID,
		RecoveryRootKeyID: keyID, RecoveryPrivateKeyPEM: string(privatePEM),
	})
	if err != nil {
		return nil, err
	}
	defer zero(payload)

	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	pkg := &RecoveryPackage{
		Schema: RecoverySchema, ProtocolVersion: ProtocolVersion,
		IdentityID: identityID, RecoveryRootKeyID: keyID,
		KDF: RecoveryKDF{
			Name: "argon2id", SaltB64: base64.StdEncoding.EncodeToString(salt),
			Time: argonTime, MemoryKiB: argonMemoryKiB,
			Parallelism: recoveryParallelism(), KeyBytes: argonKeyBytes,
		},
		Cipher: RecoveryCipher{Name: "AES-256-GCM", NonceB64: base64.StdEncoding.EncodeToString(nonce)},
	}
	key := argon2.IDKey(passphrase, salt, pkg.KDF.Time, pkg.KDF.MemoryKiB, pkg.KDF.Parallelism, pkg.KDF.KeyBytes)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad, err := canon.Canonicalize(recoveryAAD(pkg))
	if err != nil {
		return nil, err
	}
	pkg.CiphertextB64 = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, payload, aad))
	return json.MarshalIndent(pkg, "", "  ")
}

// OpenRecoveryPackage decrypts and proves the recovery key without writing it.
func OpenRecoveryPackage(path string, passphrase []byte, expectedIdentity string) (*keys.Pair, *RecoveryPackage, error) {
	raw, err := readBoundedRegular(path, 1024*1024)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: read recovery package: %w", err)
	}
	var pkg RecoveryPackage
	if err := strictjson.UnmarshalExact(raw, &pkg); err != nil {
		return nil, nil, fmt.Errorf("identity: invalid recovery package: %w", err)
	}
	if pkg.Schema != RecoverySchema || pkg.ProtocolVersion != ProtocolVersion ||
		pkg.KDF.Name != "argon2id" || pkg.KDF.Time != argonTime || pkg.KDF.MemoryKiB != argonMemoryKiB ||
		pkg.KDF.KeyBytes != argonKeyBytes || pkg.KDF.Parallelism < 1 || pkg.KDF.Parallelism > 4 ||
		pkg.Cipher.Name != "AES-256-GCM" || !identityIDPattern.MatchString(pkg.IdentityID) ||
		!keyIDPattern.MatchString(pkg.RecoveryRootKeyID) {
		return nil, nil, fmt.Errorf("identity: recovery package parameters are not supported")
	}
	if expectedIdentity != "" && pkg.IdentityID != expectedIdentity {
		return nil, nil, fmt.Errorf("identity: recovery package belongs to %s, not %s", pkg.IdentityID, expectedIdentity)
	}
	salt, err := base64.StdEncoding.Strict().DecodeString(pkg.KDF.SaltB64)
	if err != nil || len(salt) != 16 {
		return nil, nil, fmt.Errorf("identity: recovery package salt is invalid")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(pkg.Cipher.NonceB64)
	if err != nil || len(nonce) != 12 {
		return nil, nil, fmt.Errorf("identity: recovery package nonce is invalid")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(pkg.CiphertextB64)
	if err != nil || len(ciphertext) < 16 {
		return nil, nil, fmt.Errorf("identity: recovery package ciphertext is invalid")
	}
	key := argon2.IDKey(passphrase, salt, pkg.KDF.Time, pkg.KDF.MemoryKiB, pkg.KDF.Parallelism, pkg.KDF.KeyBytes)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	aad, err := canon.Canonicalize(recoveryAAD(&pkg))
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: recovery package authentication failed (incorrect passphrase or altered package)")
	}
	defer zero(plaintext)
	var payload recoveryPayload
	if err := strictjson.UnmarshalExact(plaintext, &payload); err != nil {
		return nil, nil, fmt.Errorf("identity: decrypted recovery payload is invalid: %w", err)
	}
	if payload.Schema != recoveryPayloadSchema || payload.IdentityID != pkg.IdentityID || payload.RecoveryRootKeyID != pkg.RecoveryRootKeyID {
		return nil, nil, fmt.Errorf("identity: recovery payload does not match its authenticated package")
	}
	pair, err := keys.LoadPrivatePEMText(payload.RecoveryPrivateKeyPEM)
	payload.RecoveryPrivateKeyPEM = ""
	if err != nil {
		return nil, nil, fmt.Errorf("identity: recovery private key is invalid: %w", err)
	}
	actualID, err := pair.KeyID()
	if err != nil || actualID != pkg.RecoveryRootKeyID {
		return nil, nil, fmt.Errorf("identity: recovery private key does not match the public identity")
	}
	challenge := []byte("UEG-BPLUS-RECOVERY-PACKAGE-SELF-TEST-v1\x00" + pkg.IdentityID)
	signature, err := pair.SignB64(challenge)
	if err != nil || !pair.VerifyB64(challenge, signature) {
		return nil, nil, fmt.Errorf("identity: recovery package signing self-test failed")
	}
	return pair, &pkg, nil
}

// VerifyRecoveryPackage proves that an encrypted package can restore the
// expected recovery signing authority.
func VerifyRecoveryPackage(path string, passphrase []byte, expectedIdentity string) (*RecoveryPackage, error) {
	pair, pkg, err := OpenRecoveryPackage(path, passphrase, expectedIdentity)
	if pair != nil {
		zero(pair.Private)
	}
	return pkg, err
}
