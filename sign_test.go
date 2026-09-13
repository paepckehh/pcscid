package pcscid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeOpenSSHKey serializes an ed25519 private key into a real
// OpenSSH private key file (unencrypted container), the same format
// ssh-keygen writes for a passphrase-less key.
func writeOpenSSHKey(t *testing.T, key ed25519.PrivateKey, comment string) string {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("bad public key type")
	}

	var public []byte
	public = appendSSHString(public, []byte(keyAlgorithmEd25519))
	public = appendSSHString(public, pub)

	var private []byte
	var check [4]byte
	rand.Read(check[:])
	private = append(private, check[:]...)
	private = append(private, check[:]...)
	private = appendSSHString(private, []byte(keyAlgorithmEd25519))
	private = appendSSHString(private, pub)
	private = appendSSHString(private, key)
	private = appendSSHString(private, []byte(comment))
	private = append(private, 1, 2, 3) // container padding

	var blob []byte
	blob = append(blob, openSSHKeyMagic...)
	blob = appendSSHString(blob, []byte("none"))
	blob = appendSSHString(blob, []byte("none"))
	blob = appendSSHString(blob, nil)
	blob = append(blob, 0, 0, 0, 1)
	blob = appendSSHString(blob, public)
	blob = appendSSHString(blob, private)

	path := filepath.Join(t.TempDir(), "id_ed25519")
	var file strings.Builder
	file.WriteString(openSSHArmorBegin + "\n")
	encoded := base64.StdEncoding.EncodeToString(blob)
	for len(encoded) > 70 {
		file.WriteString(encoded[:70])
		file.WriteString("\n")
		encoded = encoded[70:]
	}
	file.WriteString(encoded)
	file.WriteString("\n")
	file.WriteString(openSSHArmorEnd)
	file.WriteString("\n")
	if err := os.WriteFile(path, []byte(file.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewSigner(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeOpenSSHKey(t, key, "pcscid test")
	if _, err := NewSigner(path); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
}

func TestNewSignerInvalid(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	good := writeOpenSSHKey(t, key, "")

	cases := map[string]string{
		"missing file": filepath.Join(t.TempDir(), "absent"),
		"no armor":     filepath.Join(t.TempDir(), "plain"),
		"rsa type":     filepath.Join(t.TempDir(), "rsa"),
		"corrupt":      filepath.Join(t.TempDir(), "corrupt"),
	}
	if err := os.WriteFile(cases["no armor"], []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cases["rsa type"], []byte(openSSHArmorBegin+"\nAAAA\n"+openSSHArmorEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cases["corrupt"], []byte(openSSHArmorBegin+"\n"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0}, 64))+"\n"+openSSHArmorEnd+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range cases {
		if _, err := NewSigner(path); err == nil {
			t.Errorf("%s: accepted invalid key", name)
		}
	}

	// The good key must remain good after all rejects, and a
	// passphrase protected container must be refused.
	if _, err := NewSigner(good); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	var encrypted []byte
	encrypted = append(encrypted, openSSHKeyMagic...)
	encrypted = appendSSHString(encrypted, []byte("aes256-ctr"))
	encrypted = appendSSHString(encrypted, []byte("bcrypt"))
	encrypted = appendSSHString(encrypted, []byte("salt"))
	encryptedPath := filepath.Join(t.TempDir(), "encrypted")
	os.WriteFile(encryptedPath, []byte(openSSHArmorBegin+"\n"+base64.StdEncoding.EncodeToString(encrypted)+"\n"+openSSHArmorEnd+"\n"), 0o600)
	if _, err := NewSigner(encryptedPath); err == nil {
		t.Error("encrypted key accepted")
	}
}

func TestSignerSignLine(t *testing.T) {
	t.Parallel()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(writeOpenSSHKey(t, key, ""))
	if err != nil {
		t.Fatal(err)
	}

	line := "#qr-xlrk-i5:r3v-401-5gmr"
	signed := s.SignLine(line)
	if !strings.HasPrefix(signed, line+"$") {
		t.Fatalf("signed line %q lacks %q prefix", signed, line+"$")
	}
	sig, err := base64.StdEncoding.DecodeString(signed[len(line)+1:])
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}

	// Parse the SSHSIG blob the way ssh-keygen -Y verify does and
	// check the signature over the bare line.
	r := sshReader{data: sig}
	if magic := r.bytes(len(sshsigMagic)); string(magic) != sshsigMagic {
		t.Fatalf("signature magic %q", magic)
	}
	if version := r.uint32(); version != sshsigVersion {
		t.Fatalf("signature version %d, want %d", version, sshsigVersion)
	}
	if public := r.sshString(); len(public) == 0 {
		t.Fatal("missing embedded public key")
	}
	if namespace := r.sshString(); string(namespace) != sshsigNamespace {
		t.Fatalf("namespace %q, want %q", namespace, sshsigNamespace)
	}
	if reserved := r.sshString(); len(reserved) != 0 {
		t.Fatalf("reserved field %q not empty", reserved)
	}
	if hashAlg := r.sshString(); string(hashAlg) != sshsigHashAlgorithm {
		t.Fatalf("hash algorithm %q, want %q", hashAlg, sshsigHashAlgorithm)
	}
	blob := r.sshString()
	if r.err != nil {
		t.Fatal(r.err)
	}
	b := sshReader{data: blob}
	if alg := b.sshString(); string(alg) != keyAlgorithmEd25519 {
		t.Fatalf("signature algorithm %q", alg)
	}
	sigBytes := b.sshString()
	if b.err != nil {
		t.Fatal(b.err)
	}
	digest := sha512.Sum512([]byte(line))
	signedMsg := sshsigSignedMessage(sshsigNamespace, digest[:])
	if !ed25519.Verify(pub, signedMsg, sigBytes) {
		t.Error("signature does not verify")
	}
}

func TestSignerDeterministic(t *testing.T) {
	t.Parallel()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(writeOpenSSHKey(t, key, ""))
	if err != nil {
		t.Fatal(err)
	}
	if a, b := s.Sign([]byte("same")), s.Sign([]byte("same")); a != b {
		t.Error("signing is not deterministic")
	}
}
