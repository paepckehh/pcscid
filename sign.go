// sign.go parses OpenSSH ed25519 private keys and signs output lines
// in the OpenSSH SSHSIG format (PROTOCOL.sshsig), the signature
// format of `ssh-keygen -Y sign`, so every signed line can be
// verified with the stock `ssh-keygen -Y verify` against the key's
// public half. Pure stdlib, no cgo, no third party code.

package pcscid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// sshsigMagic is the fixed prefix of every SSHSIG signature blob and
// of the message that is signed.
const sshsigMagic = "SSHSIG"

// sshsigNamespace is the SSHSIG namespace pcscid signs under. The
// verifier must pass the same namespace to ssh-keygen -Y verify.
const sshsigNamespace = "pcscid"

// sshsigVersion is the SSHSIG container version, the only one
// defined by the protocol.
const sshsigVersion uint32 = 1

// sshsigSeparator terminates a signed output line before its
// signature.
const sshsigSeparator = '$'

// sshsigHashAlgorithm is the SSHSIG hash algorithm, the only one
// OpenSSH itself defines.
const sshsigHashAlgorithm = "sha512"

// openSSHKeyMagic introduces every unencrypted OpenSSH private key
// blob.
var openSSHKeyMagic = []byte("openssh-key-v1\x00")

// openSSHArmor marks an OpenSSH private key file.
const (
	openSSHArmorBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
	openSSHArmorEnd   = "-----END OPENSSH PRIVATE KEY-----"
)

// Signer signs output lines with an ed25519 private key in the
// OpenSSH SSHSIG format.
type Signer struct {
	key ed25519.PrivateKey
}

// NewSigner loads an OpenSSH ed25519 private key from path and returns
// a Signer over it. The key must be usable for signing: an unencrypted
// ("openssh-key-v1" container, cipher "none") ed25519 key whose private
// half matches its public half. Encrypted keys, keys of other types and
// damaged files fail with an error instead of silently producing
// unsigned output.
func NewSigner(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := parseOpenSSHEd25519(data)
	if err != nil {
		return nil, fmt.Errorf("pcscid: %s: %w", path, err)
	}
	return &Signer{key: key}, nil
}

// SignLine returns line with the separator and the base64 encoded
// SSHSIG signature of the line itself appended: line$<base64>. The
// signature covers exactly the bytes of line as emitted, so a
// signature over "#xx-xxxx-xx:xxx-xxx-xxxx" is stable text a verifier
// can re-sign and compare.
func (s *Signer) SignLine(line string) string {
	return line + string(sshsigSeparator) + s.Sign([]byte(line))
}

// Sign returns the SSHSIG signature of msg as base64. The SSHSIG blob
// is the binary signature format inside the armored block of
// `ssh-keygen -Y sign`; encoding it as plain base64 keeps one signed
// output line a single line, it re-arms into the PEM style block by
// wrapping it at 70 columns between the armor lines.
func (s *Signer) Sign(msg []byte) string {
	digest := sha512.Sum512(msg)
	signed := sshsigSignedMessage(sshsigNamespace, digest[:])

	pub, _ := s.key.Public().(ed25519.PublicKey)
	var public []byte
	public = appendSSHString(public, []byte(keyAlgorithmEd25519))
	public = appendSSHString(public, pub)

	var blob []byte
	blob = appendSSHString(blob, []byte(keyAlgorithmEd25519))
	blob = appendSSHString(blob, ed25519.Sign(s.key, signed))

	var out []byte
	out = append(out, sshsigMagic...)
	out = append(out, byte(sshsigVersion>>24), byte(sshsigVersion>>16), byte(sshsigVersion>>8), byte(sshsigVersion))
	out = appendSSHString(out, public)
	out = appendSSHString(out, []byte(sshsigNamespace))
	out = appendSSHString(out, nil)
	out = appendSSHString(out, []byte(sshsigHashAlgorithm))
	out = appendSSHString(out, blob)
	return base64.StdEncoding.EncodeToString(out)
}

// keyAlgorithmEd25519 is the SSH wire identifier of an ed25519 key.
const keyAlgorithmEd25519 = "ssh-ed25519"

// sshsigSignedMessage builds the message an SSHSIG signature covers
// (sshsig_wrap_sign in OpenSSH): the magic, the namespace, the empty
// reserved field, the hash algorithm and the digest of the payload.
// The version only lives in the outer signature blob, it is not
// signed.
func sshsigSignedMessage(namespace string, digest []byte) []byte {
	var msg []byte
	msg = append(msg, sshsigMagic...)
	msg = appendSSHString(msg, []byte(namespace))
	msg = appendSSHString(msg, nil)
	msg = appendSSHString(msg, []byte(sshsigHashAlgorithm))
	msg = appendSSHString(msg, digest)
	return msg
}

// parseOpenSSHEd25519 extracts a usable ed25519 private key from the
// contents of an OpenSSH private key file.
func parseOpenSSHEd25519(data []byte) (ed25519.PrivateKey, error) {
	blob, err := decodeOpenSSHArmor(data)
	if err != nil {
		return nil, err
	}
	r := sshReader{data: blob}
	if magic := r.bytes(len(openSSHKeyMagic)); !bytes.Equal(magic, openSSHKeyMagic) {
		return nil, errors.New("not an openssh-key-v1 private key")
	}
	cipher := r.sshString()
	kdf := r.sshString()
	_ = r.sshString() // kdfoptions, empty when cipher is none
	if r.err != nil {
		return nil, r.err
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return nil, errors.New("passphrase protected keys are not supported")
	}
	if n := r.uint32(); r.err == nil && n < 1 {
		return nil, errors.New("key file holds no key")
	}
	_ = r.sshString() // public half, re-verified below against the private
	rest := r.sshString()
	if r.err != nil {
		return nil, r.err
	}

	p := sshReader{data: rest}
	check1 := p.uint32()
	check2 := p.uint32()
	if p.err != nil {
		return nil, p.err
	}
	if check1 != check2 {
		return nil, errors.New("key check ints mismatch, corrupt key")
	}
	if keyType := p.sshString(); string(keyType) != keyAlgorithmEd25519 {
		return nil, fmt.Errorf("unsupported key type %q, ssh-ed25519 required", keyType)
	}
	pub := p.sshString()
	priv := p.sshString()
	if p.err != nil {
		return nil, p.err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad ed25519 private half, %d bytes", len(priv))
	}
	key := ed25519.PrivateKey(priv)
	if !bytes.Equal(priv[ed25519.SeedSize:], pub) {
		return nil, errors.New("public half does not match private half")
	}

	// A usable key must round trip a self test signature.
	test := []byte("pcscid/ssh-key-check")
	if !ed25519.Verify(pub, test, ed25519.Sign(key, test)) {
		return nil, errors.New("key failed the signing self test")
	}
	return key, nil
}

// decodeOpenSSHArmor extracts the base64 payload between the OpenSSH
// armor lines.
func decodeOpenSSHArmor(data []byte) ([]byte, error) {
	lines := strings.Split(string(data), "\n")
	i := 0
	for ; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == openSSHArmorBegin {
			break
		}
	}
	if i == len(lines) {
		return nil, errors.New("missing OPENSSH PRIVATE KEY armor")
	}
	var b64 strings.Builder
	for i++; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == openSSHArmorEnd {
			blob, err := base64.StdEncoding.DecodeString(b64.String())
			if err != nil {
				return nil, fmt.Errorf("bad key base64: %w", err)
			}
			return blob, nil
		}
		b64.WriteString(line)
	}
	return nil, errors.New("unterminated OPENSSH PRIVATE KEY armor")
}

// sshReader walks the SSH wire format: uint32 length prefixed strings
// and big endian uint32 values.
type sshReader struct {
	data []byte
	err  error
}

func (r *sshReader) bytes(n int) []byte {
	if r.err != nil || n < 0 || len(r.data) < n {
		if r.err == nil {
			r.err = errors.New("truncated key data")
		}
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

func (r *sshReader) uint32() uint32 {
	if b := r.bytes(4); b != nil {
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	return 0
}

func (r *sshReader) sshString() []byte {
	n := r.uint32()
	if r.err != nil {
		return nil
	}
	if n > uint32(len(r.data)) {
		r.err = errors.New("truncated key data")
		return nil
	}
	return r.bytes(int(n))
}

// appendSSHString appends s in SSH wire format: uint32 length prefix
// then the bytes.
func appendSSHString(dst, s []byte) []byte {
	var length [4]byte
	length[0] = byte(len(s) >> 24)
	length[1] = byte(len(s) >> 16)
	length[2] = byte(len(s) >> 8)
	length[3] = byte(len(s))
	dst = append(dst, length[:]...)
	return append(dst, s...)
}
