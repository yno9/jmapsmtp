// Interop helper for the OpenPGP port.
//
// Encryption picks a fresh session key every time, so its output cannot be
// compared byte for byte. Cross-decryption is the check: what one
// implementation encrypts, the other opens.
//
//	encrypt   read {public_key, plaintext} and print an armoured PGP MESSAGE
//	decrypt   read {private_key, ciphertext} and print the plaintext
package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type request struct {
	PublicKey string `json:"public_key,omitempty"`
	// PublicKeyB64 carries an unarmoured key — the Autocrypt form — which is
	// not UTF-8 and so cannot ride in a JSON string.
	PublicKeyB64 string `json:"public_key_b64,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

type response struct {
	Ciphertext string `json:"ciphertext,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
	Err        string `json:"err,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: pgp-interop encrypt|decrypt")
	}
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fail("read input: %v", err)
	}
	switch os.Args[1] {
	case "encrypt":
		emit(doEncrypt(req))
	case "decrypt":
		emit(doDecrypt(req))
	default:
		fail("unknown command %q", os.Args[1])
	}
}

// doEncrypt is pgpEncryptInline from go-jmapsmtp/autocrypt.go, with the key
// read from the request instead of from disk.
func doEncrypt(req request) response {
	key := []byte(req.PublicKey)
	if req.PublicKeyB64 != "" {
		var err error
		key, err = base64.StdEncoding.DecodeString(req.PublicKeyB64)
		if err != nil {
			return response{Err: fmt.Sprintf("bad key base64: %v", err)}
		}
	}
	entity, err := readEntity(key)
	if err != nil {
		return response{Err: err.Error()}
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		return response{Err: fmt.Sprintf("bad plaintext base64: %v", err)}
	}

	var buf bytes.Buffer
	aw, err := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err != nil {
		return response{Err: err.Error()}
	}
	cfg := &packet.Config{DefaultHash: crypto.SHA256, DefaultCipher: packet.CipherAES256}
	w, err := openpgp.Encrypt(aw, openpgp.EntityList{entity}, nil, nil, cfg)
	if err != nil {
		return response{Err: err.Error()}
	}
	if _, err := w.Write(plaintext); err != nil {
		return response{Err: err.Error()}
	}
	w.Close()
	aw.Close()
	return response{Ciphertext: buf.String()}
}

func doDecrypt(req request) response {
	block, err := armor.Decode(bytes.NewBufferString(req.PrivateKey))
	if err != nil {
		return response{Err: fmt.Sprintf("private key armor: %v", err)}
	}
	keyring, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return response{Err: fmt.Sprintf("private keyring: %v", err)}
	}

	ctBlock, err := armor.Decode(bytes.NewBufferString(req.Ciphertext))
	if err != nil {
		return response{Err: fmt.Sprintf("ciphertext armor: %v", err)}
	}
	md, err := openpgp.ReadMessage(ctBlock.Body, keyring, nil, nil)
	if err != nil {
		return response{Err: fmt.Sprintf("read message: %v", err)}
	}
	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return response{Err: fmt.Sprintf("read body: %v", err)}
	}
	return response{Plaintext: base64.StdEncoding.EncodeToString(plaintext)}
}

// readEntity accepts armoured or binary, as loadUserPubkeyEntity and
// loadPeerKeyForDomain respectively do.
func readEntity(key []byte) (*openpgp.Entity, error) {
	var reader io.Reader = bytes.NewReader(key)
	if bytes.HasPrefix(key, []byte("-----BEGIN PGP")) {
		block, err := armor.Decode(bytes.NewReader(key))
		if err != nil {
			return nil, fmt.Errorf("armor: %w", err)
		}
		reader = block.Body
	}
	entities, err := openpgp.ReadKeyRing(reader)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("no entities")
	}
	return entities[0], nil
}

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(v); err != nil {
		fail("encode: %v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
