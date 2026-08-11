// Interop helper for the cryptenv port.
//
// `just interop` copies this into the oracle checkout and builds it there, so
// it links the REAL Go cryptenv package rather than a reimplementation of it.
// The Rust side (crates/cryptenv/tests/interop.rs) drives it to check that an
// envelope sealed by either implementation opens in the other and yields
// byte-identical derived keys.
//
//	gen <password> <t> <m> <p>   envelope JSON + derived keys, on stdout
//	unseal <password>            envelope JSON on stdin, derived keys on stdout
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/yno9/go-jmap-smtp/cryptenv"
)

type result struct {
	Envelope json.RawMessage `json:"envelope,omitempty"`
	Auth     string          `json:"auth"`
	KEK      string          `json:"kek"`
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: cryptenv-interop gen <password> <t> <m> <p> | unseal <password>")
	}
	switch os.Args[1] {
	case "gen":
		gen()
	case "unseal":
		unseal()
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func gen() {
	if len(os.Args) != 6 {
		fail("gen needs <password> <t> <m> <p>")
	}
	t, m, p := atoi(os.Args[3]), atoi(os.Args[4]), atoi(os.Args[5])

	// DefaultKDF is a package-level var, and NewEnvelope reads it rather than
	// taking parameters — the same knob the Go tests turn in fastEnv.
	prev := cryptenv.DefaultKDF
	cryptenv.DefaultKDF = cryptenv.KDFParams{
		Time: uint32(t), Memory: uint32(m), Threads: uint8(p),
	}
	defer func() { cryptenv.DefaultKDF = prev }()

	env, auth, kek, err := cryptenv.NewEnvelope(os.Args[2])
	if err != nil {
		fail("NewEnvelope: %v", err)
	}
	b, err := env.Bytes()
	if err != nil {
		fail("Bytes: %v", err)
	}
	emit(result{Envelope: b, Auth: b64(auth), KEK: b64(kek)})
}

func unseal() {
	if len(os.Args) != 3 {
		fail("unseal needs <password>")
	}
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}
	env, err := cryptenv.FromBytes(body)
	if err != nil {
		fail("FromBytes: %v", err)
	}
	auth, kek, err := env.Unseal(os.Args[2])
	if err != nil {
		fail("Unseal: %v", err)
	}
	emit(result{Auth: b64(auth), KEK: b64(kek)})
}

func emit(r result) {
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fail("encode: %v", err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		fail("not a number: %q", s)
	}
	return n
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
