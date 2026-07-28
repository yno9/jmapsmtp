// Interop helper for the Autocrypt port.
//
// Only the deterministic, byte-level rewrites are here: header injection,
// header parsing and PGP/MIME wrapping. OpenPGP encryption picks a fresh
// session key every time and cannot be compared this way.
//
// `just interop` builds this inside the oracle checkout, but these functions
// are unexported in package main, so the bodies are the Go originals copied
// verbatim — with the copy pinned by this very comparison. If go-jmapsmtp
// changes one of them, the interop test starts failing.
package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type request struct {
	Op      string `json:"op"`
	Raw     string `json:"raw"`
	From    string `json:"from"`
	KeyData string `json:"key_data"`
	Header  string `json:"header"`
}

type response struct {
	Raw     string `json:"raw,omitempty"`
	Addr    string `json:"addr,omitempty"`
	KeyData string `json:"key_data,omitempty"`
	Failed   bool `json:"failed,omitempty"`
	Panicked bool `json:"panicked,omitempty"`
}

func main() {
	var reqs []request
	if err := json.NewDecoder(os.Stdin).Decode(&reqs); err != nil {
		fail("read input: %v", err)
	}
	out := []response{}
	for _, r := range reqs {
		switch r.Op {
		case "chat_version":
			out = append(out, response{Raw: string(injectChatVersionHeader([]byte(r.Raw)))})
		case "autocrypt":
			out = append(out, response{
				Raw: string(injectAutocryptHeaderWithKey([]byte(r.Raw), r.From, r.KeyData)),
			})
		case "parse":
			addr, kd := parseAutocryptHeader(r.Header)
			out = append(out, response{Addr: addr, KeyData: kd})
		case "wrap":
			out = append(out, wrapSafely(r.Raw))
		default:
			fail("unknown op %q", r.Op)
		}
	}
	emit(out)
}

// wrapSafely calls pgpMIMEWrapInline and reports a panic instead of dying of
// one. The real relay has no such guard — sendEmail runs it in a bare
// goroutine — so a panic there takes the whole process down. Recovering here
// is only so the comparison can observe the difference. SPEC.md §11.11.
func wrapSafely(raw string) (resp response) {
	defer func() {
		if r := recover(); r != nil {
			resp = response{Panicked: true}
		}
	}()
	wrapped, err := pgpMIMEWrapInline([]byte(raw))
	if err != nil {
		return response{Failed: true}
	}
	return response{Raw: string(wrapped)}
}

// ── copied verbatim from go-jmapsmtp/autocrypt.go ─────────────────────────

func injectChatVersionHeader(raw []byte) []byte {
	if bytes.Contains(raw, []byte("\nChat-Version:")) || bytes.HasPrefix(raw, []byte("Chat-Version:")) {
		return raw
	}
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+2])
	out.WriteString("Chat-Version: 1.0\r\n")
	out.Write(raw[idx+2:])
	return out.Bytes()
}

// injectAutocryptHeaderWithKey is injectEntityAutocryptHeader with the entity
// already serialised and base64-encoded, so the helper needs no PGP key.
func injectAutocryptHeaderWithKey(raw []byte, fromEmail, pubB64 string) []byte {
	acHeader := "Autocrypt: addr=" + fromEmail + "; prefer-encrypt=mutual; keydata=" + pubB64 + "\r\n"
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	var out bytes.Buffer
	out.Write(raw[:idx+2])
	out.WriteString(acHeader)
	out.Write(raw[idx+2:])
	return out.Bytes()
}

func parseAutocryptHeader(header string) (addr, keydata string) {
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "addr":
			addr = v
		case "keydata":
			keydata = v
		}
	}
	return
}

func pgpMIMEWrapInline(rawMsg []byte) ([]byte, error) {
	sep := []byte("\r\n\r\n")
	headerEnd := bytes.Index(rawMsg, sep)
	if headerEnd < 0 {
		return nil, fmt.Errorf("no header/body separator")
	}
	origHeaders := string(rawMsg[:headerEnd])
	body := rawMsg[headerEnd+4:]

	startMarker := []byte("-----BEGIN PGP MESSAGE-----")
	endMarker := []byte("-----END PGP MESSAGE-----")
	start := bytes.Index(body, startMarker)
	end := bytes.Index(body, endMarker)
	if start < 0 || end < 0 {
		return nil, fmt.Errorf("no PGP block in body")
	}
	pgpBlock := body[start : end+len(endMarker)]

	h := sha1.Sum(pgpBlock)
	boundary := fmt.Sprintf("biset-pgp-%x", h[:6])

	var out bytes.Buffer
	for _, line := range strings.Split(origHeaders, "\r\n") {
		k := strings.ToLower(strings.SplitN(line, ":", 2)[0])
		if k == "content-type" || k == "content-transfer-encoding" {
			continue
		}
		out.WriteString(line + "\r\n")
	}
	out.WriteString(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="` + boundary + `"` + "\r\n")
	out.WriteString("\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-encrypted\r\n\r\n")
	out.WriteString("Version: 1\r\n")
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/octet-stream\r\n\r\n")
	out.Write(bytes.ReplaceAll(pgpBlock, []byte("\n"), []byte("\r\n")))
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes(), nil
}

var _ = base64.StdEncoding

func emit(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fail("encode: %v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
