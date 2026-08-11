// Interop helper for the MIME port.
//
// Reads its input as JSON on stdin and prints what the real go-jmapserver MIME
// functions make of it. `just interop` builds this inside the oracle checkout
// so it links those functions rather than a reimplementation.
//
//	parse   ParseMIMEEmail + MessageBody + ExtractAttachments over raw messages
//	build   BuildRFC5322 + BuildEnvelope over Email objects
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"git.sr.ht/~rockorager/go-jmap/mail/email"
	jmapserver "github.com/yno9/go-jmapserver"
)

type parsed struct {
	Err         string           `json:"err,omitempty"`
	Email       json.RawMessage  `json:"email,omitempty"`
	Body        string           `json:"body"`
	Attachments []attachmentJSON `json:"attachments"`
}

type attachmentJSON struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Bytes       string `json:"bytes"`
}

type built struct {
	Raw      string          `json:"raw"`
	MsgID    string          `json:"msg_id"`
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: mime-interop parse|build")
	}
	switch os.Args[1] {
	case "parse":
		doParse()
	case "build":
		doBuild()
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func doParse() {
	var inputs []string
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		fail("read input: %v", err)
	}
	out := []parsed{}
	for _, b64 := range inputs {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			fail("bad base64: %v", err)
		}
		p := parsed{Attachments: []attachmentJSON{}}
		m, err := jmapserver.ParseMIMEEmail(raw)
		if err != nil {
			p.Err = err.Error()
			out = append(out, p)
			continue
		}
		// receivedAt falls back to time.Now() when the Date header is absent
		// or unparseable, which no comparison could survive. Dropped on both
		// sides; the Date-derived case is checked separately.
		m.ReceivedAt = nil
		b, mErr := json.Marshal(m)
		if mErr != nil {
			fail("marshal: %v", mErr)
		}
		p.Email = b
		p.Body = jmapserver.MessageBody(m)
		for _, a := range jmapserver.ExtractAttachments(raw) {
			p.Attachments = append(p.Attachments, attachmentJSON{
				Filename:    a.Filename,
				ContentType: a.ContentType,
				Bytes:       base64.StdEncoding.EncodeToString(a.Bytes),
			})
		}
		out = append(out, p)
	}
	emit(out)
}

// buildInput pairs an Email with the default domain BuildRFC5322 takes.
type buildInput struct {
	Email  email.Email `json:"email"`
	Domain string      `json:"domain"`
}

func doBuild() {
	var inputs []buildInput
	if err := json.NewDecoder(os.Stdin).Decode(&inputs); err != nil {
		fail("read input: %v", err)
	}
	out := []built{}
	for _, in := range inputs {
		raw, msgID := jmapserver.BuildRFC5322(in.Email, in.Domain)
		b := built{Raw: string(raw), MsgID: msgID}
		if env := jmapserver.BuildEnvelope(in.Email); env != nil {
			j, err := json.Marshal(env)
			if err != nil {
				fail("marshal envelope: %v", err)
			}
			b.Envelope = j
		}
		out = append(out, b)
	}
	emit(out)
}

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
