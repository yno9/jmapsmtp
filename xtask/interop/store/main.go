// Interop helper for the Store port.
//
// `just interop` copies this into the oracle checkout and builds it there, so
// it links the REAL go-jmapserver Store rather than a reimplementation. The
// Rust side (crates/jmapserver/tests/store_interop.rs) drives it to check
// that a data directory written by either implementation loads in the other.
//
//	seed <dir>   populate <dir> with a known set of messages and state
//	dump <dir>   open <dir> and print what the Go Store sees, as JSON
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	jmapserver "github.com/yno9/go-jmapserver"
)

// dump is what both implementations report, so the two can be compared
// directly. Everything here is deterministic: All() is sorted by the store,
// and the remaining fields are counters.
type dump struct {
	State           string         `json:"state"`
	MailboxState    string         `json:"mailbox_state"`
	SubmissionState string         `json:"submission_state"`
	Messages        []dumpMessage  `json:"messages"`
	Mailboxes       []jmap.ID      `json:"mailboxes"`
	Submissions     []string       `json:"submissions"`
	Identities      []string       `json:"identities"`
}

// A projection of Email rather than the whole thing: these are the fields the
// store itself is responsible for, and comparing them isolates a store bug
// from a serialisation bug (which the jmap-types tests already cover).
type dumpMessage struct {
	ID         jmap.ID  `json:"id"`
	ThreadID   jmap.ID  `json:"thread_id"`
	Subject    string   `json:"subject"`
	ReceivedAt string   `json:"received_at"`
	Keywords   []string `json:"keywords"`
	MailboxIDs []string `json:"mailbox_ids"`
	MessageID  []string `json:"message_id"`
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: store-interop seed|dump <dir>")
	}
	switch os.Args[1] {
	case "seed":
		seed(os.Args[2])
	case "dump":
		emit(dumpStore(os.Args[2]))
	default:
		fail("unknown command %q", os.Args[1])
	}
}

// seed writes a fixed corpus, chosen to exercise the parts of the store that
// have any state to get wrong: threading by reply chain, threading by group
// header, a message with no timestamp, ids needing filename escaping,
// keywords, mailbox membership, and a submission record.
func seed(dir string) {
	store, err := jmapserver.NewStore(dir)
	if err != nil {
		fail("NewStore: %v", err)
	}

	at := func(s string) *time.Time {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			fail("parse %q: %v", s, err)
		}
		return &t
	}

	msgs := []email.Email{
		{
			ID: "msg-parent", MessageID: []string{"parent@x"},
			Subject: "parent", ReceivedAt: at("2026-07-01T00:00:00Z"),
			From:       []*mail.Address{{Name: "A", Email: "a@x"}},
			MailboxIDs: map[jmap.ID]bool{"mbx-inbox": true},
			Keywords:   map[string]bool{"$seen": true},
		},
		{
			// Joins msg-parent's thread; brackets must be stripped to match.
			ID: "msg-reply", MessageID: []string{"reply@x"},
			InReplyTo: []string{"<parent@x>"},
			Subject:   "reply", ReceivedAt: at("2026-07-02T00:00:00Z"),
			MailboxIDs: map[jmap.ID]bool{"mbx-inbox": true},
		},
		{
			// A group header short-circuits the reply walk entirely.
			ID: "msg-group", MessageID: []string{"group@x"},
			InReplyTo: []string{"<parent@x>"},
			Headers:   []*email.Header{{Name: "Chat-Group-Id", Value: "grp1"}},
			Subject:   "group", ReceivedAt: at("2026-07-03T00:00:00Z"),
		},
		{
			// No timestamp: must sort last on both sides.
			ID: "msg-undated", MessageID: []string{"undated@x"}, Subject: "undated",
		},
		{
			// Every character safeFilename rewrites, plus a local offset.
			ID: `msg-a/b\c:d*e?f"g<h>i|j`, Subject: "escaped",
			ReceivedAt: at("2026-07-04T12:00:00+09:00"),
		},
	}
	for _, m := range msgs {
		if err := store.Put(m); err != nil {
			fail("Put %s: %v", m.ID, err)
		}
	}

	// A patch, so the change log holds an Updated record as well as Addeds.
	if err := store.PatchEmail("msg-parent", map[string]any{
		"keywords/$flagged": true,
		"mailboxIds/mbx-archive": true,
	}); err != nil {
		fail("PatchEmail: %v", err)
	}

	if err := store.SyncMailboxes([]mailbox.Mailbox{
		{ID: "mbx-inbox", Name: "Inbox", Role: mailbox.RoleInbox, IsSubscribed: true},
		{ID: "mbx-archive", Name: "Archive", Role: mailbox.RoleArchive},
	}); err != nil {
		fail("SyncMailboxes: %v", err)
	}

	store.AddSubmission(map[string]any{"id": "sub-1", "emailId": "msg-parent"})
}

func dumpStore(dir string) dump {
	store, err := jmapserver.NewStore(dir)
	if err != nil {
		fail("NewStore: %v", err)
	}
	d := dump{
		State:           store.State(),
		MailboxState:    store.MailboxState(),
		SubmissionState: store.SubmissionState(),
		Messages:        []dumpMessage{},
		Mailboxes:       []jmap.ID{},
		Submissions:     []string{},
		Identities:      []string{},
	}
	for _, m := range store.All() {
		d.Messages = append(d.Messages, dumpMessage{
			ID: m.ID, ThreadID: m.ThreadID, Subject: m.Subject,
			ReceivedAt: formatTime(m.ReceivedAt),
			Keywords:   sortedTrueKeys(m.Keywords),
			MailboxIDs: sortedTrueIDs(m.MailboxIDs),
			MessageID:  m.MessageID,
		})
	}
	for _, mb := range store.Mailboxes() {
		d.Mailboxes = append(d.Mailboxes, mb.ID)
	}
	for _, s := range store.Submissions() {
		b, _ := json.Marshal(s)
		d.Submissions = append(d.Submissions, string(b))
	}
	return d
}

// formatTime reuses encoding/json's own rendering, so the string compared
// against Rust is exactly what would land in a message file.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	b, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(b[1 : len(b)-1]) // strip the surrounding quotes
}

// Only the true entries, sorted — a false entry means "not in this set", and
// Go's map order is not stable enough to compare raw.
func sortedTrueKeys(m map[string]bool) []string {
	out := []string{}
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sortStrings(out)
	return out
}

func sortedTrueIDs(m map[jmap.ID]bool) []string {
	out := []string{}
	for k, v := range m {
		if v {
			out = append(out, string(k))
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
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
