// Interop helper for the SMTP port.
//
// Drives `net/smtp` — the exact client go-jmapsmtp's smtpSend uses — against
// whatever server is listening, and reports what happened. Pointing it at the
// Rust server is the check that matters: mail this relay receives arrives
// from clients like this one.
//
//	send <host:port>   read {from, rcpts, message} from stdin and deliver it
//	probe <host:port>  connect, EHLO, and report the advertised extensions
//	serve <host:port>  run a go-smtp server with the relay's own options and
//	                   print what one message delivered to it looked like
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"

	gosmtp "github.com/emersion/go-smtp"
)

// smtp refers to net/smtp for the client half and go-smtp for the server
// half; the alias keeps the copied smtpSend body reading like the original.
type _ = gosmtp.Server

type sendRequest struct {
	From    string   `json:"from"`
	Rcpts   []string `json:"rcpts"`
	Message string   `json:"message"`
	// Helo is what the client announces; the relay sends its own hostname.
	Helo string `json:"helo"`
}

type sendResponse struct {
	OK       bool     `json:"ok"`
	Err      string   `json:"err,omitempty"`
	Rejected []string `json:"rejected,omitempty"`
}

type probeResponse struct {
	Greeting   string   `json:"greeting"`
	Extensions []string `json:"extensions"`
	Err        string   `json:"err,omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: smtp-interop send|probe <host:port>")
	}
	switch os.Args[1] {
	case "send":
		doSend(os.Args[2])
	case "probe":
		doProbe(os.Args[2])
	case "serve":
		doServe(os.Args[2])
	default:
		fail("unknown command %q", os.Args[1])
	}
}

// doSend mirrors smtpSend in go-jmapsmtp/main.go step for step, including its
// habit of logging a rejected RCPT and carrying on rather than aborting.
func doSend(target string) {
	var req sendRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fail("read input: %v", err)
	}

	resp := sendResponse{Rejected: []string{}}
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		emit(sendResponse{Err: fmt.Sprintf("dial: %v", err)})
		return
	}
	c, err := smtp.NewClient(conn, strings.SplitN(target, ":", 2)[0])
	if err != nil {
		emit(sendResponse{Err: err.Error()})
		return
	}
	defer c.Close()

	if err := c.Hello(req.Helo); err != nil {
		emit(sendResponse{Err: fmt.Sprintf("EHLO: %v", err)})
		return
	}
	if err := c.Mail(req.From); err != nil {
		emit(sendResponse{Err: fmt.Sprintf("MAIL FROM: %v", err)})
		return
	}
	for _, addr := range req.Rcpts {
		if err := c.Rcpt(addr); err != nil {
			resp.Rejected = append(resp.Rejected, addr)
		}
	}
	w, err := c.Data()
	if err != nil {
		emit(sendResponse{Err: fmt.Sprintf("DATA: %v", err)})
		return
	}
	if _, err := w.Write([]byte(req.Message)); err != nil {
		emit(sendResponse{Err: fmt.Sprintf("write body: %v", err)})
		return
	}
	if err := w.Close(); err != nil {
		emit(sendResponse{Err: fmt.Sprintf("end DATA: %v", err)})
		return
	}
	c.Quit()
	resp.OK = true
	emit(resp)
}

func doProbe(target string) {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		emit(probeResponse{Err: fmt.Sprintf("dial: %v", err)})
		return
	}
	defer conn.Close()

	// net/smtp swallows the greeting, so it is read directly to compare it.
	greeting := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(greeting)
	if err != nil {
		emit(probeResponse{Err: fmt.Sprintf("greeting: %v", err)})
		return
	}
	resp := probeResponse{
		Greeting:   strings.TrimRight(string(greeting[:n]), "\r\n"),
		Extensions: []string{},
	}

	// Re-dial for the EHLO, since the greeting has already been consumed.
	conn2, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		emit(probeResponse{Err: fmt.Sprintf("dial: %v", err)})
		return
	}
	defer conn2.Close()
	c, err := smtp.NewClient(conn2, strings.SplitN(target, ":", 2)[0])
	if err != nil {
		resp.Err = err.Error()
		emit(resp)
		return
	}
	defer c.Close()
	if err := c.Hello("interop.test"); err != nil {
		resp.Err = fmt.Sprintf("EHLO: %v", err)
		emit(resp)
		return
	}
	for _, ext := range []string{
		"PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES", "CHUNKING",
		"STARTTLS", "SMTPUTF8", "SIZE", "AUTH", "DSN", "BINARYMIME",
	} {
		if ok, _ := c.Extension(ext); ok {
			resp.Extensions = append(resp.Extensions, ext)
		}
	}
	sort.Strings(resp.Extensions)
	c.Quit()
	emit(resp)
}

// received is what one delivery looked like from the server's side.
type received struct {
	From    string   `json:"from"`
	Rcpts   []string `json:"rcpts"`
	Message string   `json:"message"`
	Err     string   `json:"err,omitempty"`
}

// serveBackend accepts everything and hands the first message to a channel.
type serveBackend struct{ done chan received }

func (b *serveBackend) NewSession(*gosmtp.Conn) (gosmtp.Session, error) {
	return &serveSession{backend: b, rcpts: []string{}}, nil
}

type serveSession struct {
	backend *serveBackend
	from    string
	rcpts   []string
}

func (s *serveSession) Mail(from string, _ *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

// One address is rejected on purpose, so the Rust client's "log the rejection
// and carry on" behaviour is exercised rather than assumed.
func (s *serveSession) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	if strings.HasPrefix(strings.ToLower(to), "reject@") {
		return &gosmtp.SMTPError{Code: 550, Message: "No such user here"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *serveSession) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.backend.done <- received{From: s.from, Rcpts: s.rcpts, Message: string(raw)}
	return nil
}

func (s *serveSession) Reset()        { s.from = ""; s.rcpts = []string{} }
func (s *serveSession) Logout() error { return nil }

// doServe mirrors startSMTP's server options, minus TLS: the point is to make
// the real go-smtp server judge what the Rust client sends.
func doServe(addr string) {
	backend := &serveBackend{done: make(chan received, 1)}
	srv := gosmtp.NewServer(backend)
	srv.Addr = addr
	srv.Domain = "go.example.com"
	srv.AllowInsecureAuth = true
	srv.EnableSMTPUTF8 = true
	srv.ReadTimeout = 30 * time.Second
	srv.WriteTimeout = 30 * time.Second

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		emit(received{Err: fmt.Sprintf("listen: %v", err)})
		return
	}
	// The chosen port goes out first so the caller knows where to connect.
	fmt.Fprintf(os.Stderr, "listening %s\n", ln.Addr().String())
	go srv.Serve(ln) //nolint:errcheck

	select {
	case r := <-backend.done:
		emit(r)
	case <-time.After(30 * time.Second):
		emit(received{Err: "timed out waiting for a message"})
	}
	ln.Close()
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
