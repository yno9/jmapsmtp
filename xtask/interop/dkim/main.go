// Interop helper for the DKIM port.
//
// A DKIM signature's whole job is to verify somewhere else, so that is what
// this checks: each implementation signs, the other verifies. Byte-identical
// output is neither required nor achievable — the signature covers a t=
// timestamp taken from the signer's clock.
//
//	sign     read {key_pem, domain, selector, message} and print the signed message
//	verify   read a signed message and report whether go-msgauth accepts it
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

type signRequest struct {
	KeyPEM   string `json:"key_pem"`
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	Message  string `json:"message"`
}

type signResponse struct {
	Signed string `json:"signed,omitempty"`
	Err    string `json:"err,omitempty"`
}

type verifyResponse struct {
	OK     bool   `json:"ok"`
	Domain string `json:"domain,omitempty"`
	Err    string `json:"err,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: dkim-interop sign|verify")
	}
	switch os.Args[1] {
	case "sign":
		doSign()
	case "verify":
		doVerify()
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func doSign() {
	var reqs []signRequest
	if err := json.NewDecoder(os.Stdin).Decode(&reqs); err != nil {
		fail("read input: %v", err)
	}
	out := []signResponse{}
	for _, r := range reqs {
		key, err := parseKey(r.KeyPEM)
		if err != nil {
			out = append(out, signResponse{Err: err.Error()})
			continue
		}
		opts := &dkim.SignOptions{
			Domain:                 r.Domain,
			Selector:               r.Selector,
			Signer:                 key,
			HeaderCanonicalization: dkim.CanonicalizationRelaxed,
			BodyCanonicalization:   dkim.CanonicalizationRelaxed,
			HeaderKeys: []string{
				"From", "To", "Cc", "Subject", "Date", "Message-Id", "Content-Type",
			},
		}
		var buf bytes.Buffer
		if err := dkim.Sign(&buf, strings.NewReader(r.Message), opts); err != nil {
			out = append(out, signResponse{Err: err.Error()})
			continue
		}
		out = append(out, signResponse{Signed: buf.String()})
	}
	emit(out)
}

// verifyRequest carries the public key inline: dkim.Verify normally resolves
// it from DNS, which a test cannot do, so a fixed resolver is installed.
type verifyRequest struct {
	Message string `json:"message"`
	Record  string `json:"record"`
	Domain  string `json:"domain"`
	Selector string `json:"selector"`
}

func doVerify() {
	var reqs []verifyRequest
	if err := json.NewDecoder(os.Stdin).Decode(&reqs); err != nil {
		fail("read input: %v", err)
	}
	out := []verifyResponse{}
	for _, r := range reqs {
		opts := &dkim.VerifyOptions{
			LookupTXT: func(domain string) ([]string, error) {
				want := r.Selector + "._domainkey." + r.Domain
				if domain != want {
					return nil, fmt.Errorf("unexpected lookup %q", domain)
				}
				return []string{r.Record}, nil
			},
		}
		verifications, err := dkim.VerifyWithOptions(strings.NewReader(r.Message), opts)
		if err != nil {
			out = append(out, verifyResponse{Err: err.Error()})
			continue
		}
		if len(verifications) == 0 {
			out = append(out, verifyResponse{Err: "no signature found"})
			continue
		}
		v := verifications[0]
		resp := verifyResponse{OK: v.Err == nil, Domain: v.Domain}
		if v.Err != nil {
			resp.Err = v.Err.Error()
		}
		out = append(out, resp)
	}
	emit(out)
}

func parseKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA key")
	}
	return rk, nil
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
