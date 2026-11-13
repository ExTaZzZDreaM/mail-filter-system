package validator

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dmarc"
)

// DKIMResult is the outcome of verifying a single DKIM-Signature.
type DKIMResult struct {
	Domain string // d= tag
	Result string // pass, fail, temperror, permerror
	Err    error
}

// DMARCResult is the outcome of DMARC evaluation for the RFC5322.From domain.
type DMARCResult struct {
	Result string       // pass, fail, none, temperror, permerror
	Policy dmarc.Policy // effective policy (after sp= and pct=), set when a record was found
}

// AuthResults collects SPF, DKIM and DMARC results for one message.
type AuthResults struct {
	SPF        spf.Result
	SPFDomain  string // domain SPF was evaluated for (MAIL FROM, or HELO if MAIL FROM is empty)
	DKIM       []DKIMResult
	DMARC      DMARCResult
	FromDomain string // domain of the RFC5322.From header
}

// Checker performs sender authentication. The zero value uses the system resolver.
type Checker struct {
	// SPFResolver overrides DNS for SPF checks (used in tests).
	SPFResolver spf.DNSResolver
	// LookupTXT overrides TXT lookups for DKIM keys and DMARC records (used in tests).
	LookupTXT func(name string) ([]string, error)
	// sample returns a number in [0, 100) used for DMARC pct= sampling.
	sample func() int
}

// Authenticate runs SPF, DKIM and DMARC checks.
//   - ip:         address of the connecting SMTP client
//   - helo:       name given in HELO/EHLO
//   - mailFrom:   envelope sender (MAIL FROM), may be empty for bounces
//   - fromDomain: domain of the From header
//   - raw:        full message as received
func (c *Checker) Authenticate(ctx context.Context, ip net.IP, helo, mailFrom, fromDomain string, raw []byte) AuthResults {
	res := AuthResults{FromDomain: strings.ToLower(fromDomain)}
	res.SPF, res.SPFDomain = c.checkSPF(ctx, ip, helo, mailFrom)
	res.DKIM = c.verifyDKIM(raw)
	res.DMARC = c.evaluateDMARC(res)
	return res
}

func (c *Checker) samplePercent() int {
	if c.sample != nil {
		return c.sample()
	}
	return rand.IntN(100)
}

// Header formats the results as an Authentication-Results header value (RFC 8601).
func (r AuthResults) Header(authServID string) string {
	parts := []string{authServID}

	spfPart := "spf=" + string(r.SPF)
	if r.SPFDomain != "" {
		spfPart += " smtp.mailfrom=" + r.SPFDomain
	}
	parts = append(parts, spfPart)

	if len(r.DKIM) == 0 {
		parts = append(parts, "dkim=none")
	}
	for _, d := range r.DKIM {
		p := "dkim=" + d.Result
		if d.Domain != "" {
			p += " header.d=" + d.Domain
		}
		parts = append(parts, p)
	}

	dmarcPart := "dmarc=" + r.DMARC.Result
	if r.DMARC.Policy != "" {
		dmarcPart += fmt.Sprintf(" (p=%s)", r.DMARC.Policy)
	}
	if r.FromDomain != "" {
		dmarcPart += " header.from=" + r.FromDomain
	}
	parts = append(parts, dmarcPart)

	return strings.Join(parts, "; ")
}

// domainOf returns the lower-cased domain part of an e-mail address.
func domainOf(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	i := strings.LastIndex(addr, "@")
	if i < 0 || i == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[i+1:])
}
