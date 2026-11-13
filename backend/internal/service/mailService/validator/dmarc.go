package validator

import (
	"errors"
	"log"
	"strings"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// evaluateDMARC applies DMARC (RFC 7489) to already computed SPF and DKIM results.
// DMARC passes when SPF passes for an aligned domain, or at least one DKIM
// signature passes for an aligned domain.
func (c *Checker) evaluateDMARC(r AuthResults) DMARCResult {
	if r.FromDomain == "" {
		return DMARCResult{Result: "none"}
	}

	rec, isSubdomain, err := c.lookupDMARC(r.FromDomain)
	if err != nil {
		switch {
		case errors.Is(err, dmarc.ErrNoPolicy):
			return DMARCResult{Result: "none"}
		case dmarc.IsTempFail(err):
			log.Printf("DMARC lookup for %s: %v", r.FromDomain, err)
			return DMARCResult{Result: "temperror"}
		default:
			log.Printf("DMARC lookup for %s: %v", r.FromDomain, err)
			return DMARCResult{Result: "permerror"}
		}
	}

	if r.SPF == spf.Pass && aligned(r.SPFDomain, r.FromDomain, rec.SPFAlignment) {
		return DMARCResult{Result: "pass", Policy: rec.Policy}
	}
	for _, d := range r.DKIM {
		if d.Result == "pass" && aligned(d.Domain, r.FromDomain, rec.DKIMAlignment) {
			return DMARCResult{Result: "pass", Policy: rec.Policy}
		}
	}

	return DMARCResult{Result: "fail", Policy: c.effectivePolicy(rec, isSubdomain)}
}

// lookupDMARC queries _dmarc.<domain>, falling back to the organizational
// domain. isSubdomain reports whether the fallback record was used.
func (c *Checker) lookupDMARC(domain string) (rec *dmarc.Record, isSubdomain bool, err error) {
	opts := &dmarc.LookupOptions{LookupTXT: c.LookupTXT}

	rec, err = dmarc.LookupWithOptions(domain, opts)
	if errors.Is(err, dmarc.ErrNoPolicy) {
		if org := orgDomain(domain); org != domain {
			rec, err = dmarc.LookupWithOptions(org, opts)
			isSubdomain = true
		}
	}
	return rec, isSubdomain, err
}

// effectivePolicy applies sp= for subdomains and pct= sampling: when a message
// is not sampled, the policy is downgraded one step (RFC 7489 section 6.6.4).
func (c *Checker) effectivePolicy(rec *dmarc.Record, isSubdomain bool) dmarc.Policy {
	p := rec.Policy
	if isSubdomain && rec.SubdomainPolicy != "" {
		p = rec.SubdomainPolicy
	}

	if rec.Percent != nil && *rec.Percent < 100 && c.samplePercent() >= *rec.Percent {
		switch p {
		case dmarc.PolicyReject:
			p = dmarc.PolicyQuarantine
		case dmarc.PolicyQuarantine:
			p = dmarc.PolicyNone
		}
	}
	return p
}

// aligned checks identifier alignment between an authenticated domain and the
// From domain. Relaxed mode (the default) compares organizational domains.
func aligned(authDomain, fromDomain string, mode dmarc.AlignmentMode) bool {
	authDomain = strings.ToLower(authDomain)
	fromDomain = strings.ToLower(fromDomain)
	if authDomain == "" || fromDomain == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return authDomain == fromDomain
	}
	return orgDomain(authDomain) == orgDomain(fromDomain)
}

// orgDomain returns the organizational domain (public suffix + 1 label).
func orgDomain(domain string) string {
	org, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return domain
	}
	return org
}
