package validator

import (
	"context"
	"log"
	"net"
	"strings"

	"blitiri.com.ar/go/spf"
)

// checkSPF evaluates SPF (RFC 7208) for the envelope sender, falling back to
// the HELO name when MAIL FROM is empty. It returns the result and the domain
// that was checked.
func (c *Checker) checkSPF(ctx context.Context, ip net.IP, helo, mailFrom string) (spf.Result, string) {
	if ip == nil {
		return spf.None, ""
	}

	helo = strings.ToLower(strings.TrimSpace(helo))
	mailFrom = strings.Trim(strings.TrimSpace(mailFrom), "<>")

	domain := domainOf(mailFrom)
	if domain == "" {
		domain = helo
	}
	if domain == "" {
		return spf.None, ""
	}

	opts := []spf.Option{spf.WithContext(ctx)}
	if c.SPFResolver != nil {
		opts = append(opts, spf.WithResolver(c.SPFResolver))
	}

	res, err := spf.CheckHostWithSender(ip, helo, mailFrom, opts...)
	if err != nil && res != spf.Pass {
		log.Printf("SPF %s for %s from %s: %v", res, domain, ip, err)
	}
	return res, domain
}
