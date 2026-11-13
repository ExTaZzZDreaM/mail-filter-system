package validator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"mail_server/models"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dmarc"
)

// AuthServID is the authserv-id used in Authentication-Results values.
var AuthServID = "localhost"

const authTimeout = 20 * time.Second

var defaultChecker = &Checker{}

// Block reasons. They are used as quarantine group keys, so keep them stable.
var (
	ErrDMARCReject     = errors.New("DMARC failed (policy reject)")
	ErrDMARCQuarantine = errors.New("DMARC failed (policy quarantine)")
	ErrSPFFail         = errors.New("SPF failed")
)

// Validate authenticates the sender and scans the message. A non-nil error
// means the message must be quarantined; the error text is the reason.
func Validate(mail *models.Mail) error {
	if mail.From == "" {
		return fmt.Errorf("invalid email: From address is empty")
	}

	ip := net.ParseIP(mail.SenderIP)

	if isTrusted(ip) {
		mail.AuthResults = AuthServID + "; none (trusted network)"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), authTimeout)
		res := defaultChecker.Authenticate(ctx, ip, mail.Helo, mail.MailFrom, domainOf(mail.FromAddress), mail.RawMessage)
		cancel()

		mail.AuthResults = res.Header(AuthServID)
		log.Printf("Authentication-Results: %s", mail.AuthResults)

		if err := decide(res, spfFailAction()); err != nil {
			return err
		}

		if err := checkAbuseIP(mail.SenderIP); err != nil {
			log.Println("AbuseIPDB check error:", err)
			return fmt.Errorf("AbuseIPDB check failed")
		}
	}

	if err := scanFiles(mail); err != nil {
		log.Println("File scan error:", err)
		return fmt.Errorf("File (virusTotal) scan failed")
	}

	return nil
}

// decide turns authentication results into an accept (nil) or quarantine (error) decision.
//
//   - DMARC fail is enforced according to the domain's policy (p=none only monitors).
//   - DMARC pass accepts the message regardless of SPF, since an aligned DKIM signature is enough.
//   - Without an applicable DMARC result, a hard SPF fail is quarantined when
//     spfFail is "quarantine". softfail/neutral/none and temporary errors never block.
func decide(r AuthResults, spfFail string) error {
	switch r.DMARC.Result {
	case "fail":
		switch r.DMARC.Policy {
		case dmarc.PolicyReject:
			return ErrDMARCReject
		case dmarc.PolicyQuarantine:
			return ErrDMARCQuarantine
		}
		return nil
	case "pass":
		return nil
	}

	if r.SPF == spf.Fail && spfFail == "quarantine" {
		return ErrSPFFail
	}
	return nil
}

// spfFailAction reads SPF_FAIL_ACTION: "quarantine" (default) or "accept".
func spfFailAction() string {
	if strings.EqualFold(os.Getenv("SPF_FAIL_ACTION"), "accept") {
		return "accept"
	}
	return "quarantine"
}

var (
	trustedOnce sync.Once
	trustedNets []*net.IPNet
)

// isTrusted reports whether ip belongs to TRUSTED_NETWORKS (comma-separated
// CIDRs). Mail from these networks skips SPF/DKIM/DMARC and AbuseIPDB.
func isTrusted(ip net.IP) bool {
	trustedOnce.Do(func() {
		trustedNets = parseNetworks(os.Getenv("TRUSTED_NETWORKS"))
	})
	if ip == nil {
		return false
	}
	for _, n := range trustedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseNetworks(s string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			log.Printf("TRUSTED_NETWORKS: skipping invalid CIDR %q: %v", part, err)
			continue
		}
		nets = append(nets, n)
	}
	return nets
}
