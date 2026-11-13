package validator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
)

// fakeDNS serves TXT records from a map; everything else is NXDOMAIN.
type fakeDNS map[string][]string

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f fakeDNS) lookupTXT(name string) ([]string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if txt, ok := f[name]; ok {
		return txt, nil
	}
	return nil, notFound(name)
}

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.lookupTXT(name)
}
func (f fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, notFound(name)
}
func (f fakeDNS) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	return nil, notFound(name)
}
func (f fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	return nil, notFound(addr)
}

func newChecker(dns fakeDNS) *Checker {
	return &Checker{SPFResolver: dns, LookupTXT: dns.lookupTXT}
}

const testMessage = "From: Alice <alice@example.com>\r\n" +
	"To: bob@test.com\r\n" +
	"Subject: Hello\r\n" +
	"Date: Fri, 13 Nov 2026 10:00:00 +0000\r\n" +
	"Message-ID: <1@example.com>\r\n" +
	"\r\n" +
	"Hi Bob!\r\n"

// signMessage signs msg for domain with selector "sel" and registers the key in dns.
func signMessage(t *testing.T, dns fakeDNS, domain, msg string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dns["sel._domainkey."+domain] = []string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)}

	var buf bytes.Buffer
	opts := &dkim.SignOptions{
		Domain:                 domain,
		Selector:               "sel",
		Signer:                 key,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
	}
	if err := dkim.Sign(&buf, strings.NewReader(msg), opts); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckSPF(t *testing.T) {
	dns := fakeDNS{
		"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
		"soft.com":    {"v=spf1 ip4:192.0.2.0/24 ~all"},
		"inc.com":     {"v=spf1 include:example.com -all"},
		"loop.com":    {"v=spf1 include:loop.com -all"},
		"helo.com":    {"v=spf1 ip4:203.0.113.5 -all"},
	}
	c := newChecker(dns)

	cases := []struct {
		name, ip, helo, from string
		want                 spf.Result
		wantDomain           string
	}{
		{"pass", "192.0.2.10", "mx.example.com", "alice@example.com", spf.Pass, "example.com"},
		{"fail", "198.51.100.1", "mx.example.com", "alice@example.com", spf.Fail, "example.com"},
		{"softfail", "198.51.100.1", "x", "a@soft.com", spf.SoftFail, "soft.com"},
		{"include", "192.0.2.10", "x", "a@inc.com", spf.Pass, "inc.com"},
		{"include loop terminates", "198.51.100.1", "x", "a@loop.com", spf.PermError, "loop.com"},
		{"no record", "192.0.2.10", "x", "a@norecord.com", spf.None, "norecord.com"},
		{"null sender uses HELO", "203.0.113.5", "helo.com", "", spf.Pass, "helo.com"},
		{"angle brackets", "192.0.2.10", "x", "<alice@example.com>", spf.Pass, "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, domain := c.checkSPF(context.Background(), net.ParseIP(tc.ip), tc.helo, tc.from)
			if got != tc.want || domain != tc.wantDomain {
				t.Errorf("checkSPF = %s, %s; want %s, %s", got, domain, tc.want, tc.wantDomain)
			}
		})
	}
}

func TestVerifyDKIM(t *testing.T) {
	dns := fakeDNS{}
	c := newChecker(dns)
	signed := signMessage(t, dns, "example.com", testMessage)

	t.Run("valid signature", func(t *testing.T) {
		res := c.verifyDKIM(signed)
		if len(res) != 1 || res[0].Result != "pass" || res[0].Domain != "example.com" {
			t.Fatalf("got %+v, want one pass for example.com", res)
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		tampered := bytes.Replace(signed, []byte("Hi Bob!"), []byte("Pay me!"), 1)
		res := c.verifyDKIM(tampered)
		if len(res) != 1 || res[0].Result == "pass" {
			t.Fatalf("got %+v, want failure", res)
		}
	})

	t.Run("extra Received header prepended by our server", func(t *testing.T) {
		withReceived := append([]byte("Received: from mx.example.com (mx [192.0.2.10])\r\n"), signed...)
		res := c.verifyDKIM(withReceived)
		if len(res) != 1 || res[0].Result != "pass" {
			t.Fatalf("got %+v, want pass", res)
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		if res := c.verifyDKIM([]byte(testMessage)); len(res) != 0 {
			t.Fatalf("got %+v, want no results", res)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		res := newChecker(fakeDNS{}).verifyDKIM(signed)
		if len(res) != 1 || res[0].Result == "pass" {
			t.Fatalf("got %+v, want failure", res)
		}
	})
}

func TestAligned(t *testing.T) {
	cases := []struct {
		auth, from string
		mode       dmarc.AlignmentMode
		want       bool
	}{
		{"example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"mail.example.com", "example.com", dmarc.AlignmentRelaxed, true},
		{"mail.example.com", "example.com", dmarc.AlignmentStrict, false},
		{"example.co.uk", "other.co.uk", dmarc.AlignmentRelaxed, false},
		{"evil.com", "example.com", dmarc.AlignmentRelaxed, false},
		{"", "example.com", dmarc.AlignmentRelaxed, false},
		{"EXAMPLE.com", "example.COM", "", true},
	}
	for _, tc := range cases {
		if got := aligned(tc.auth, tc.from, tc.mode); got != tc.want {
			t.Errorf("aligned(%q, %q, %q) = %v; want %v", tc.auth, tc.from, tc.mode, got, tc.want)
		}
	}
}

func TestEvaluateDMARC(t *testing.T) {
	dns := fakeDNS{
		"_dmarc.example.com": {"v=DMARC1; p=reject; sp=quarantine"},
		"_dmarc.strict.com":  {"v=DMARC1; p=reject; aspf=s"},
		"_dmarc.pct.com":     {"v=DMARC1; p=reject; pct=10"},
	}
	c := newChecker(dns)
	c.sample = func() int { return 50 } // outside a 10% sample

	cases := []struct {
		name       string
		in         AuthResults
		wantResult string
		wantPolicy dmarc.Policy
	}{
		{"aligned SPF pass", AuthResults{FromDomain: "example.com", SPF: spf.Pass, SPFDomain: "example.com"}, "pass", dmarc.PolicyReject},
		{"relaxed SPF subdomain", AuthResults{FromDomain: "example.com", SPF: spf.Pass, SPFDomain: "bounce.example.com"}, "pass", dmarc.PolicyReject},
		{"strict SPF subdomain", AuthResults{FromDomain: "strict.com", SPF: spf.Pass, SPFDomain: "bounce.strict.com"}, "fail", dmarc.PolicyReject},
		{"unaligned SPF pass", AuthResults{FromDomain: "example.com", SPF: spf.Pass, SPFDomain: "evil.com"}, "fail", dmarc.PolicyReject},
		{"aligned DKIM pass", AuthResults{FromDomain: "example.com", SPF: spf.Fail, SPFDomain: "evil.com", DKIM: []DKIMResult{{Domain: "example.com", Result: "pass"}}}, "pass", dmarc.PolicyReject},
		{"unaligned DKIM pass", AuthResults{FromDomain: "example.com", DKIM: []DKIMResult{{Domain: "evil.com", Result: "pass"}}}, "fail", dmarc.PolicyReject},
		{"aligned DKIM fail", AuthResults{FromDomain: "example.com", DKIM: []DKIMResult{{Domain: "example.com", Result: "fail"}}}, "fail", dmarc.PolicyReject},
		{"subdomain uses sp=", AuthResults{FromDomain: "news.example.com"}, "fail", dmarc.PolicyQuarantine},
		{"pct downgrades", AuthResults{FromDomain: "pct.com"}, "fail", dmarc.PolicyQuarantine},
		{"no record", AuthResults{FromDomain: "nodmarc.com"}, "none", ""},
		{"no From domain", AuthResults{}, "none", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.evaluateDMARC(tc.in)
			if got.Result != tc.wantResult || got.Policy != tc.wantPolicy {
				t.Errorf("got %+v; want %s/%s", got, tc.wantResult, tc.wantPolicy)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	cases := []struct {
		name    string
		in      AuthResults
		spfFail string
		want    error
	}{
		{"DMARC reject", AuthResults{DMARC: DMARCResult{"fail", dmarc.PolicyReject}}, "quarantine", ErrDMARCReject},
		{"DMARC quarantine", AuthResults{DMARC: DMARCResult{"fail", dmarc.PolicyQuarantine}}, "quarantine", ErrDMARCQuarantine},
		{"DMARC p=none only monitors", AuthResults{SPF: spf.Fail, DMARC: DMARCResult{"fail", dmarc.PolicyNone}}, "quarantine", nil},
		{"DMARC pass overrides SPF fail", AuthResults{SPF: spf.Fail, DMARC: DMARCResult{"pass", dmarc.PolicyReject}}, "quarantine", nil},
		{"SPF fail without DMARC", AuthResults{SPF: spf.Fail, DMARC: DMARCResult{Result: "none"}}, "quarantine", ErrSPFFail},
		{"SPF fail, action accept", AuthResults{SPF: spf.Fail, DMARC: DMARCResult{Result: "none"}}, "accept", nil},
		{"SPF softfail", AuthResults{SPF: spf.SoftFail, DMARC: DMARCResult{Result: "none"}}, "quarantine", nil},
		{"SPF temperror", AuthResults{SPF: spf.TempError, DMARC: DMARCResult{Result: "temperror"}}, "quarantine", nil},
		{"nothing published", AuthResults{SPF: spf.None, DMARC: DMARCResult{Result: "none"}}, "quarantine", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(tc.in, tc.spfFail); got != tc.want {
				t.Errorf("decide = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestAuthenticateEndToEnd(t *testing.T) {
	dns := fakeDNS{
		"example.com":        {"v=spf1 ip4:192.0.2.0/24 -all"},
		"_dmarc.example.com": {"v=DMARC1; p=reject"},
	}
	c := newChecker(dns)
	signed := signMessage(t, dns, "example.com", testMessage)

	t.Run("forwarded mail keeps DKIM, passes DMARC", func(t *testing.T) {
		// Sent from an IP outside SPF (e.g. a forwarder), but the DKIM signature survives.
		res := c.Authenticate(context.Background(), net.ParseIP("198.51.100.1"), "fwd.org", "alice@example.com", "example.com", signed)
		if res.SPF != spf.Fail || res.DMARC.Result != "pass" {
			t.Fatalf("got %+v", res)
		}
		if err := decide(res, "quarantine"); err != nil {
			t.Fatalf("decide = %v; want accept", err)
		}
		want := "test.com; spf=fail smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass (p=reject) header.from=example.com"
		if h := res.Header("test.com"); h != want {
			t.Errorf("Header =\n%s\nwant\n%s", h, want)
		}
	})

	t.Run("spoofed unsigned mail is rejected", func(t *testing.T) {
		res := c.Authenticate(context.Background(), net.ParseIP("198.51.100.1"), "evil.org", "x@evil.org", "example.com", []byte(testMessage))
		if err := decide(res, "quarantine"); err != ErrDMARCReject {
			t.Fatalf("decide = %v; want %v (results %+v)", err, ErrDMARCReject, res)
		}
	})
}

func TestParseNetworks(t *testing.T) {
	nets := parseNetworks("127.0.0.0/8, ::1/128, bogus, ")
	if len(nets) != 2 {
		t.Fatalf("got %d networks, want 2", len(nets))
	}
	if !nets[0].Contains(net.ParseIP("127.0.0.1")) || !nets[1].Contains(net.ParseIP("::1")) {
		t.Fatal("parsed networks do not contain loopback addresses")
	}
}
