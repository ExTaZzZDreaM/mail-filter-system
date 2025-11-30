package validator

import (
	"context"
	"fmt"
	"mail_server/models"
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

func Validate(mail *models.Mail) error {
	if mail.From == "" {
		return fmt.Errorf("invalid email: From address is empty")
	}

	SPFResult, err := checkSPF(context.Background(), net.ParseIP(mail.SenderIP), "asd@yandex.kz", "helo.example.com")
	if err != nil {
		fmt.Println("SPF check error:", err, "SenderIP:", mail.SenderIP, "From:", mail.From)
		return fmt.Errorf("SPF check failed")
	}

	dkimResult, err := verifyDKIM(mail.RawMessage)
	if err != nil {
		fmt.Println("DKIM check error:", err)
		return fmt.Errorf("DKIM verification failed")
	}

	domain, _ := publicsuffix.EffectiveTLDPlusOne(mail.From[strings.Index(mail.From, "@")+1:])

	dmarcPolicy, err := fetchDMARCPolicy(domain)

	if err == nil && dmarcPolicy == "reject" && (dkimResult != "pass" || SPFResult != "pass") {
		fmt.Println("DMARC policy check error:", err)
		return fmt.Errorf("DMARC policy failed")
	}

	if err := checkAbuseIP(mail.SenderIP); err != nil {
		fmt.Println("AbuseIPDB check error:", err)
		return fmt.Errorf("AbuseIPDB check failed")
	}

	if err := scanFiles(mail); err != nil {
		fmt.Println("File scan error:", err)
		return fmt.Errorf("File (virusTotal) scan failed")
	}

	return nil
}
