package validator

import (
	"net"
	"strings"
)

func fetchDMARCPolicy(domain string) (string, error) {
	records, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		return "", err
	}
	for _, record := range records {
		if strings.Contains(record, "v=DMARC1") {
			if strings.Contains(record, "p=reject") {
				return "reject", nil
			}
		}
	}
	return "pass", nil
}
