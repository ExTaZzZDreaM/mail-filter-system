package validator

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type SPFResult string

const (
	SPFResultPass      SPFResult = "pass"
	SPFResultFail      SPFResult = "fail"
	SPFResultSoftFail  SPFResult = "softfail"
	SPFResultNeutral   SPFResult = "neutral"
	SPFResultNone      SPFResult = "none"
	SPFResultPermError SPFResult = "permerror"
	SPFResultTempError SPFResult = "temperror"
)

func checkSPF(ctx context.Context, ip net.IP, email, helo string) (SPFResult, error) {
	domain, err := extractDomain(email)
	if err != nil {
		return SPFResultNone, fmt.Errorf("invalid email format: %w", err)
	}

	spfRecord, err := lookupSPFRecord(ctx, domain)
	if err != nil {
		if strings.Contains(err.Error(), "no SPF record") {
			return SPFResultNone, nil
		}
		return SPFResultTempError, fmt.Errorf("DNS lookup failed: %w", err)
	}

	return evaluateSPF(ctx, spfRecord, ip, domain, helo)
}

func extractDomain(email string) (string, error) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("invalid email address: %s", email)
	}
	return strings.ToLower(parts[1]), nil
}

func lookupSPFRecord(ctx context.Context, domain string) (string, error) {
	resolver := &net.Resolver{}
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("TXT lookup for %s: %w", domain, err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1 ") {
			return record, nil
		}
	}
	return "", fmt.Errorf("no SPF record found for %s", domain)
}

func evaluateSPF(ctx context.Context, spfRecord string, ip net.IP, domain, helo string) (SPFResult, error) {
	parts := strings.Fields(spfRecord)
	if len(parts) < 1 || parts[0] != "v=spf1" {
		return SPFResultPermError, fmt.Errorf("invalid SPF record: %s", spfRecord)
	}

	defaultResult := SPFResultNeutral

	for _, part := range parts[1:] {
		qualifier := "+"
		if strings.HasPrefix(part, "+") || strings.HasPrefix(part, "-") || strings.HasPrefix(part, "~") || strings.HasPrefix(part, "?") {
			qualifier = part[:1]
			part = part[1:]
		}

		switch {
		case strings.HasPrefix(part, "ip4:"):
			if matchIP4(part[4:], ip) {
				return qualifierToResult(qualifier), nil
			}
		case strings.HasPrefix(part, "ip6:"):
			if matchIP6(part[4:], ip) {
				return qualifierToResult(qualifier), nil
			}
		case strings.HasPrefix(part, "a"):
			if matchA(ctx, domain, part, ip) {
				return qualifierToResult(qualifier), nil
			}
		case strings.HasPrefix(part, "mx"):
			if matchMX(ctx, domain, part, ip) {
				return qualifierToResult(qualifier), nil
			}
		case strings.HasPrefix(part, "include:"):
			includedDomain := part[8:]
			includedRecord, err := lookupSPFRecord(ctx, includedDomain)
			if err == nil {
				result, err := evaluateSPF(ctx, includedRecord, ip, includedDomain, helo)
				if err == nil && result != SPFResultNeutral {
					return result, nil
				}
			}
		case part == "all":
			return qualifierToResult(qualifier), nil
		}
	}

	return defaultResult, nil
}

func matchIP4(cidr string, ip net.IP) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

func matchIP6(cidr string, ip net.IP) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

func matchA(ctx context.Context, domain, mechanism string, ip net.IP) bool {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return false
	}
	for _, recordIP := range ips {
		if recordIP.Equal(ip) {
			return true
		}
	}
	return false
}

func matchMX(ctx context.Context, domain, mechanism string, ip net.IP) bool {
	resolver := &net.Resolver{}
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}
	for _, mx := range mxRecords {
		ips, err := resolver.LookupIP(ctx, "ip", mx.Host)
		if err != nil {
			continue
		}
		for _, recordIP := range ips {
			if recordIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func qualifierToResult(qualifier string) SPFResult {
	switch qualifier {
	case "+":
		return SPFResultPass
	case "-":
		return SPFResultFail
	case "~":
		return SPFResultSoftFail
	case "?":
		return SPFResultNeutral
	default:
		return SPFResultNeutral
	}
}
