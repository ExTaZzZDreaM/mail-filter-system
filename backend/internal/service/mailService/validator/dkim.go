package validator

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

func verifyDKIM(rawMessage []byte) (string, error) {
	headers, body, err := parseRawMessage(rawMessage)
	if err != nil {
		return "none", fmt.Errorf("parse raw message: %w", err)
	}

	dkimSig, err := extractDKIMSignature(headers)
	if err != nil {
		return "none", nil // No DKIM-Signature header
	}

	sigFields, err := parseDKIMFields(dkimSig)
	if err != nil {
		return "none", fmt.Errorf("parse DKIM-Signature: %w", err)
	}

	pubKey, err := fetchDKIMPublicKey(context.Background(), sigFields["s"], sigFields["d"])
	if err != nil {
		return "fail", fmt.Errorf("fetch public key: %w", err)
	}

	canonicalizedHeaders, err := canonicalizeHeaders(headers, sigFields["h"], sigFields["c"])
	if err != nil {
		return "fail", fmt.Errorf("canonicalize headers: %w", err)
	}
	canonicalizedBody, err := canonicalizeBody(body, sigFields["c"])
	if err != nil {
		return "fail", fmt.Errorf("canonicalize body: %w", err)
	}

	hashAlgo := crypto.SHA256
	if sigFields["a"] != "rsa-sha256" {
		return "fail", fmt.Errorf("unsupported DKIM algorithm: %s", sigFields["a"])
	}
	hash := sha256.New()
	hash.Write(canonicalizedHeaders)
	hash.Write(canonicalizedBody)
	hashed := hash.Sum(nil)

	signature, err := base64.StdEncoding.DecodeString(sigFields["b"])
	if err != nil {
		return "fail", fmt.Errorf("decode signature: %w", err)
	}

	err = rsa.VerifyPKCS1v15(pubKey, hashAlgo, hashed, signature)
	if err != nil {
		return "fail", fmt.Errorf("signature verification failed: %w", err)
	}

	return "pass", nil
}

func parseRawMessage(rawMessage []byte) (map[string][]string, []byte, error) {
	parts := bytes.SplitN(rawMessage, []byte("\r\n\r\n"), 2)
	if len(parts) < 1 {
		return nil, nil, fmt.Errorf("invalid email format")
	}
	headerLines := strings.Split(string(parts[0]), "\r\n")
	headers := make(map[string][]string)
	var currentHeader string

	for _, line := range headerLines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentHeader != "" {
				headers[currentHeader][len(headers[currentHeader])-1] += " " + strings.TrimSpace(line)
			}
			continue
		}
		colonIndex := strings.Index(line, ":")
		if colonIndex == -1 {
			continue
		}
		name := strings.TrimSpace(line[:colonIndex])
		value := strings.TrimSpace(line[colonIndex+1:])
		headers[name] = append(headers[name], value)
		currentHeader = name
	}

	body := []byte{}
	if len(parts) > 1 {
		body = parts[1]
	}
	return headers, body, nil
}

func extractDKIMSignature(headers map[string][]string) (string, error) {
	for _, sig := range headers["DKIM-Signature"] {
		return sig, nil
	}
	return "", fmt.Errorf("no DKIM-Signature header found")
}

func parseDKIMFields(sig string) (map[string]string, error) {
	fields := make(map[string]string)
	parts := strings.Split(sig, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid DKIM-Signature field: %s", part)
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		fields[key] = value
	}
	if fields["v"] != "1" || fields["s"] == "" || fields["d"] == "" || fields["b"] == "" {
		return nil, fmt.Errorf("missing or invalid required DKIM fields")
	}
	return fields, nil
}

func fetchDKIMPublicKey(ctx context.Context, selector, domain string) (*rsa.PublicKey, error) {
	resolver := &net.Resolver{}
	txtRecords, err := resolver.LookupTXT(ctx, selector+"._domainkey."+domain)
	if err != nil {
		return nil, fmt.Errorf("DNS TXT lookup for %s._domainkey.%s: %w", selector, domain, err)
	}

	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DKIM1;") {
			key := extractPublicKey(record)
			if key == "" {
				continue
			}
			der, err := base64.StdEncoding.DecodeString(key)
			if err != nil {
				return nil, fmt.Errorf("decode public key: %w", err)
			}
			pubKey, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return nil, fmt.Errorf("parse public key: %w", err)
			}
			rsaKey, ok := pubKey.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("public key is not RSA")
			}
			return rsaKey, nil
		}
	}
	return nil, fmt.Errorf("no valid DKIM public key found")
}

func extractPublicKey(record string) string {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return part[2:]
		}
	}
	return ""
}

func canonicalizeHeaders(headers map[string][]string, signedHeaders, canonicalization string) ([]byte, error) {
	hFields := strings.Split(signedHeaders, ":")
	var canonicalized []string
	for _, h := range hFields {
		h = strings.TrimSpace(h)
		if values, ok := headers[h]; ok {
			for _, v := range values {
				if canonicalization == "relaxed" {
					h = strings.ToLower(h)
					v = strings.Join(strings.Fields(v), " ")
				}
				canonicalized = append(canonicalized, fmt.Sprintf("%s:%s", h, v))
			}
		}
	}
	if dkimValues, ok := headers["DKIM-Signature"]; ok {
		for _, v := range dkimValues {
			if canonicalization == "relaxed" {
				v = strings.Join(strings.Fields(v), " ")
			}
			sigParts := strings.Split(v, ";")
			var cleanedParts []string
			for _, part := range sigParts {
				if !strings.HasPrefix(strings.TrimSpace(part), "b=") {
					cleanedParts = append(cleanedParts, part)
				}
			}
			cleanedSig := strings.Join(cleanedParts, ";")
			canonicalized = append(canonicalized, fmt.Sprintf("dkim-signature:%s", cleanedSig))
		}
	}
	return []byte(strings.Join(canonicalized, "\r\n") + "\r\n"), nil
}

func canonicalizeBody(body []byte, canonicalization string) ([]byte, error) {
	if canonicalization == "relaxed" {
		lines := strings.Split(string(body), "\r\n")
		var cleaned []string
		for _, line := range lines {
			line = strings.TrimRight(line, " \t")
			if line != "" {
				cleaned = append(cleaned, line)
			}
		}
		body = []byte(strings.Join(cleaned, "\r\n"))
	}
	if !bytes.HasSuffix(body, []byte("\r\n")) {
		body = append(body, '\r', '\n')
	}
	return body, nil
}
