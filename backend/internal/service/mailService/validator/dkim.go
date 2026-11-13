package validator

import (
	"bytes"
	"errors"
	"log"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

// maxDKIMSignatures limits work spent on messages with many signatures.
const maxDKIMSignatures = 5

// verifyDKIM verifies every DKIM-Signature in the message (RFC 6376).
// A message without signatures yields an empty slice.
func (c *Checker) verifyDKIM(raw []byte) []DKIMResult {
	opts := &dkim.VerifyOptions{
		LookupTXT:        c.LookupTXT,
		MaxVerifications: maxDKIMSignatures,
	}

	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(raw), opts)
	if err != nil && !errors.Is(err, dkim.ErrTooManySignatures) {
		log.Printf("DKIM verification error: %v", err)
		return []DKIMResult{{Result: "permerror", Err: err}}
	}

	results := make([]DKIMResult, 0, len(verifications))
	for _, v := range verifications {
		r := DKIMResult{Domain: strings.ToLower(v.Domain), Err: v.Err}
		switch {
		case v.Err == nil:
			r.Result = "pass"
		case dkim.IsTempFail(v.Err):
			r.Result = "temperror"
		case dkim.IsPermFail(v.Err):
			r.Result = "permerror"
		default:
			r.Result = "fail"
		}
		if v.Err != nil {
			log.Printf("DKIM %s for d=%s: %v", r.Result, r.Domain, v.Err)
		}
		results = append(results, r)
	}
	return results
}
