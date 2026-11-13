package mailHandler

import "testing"

func TestExtractHELO(t *testing.T) {
	cases := map[string]string{
		"Received: from mx.example.com (host [192.0.2.1])\r\n        by test.com\r\n": "mx.example.com",
		"Received: from [192.0.2.1] (host [192.0.2.1])\r\n":                           "[192.0.2.1]",
		"Subject: no received header\r\n":                                             "",
		"":                                                                            "",
	}
	for in, want := range cases {
		if got := extractHELO([]byte(in)); got != want {
			t.Errorf("extractHELO(%q) = %q; want %q", in, got, want)
		}
	}
}
