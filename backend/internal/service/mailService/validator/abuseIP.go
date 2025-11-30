package validator

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	} `json:"data"`
}

func checkAbuseIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	baseURL := "https://api.abuseipdb.com/api/v2/check"
	params := url.Values{}
	params.Add("ipAddress", ip)
	params.Add("maxAgeInDays", "90")
	params.Add("verbose", "")

	req, err := http.NewRequest("GET", baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Key", "22d4ed0dc2fc54aaa49f39379668022a31947ff90a96e327190e5a42e96dfbb92b1a2f359f37defa")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
	}

	var apiResp AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	if apiResp.Data.IPAddress != ip {
		return fmt.Errorf("response IP mismatch: expected %s, got %s", ip, apiResp.Data.IPAddress)
	}

	if apiResp.Data.AbuseConfidenceScore > 50 {
		return fmt.Errorf("IP %s flagged as abusive (score: %d)", ip, apiResp.Data.AbuseConfidenceScore)
	}

	return nil
}
