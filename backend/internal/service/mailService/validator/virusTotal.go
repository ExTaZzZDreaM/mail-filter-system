package validator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mail_server/models"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

type VirusTotalFileResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type VirusTotalAnalysisResponse struct {
	Data struct {
		Attributes struct {
			Status string `json:"status"`
			Stats  struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
			} `json:"stats"`
		} `json:"attributes"`
	} `json:"data"`
}

func scanFiles(mail *models.Mail) error {
	for i, attachment := range mail.Attachments {
		if len(attachment.Data) == 0 {
			fmt.Println("Attachment data is empty, skipping scan")
		}
		if err := scanFile(attachment.Data, attachment.Filename); err != nil {
			return fmt.Errorf("malicious attachment detected: %s", attachment.Filename)
		}
		mail.Attachments[i] = attachment
	}
	for i, file := range mail.EmbeddedFiles {
		if len(file.Data) == 0 {
			fmt.Println("Embedded file data is empty, skipping scan")
		}
		if err := scanFile(file.Data, file.CID); err != nil {
			return fmt.Errorf("malicious embedded file detected: %s", file.CID)
		}
		mail.EmbeddedFiles[i] = file
	}
	return nil
}

func scanFile(data []byte, name string) error {
	if len(data) == 0 {
		return nil
	}
	if name == "" {
		name = "uploaded_file"
	}
	fmt.Println("Scanning file:", name)

	analysisID, err := uploadFileToVirusTotal(data, name)
	if err != nil {
		return fmt.Errorf("VirusTotal scan failed: %w", err)
	}

	analysis, err := pollAnalysisResults(analysisID)
	if err != nil {
		return fmt.Errorf("VirusTotal analysis failed: %w", err)
	}

	if analysis.Data.Attributes.Stats.Malicious > 0 || analysis.Data.Attributes.Stats.Suspicious > 0 {
		return fmt.Errorf("file %s flagged as malicious", name)
	}

	fmt.Printf("File %s scanned successfully, no threats detected\n", name)

	return nil
}

func uploadFileToVirusTotal(data []byte, name string) (string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		return "", fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, bytes.NewReader(data)); err != nil {
		return "", fmt.Errorf("write file data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("close form writer: %w", err)
	}

	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", &body)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("x-apikey", "54e468d2dd6f5824e24d67159f09461a4e62af03c5d7b71bf47f6d30cce2db84")
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
	}

	var fileResp VirusTotalFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&fileResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if fileResp.Data.ID == "" {
		return "", fmt.Errorf("no analysis ID in response")
	}

	return fileResp.Data.ID, nil
}

func pollAnalysisResults(analysisID string) (*VirusTotalAnalysisResponse, error) {
	const maxRetries = 12
	const pollInterval = 5 * time.Second

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("GET", "https://www.virustotal.com/api/v3/analyses/"+analysisID, nil)
		if err != nil {
			return nil, fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("x-apikey", "54e468d2dd6f5824e24d67159f09461a4e62af03c5d7b71bf47f6d30cce2db84")
		req.Header.Set("Accept", "application/json")

		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("send request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API returned non-200 status: %d", resp.StatusCode)
		}

		var analysisResp VirusTotalAnalysisResponse
		if err := json.NewDecoder(resp.Body).Decode(&analysisResp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		status := strings.ToLower(analysisResp.Data.Attributes.Status)
		if status == "completed" {
			return &analysisResp, nil
		}

		time.Sleep(pollInterval)
	}
	return nil, fmt.Errorf("analysis timed out after %d retries", maxRetries)
}
