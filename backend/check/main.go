package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
)

func main() {
	smtpAddr := "localhost:587"
	from := "test@gmail.com"
	to := "john.doe@test.com"
	subject := "Test Mail with Attachment"
	filename := "./kk.exe"

	data, err := os.ReadFile(filename)
	if err != nil {
		panic(fmt.Sprintf("ReadFile error: %v", err))
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	var msg bytes.Buffer
	boundary := "MYBOUNDARY"

	msg.WriteString("From: " + from + "\r\n")
	msg.WriteString("To: " + to + "\r\n")
	msg.WriteString("Subject: " + subject + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=%s\r\n", boundary))
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString("This is a test message with an attachment.\r\n")
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: application/octet-stream\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=%q\r\n", filepath.Base(filename)))
	msg.WriteString("\r\n")

	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		msg.WriteString(encoded[i:end] + "\r\n")
	}
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	conn, err := net.Dial("tcp", smtpAddr)
	if err != nil {
		panic(fmt.Sprintf("Dial error: %v", err))
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localtest.me")
	if err != nil {
		panic(fmt.Sprintf("NewClient error: %v", err))
	}
	defer client.Quit()

	// SMTP commands
	if err := client.Mail(from); err != nil {
		panic(fmt.Sprintf("Mail error: %v", err))
	}
	if err := client.Rcpt(to); err != nil {
		panic(fmt.Sprintf("Rcpt error: %v", err))
	}

	w, err := client.Data()
	if err != nil {
		panic(fmt.Sprintf("Data error: %v", err))
	}
	_, err = w.Write(msg.Bytes())
	if err != nil {
		panic(fmt.Sprintf("Write error: %v", err))
	}
	err = w.Close()
	if err != nil {
		panic(fmt.Sprintf("Close error: %v", err))
	}

	fmt.Println("Email with attachment sent successfully!")
}
