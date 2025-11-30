package mailHandler

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mail_server/internal/service/mailService"
	"mail_server/models"
	"mail_server/utils"
	"net"
	"sync"
	"time"

	"github.com/mhale/smtpd"
)

type SMTPServer struct {
	server *smtpd.Server
}

func NewSMTPServer(s *mailService.MailService, tc *tls.Config, addr, domain, mailDomain string) *SMTPServer {

	smtpd.Debug = true

	srv := &smtpd.Server{
		Addr:      addr,
		Appname:   "tmpmail",
		TLSConfig: nil,
		Handler: func(remoteAddr net.Addr, from string, to []string, data []byte) error {
			senderIP, err := getSenderIP(remoteAddr)
			if err != nil {
				return fmt.Errorf("extract sender IP: %w", err)
			}

			m, err := utils.Parse(bytes.NewReader(data))
			if err != nil {
				return fmt.Errorf("parse email: %w", err)
			}

			if len(m.From) == 0 {
				return fmt.Errorf("invalid email: missing or invalid From address")
			}

			mm := models.Mail{
				RawMessage:      data,
				Subject:         m.Subject,
				Date:            m.Date,
				MessageID:       m.MessageID,
				InReplyTo:       m.InReplyTo,
				References:      m.References,
				ResentMessageID: m.ResentMessageID,
				ContentType:     m.ContentType,
				HTMLBody:        m.HTMLBody,
				TextBody:        m.TextBody,
			}

			if mm.Date.IsZero() {
				mm.Date = time.Now()
			}
			if m.Sender != nil {
				mm.Sender = m.Sender.String()
			}
			if m.ResentSender != nil {
				mm.ResentSender = m.ResentSender.String()
			}
			for _, i := range m.From {
				mm.From = i.String()
				break
			}
			for _, i := range m.ResentTo {
				mm.ResentTo = append(mm.ResentTo, i.String())
			}
			if !m.ResentDate.IsZero() {
				mm.ResentDate = &m.ResentDate
			}
			for _, i := range m.To {
				mm.To = i.String()
				break
			}
			for _, i := range m.Cc {
				mm.Cc = i.String()
				break
			}
			for _, i := range m.Bcc {
				mm.Bcc = i.String()
			}
			for _, i := range m.ResentFrom {
				mm.ResentFrom = append(mm.ResentFrom, i.String())
			}
			for _, i := range m.ResentTo {
				mm.ResentTo = append(mm.ResentTo, i.String())
			}
			for _, i := range m.ResentCc {
				mm.ResentCc = append(mm.ResentCc, i.String())
			}
			for _, i := range m.ResentBcc {
				mm.ResentBcc = append(mm.ResentBcc, i.String())
			}
			for _, a := range m.Attachments {
				data, err := io.ReadAll(a.Data)
				if err != nil {
					return fmt.Errorf("read attachment: %w", err)
				}
				mm.Attachments = append(mm.Attachments, models.Attachment{
					Filename:    a.Filename,
					ContentType: a.ContentType,
					Data:        data,
				})
			}
			for _, a := range m.EmbeddedFiles {
				data, err := io.ReadAll(a.Data)
				if err != nil {
					return fmt.Errorf("read embedded file: %w", err)
				}
				mm.EmbeddedFiles = append(mm.EmbeddedFiles, models.EmbeddedFile{
					CID:         a.CID,
					ContentType: a.ContentType,
					Data:        data,
				})
			}

			if len(mm.To) == 0 {
				return nil
			}

			var wg sync.WaitGroup
			for i := range m.To {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()

					s.AddMail(m.To[i].Address, mm, senderIP)

				}(i)
			}
			wg.Wait()
			return nil
		},
		HandlerRcpt: func(remoteAddr net.Addr, from string, to string) bool {
			return s.ExistUserByMail(to)
		},
		Hostname: mailDomain,
		LogRead: func(remoteIP, verb, line string) {

		},
		LogWrite: func(remoteIP, verb, line string) {
		},
	}

	return &SMTPServer{server: srv}
}

func (s *SMTPServer) ListenAndServe() error {
	err := s.server.ListenAndServe()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("listen and server: %w", err)
	}
	return nil
}

func (s *SMTPServer) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func getSenderIP(addr net.Addr) (string, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), nil
	case *net.UDPAddr:
		return a.IP.String(), nil
	default:
		return "", fmt.Errorf("unsupported address type: %T", addr)
	}
}
