package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/jmoiron/sqlx"
	"log"
	"mail_server/internal/handler/backendHandler"
	"mail_server/internal/handler/mailHandler"
	"mail_server/internal/repo"
	"mail_server/internal/service"
	"mail_server/internal/service/mailService/validator"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	domain     = "test.com"
	mailDomain = "test.com"
	certsCache = "./certs"
)

func main() {
	cfg := getCfg()

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "host=localhost user=postgres password=postgres dbname=mail sslmode=disable"
		log.Println("DATABASE_URL is not set, using local development defaults")
	}
	db, err := sqlx.Connect("postgres", connStr)
	if err != nil {
		panic(err)
	}

	validator.AuthServID = mailDomain

	r := repo.NewRepo(db)
	s := service.NewService(r)

	cm := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain, mailDomain),
		Cache:      autocert.DirCache(certsCache),
	}

	tlsCfg := cm.TLSConfig()
	origGetCertificate := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		info.ServerName = mailDomain
		return origGetCertificate(info)
	}
	tlsCfg.ServerName = mailDomain

	smtpSrv := mailHandler.NewSMTPServer(s.MailService, tlsCfg, cfg.SmtpAddr, domain, mailDomain)

	go func() {
		log.Printf("SMTP server starting on %s", cfg.SmtpAddr)
		if err := smtpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("SMTP server error: %v", err)
		}
	}()

	backendSrv := backendHandler.NewBackendHandler(s, cfg.HttpAddr, tlsCfg, allowedOrigin())

	go func() {
		log.Printf("HTTP server starting on %s", cfg.HttpAddr)
		if err := backendSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := backendSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	if err := smtpSrv.Shutdown(ctx); err != nil {
		log.Printf("SMTP server shutdown error: %v", err)
	}

	log.Println("Servers stopped")
}

func getCfg() config {
	bb, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatal(err)
	}

	var cfg config

	if err := json.Unmarshal(bb, &cfg); err != nil {
		log.Fatal(err)
	}

	return cfg
}

// allowedOrigin returns the origin allowed to call the HTTP API from a browser.
func allowedOrigin() string {
	if o := os.Getenv("CORS_ORIGIN"); o != "" {
		return o
	}
	return "http://localhost:3000"
}

type config struct {
	SmtpAddr string `json:"smtp_addr"`
	HttpAddr string `json:"http_addr"`
}
