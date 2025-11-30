package service

import (
	"mail_server/internal/repo"
	"mail_server/internal/service/backendService"
	"mail_server/internal/service/mailService"
)

type Service struct {
	*mailService.MailService
	*backendService.BackendService
}

func NewService(r *repo.Repo) *Service {
	return &Service{
		mailService.NewMailService(r),
		backendService.NewBackendService(r),
	}
}
