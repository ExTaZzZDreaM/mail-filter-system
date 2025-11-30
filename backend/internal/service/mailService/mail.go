package mailService

import (
	"fmt"
	"mail_server/internal/repo"
	"mail_server/internal/service/mailService/validator"
	"mail_server/models"
)

type MailService struct {
	r *repo.Repo
}

func NewMailService(r *repo.Repo) *MailService {
	return &MailService{
		r: r,
	}
}

func (m *MailService) AddMail(mailName string, mail models.Mail, senderIP string) {
	fmt.Println("Add mail to user:", mailName)
	if !m.ExistUserByMail(mailName) {
		return
	}

	mail.SenderIP = senderIP

	err := validator.Validate(&mail)

	if err != nil {
		m.r.AddBlockedMail(err.Error(), mail)

		fmt.Println("Mail validation error:", err)
		return
	}

	m.r.MailStorage.StoreMail(mail)
}

func (m *MailService) GetBlockedMails() map[string][]models.Mail {
	return m.r.MailStorage.GetBlockedMails()
}

func (m *MailService) ExistUser(username string) bool {
	_, ex := m.r.UserStorage.GetUser(username)
	return ex
}

func (m *MailService) ExistUserByMail(mail string) bool {
	_, ex := m.r.UserStorage.GetUserByMail(mail)
	return ex
}
