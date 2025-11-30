package backendService

import (
	"fmt"
	"mail_server/internal/repo"
	"mail_server/models"

	"github.com/google/uuid"
)

type BackendService struct {
	r     *repo.Repo
	token map[string]string
}

func NewBackendService(r *repo.Repo) *BackendService {
	return &BackendService{
		r:     r,
		token: make(map[string]string),
	}
}

func (b *BackendService) Register(u models.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	u.Login = u.FirstName + u.LastName

	u.Email = u.Login + "@test.com"

	if err := b.r.UserStorage.AddUser(u); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}

	return nil
}

func (b *BackendService) Auth(u models.User) (string, error) {
	user, ex := b.r.UserStorage.GetUser(u.Login)

	if !ex {
		return "", fmt.Errorf("user not found")
	}

	if user.Password != u.Password {
		return "", fmt.Errorf("wrong password")
	}

	if user.Status != "Active" {
		return "", fmt.Errorf("user is inactive")
	}

	token := uuid.New().String()

	b.token[token] = u.Login

	return token, nil
}

func (b *BackendService) GetMail(token string) ([]models.Mail, error) {
	username, ex := b.token[token]

	if !ex {
		return nil, fmt.Errorf("user not found")
	}

	user, ex := b.r.UserStorage.GetUser(username)

	if !ex {
		return nil, fmt.Errorf("user not found")
	}

	mails, _ := b.r.MailStorage.GetMailByRecipient(user.Email)

	return mails, nil
}

func (b *BackendService) IsAdmin(token string) error {
	username, ex := b.token[token]

	if !ex {
		return fmt.Errorf("user not found")
	}

	user, ex := b.r.UserStorage.GetUser(username)

	if !ex {
		return fmt.Errorf("user not found")
	}

	if !user.IsAdmin {
		return fmt.Errorf("user is not admin")
	}

	return nil
}

func (b *BackendService) GetInactive() ([]models.User, error) {
	return b.r.GetInactiveUsers()
}

func (b *BackendService) UpdateStatus(login string) error {
	return b.r.SetUserActive(login)
}
