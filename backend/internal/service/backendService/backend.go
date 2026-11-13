package backendService

import (
	"errors"
	"fmt"
	"mail_server/internal/repo"
	userstorage "mail_server/internal/repo/userStorage"
	"mail_server/models"

	"golang.org/x/crypto/bcrypt"
)

const mailDomain = "test.com"

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInactiveUser       = errors.New("user is inactive")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("user is not admin")
	ErrUserExists         = userstorage.ErrUserExists
	ErrUserNotFound       = userstorage.ErrUserNotFound
)

// dummyHash is compared against when the user does not exist, to equalize timing.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

type BackendService struct {
	r      *repo.Repo
	tokens *tokenStore
}

func NewBackendService(r *repo.Repo) *BackendService {
	return &BackendService{
		r:      r,
		tokens: newTokenStore(),
	}
}

// Register creates an inactive user and returns the generated login.
func (b *BackendService) Register(u models.User) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}

	u.Login = u.FirstName + u.LastName
	u.Email = u.Login + "@" + mailDomain

	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	u.Password = string(hash)

	if err := b.r.UserStorage.AddUser(u); err != nil {
		return "", err
	}

	return u.Login, nil
}

func (b *BackendService) Auth(u models.User) (string, error) {
	user, ex := b.r.UserStorage.GetUser(u.Login)
	if !ex {
		// Compare against a dummy hash so response time does not reveal whether the user exists.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(u.Password))
		return "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(u.Password)); err != nil {
		return "", ErrInvalidCredentials
	}

	if user.Status != "Active" {
		return "", ErrInactiveUser
	}

	return b.tokens.issue(user.Login), nil
}

func (b *BackendService) userByToken(token string) (models.User, error) {
	login, ok := b.tokens.lookup(token)
	if !ok {
		return models.User{}, ErrUnauthorized
	}
	user, ex := b.r.UserStorage.GetUser(login)
	if !ex {
		return models.User{}, ErrUnauthorized
	}
	return user, nil
}

func (b *BackendService) GetMail(token string) ([]models.Mail, error) {
	user, err := b.userByToken(token)
	if err != nil {
		return nil, err
	}

	mails, _ := b.r.MailStorage.GetMailByRecipient(user.Email)
	return mails, nil
}

func (b *BackendService) IsAdmin(token string) error {
	user, err := b.userByToken(token)
	if err != nil {
		return err
	}
	if !user.IsAdmin {
		return ErrForbidden
	}
	return nil
}

func (b *BackendService) GetInactive() ([]models.User, error) {
	users, err := b.r.GetInactiveUsers()
	if err != nil {
		return nil, err
	}
	for i := range users {
		users[i].Password = "" // never expose password hashes
	}
	return users, nil
}

func (b *BackendService) UpdateStatus(login string) error {
	return b.r.SetUserActive(login)
}
