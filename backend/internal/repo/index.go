package repo

import (
	"github.com/jmoiron/sqlx"
	"mail_server/internal/repo/mailStorage"
	UserStorage "mail_server/internal/repo/userStorage"
)

type Repo struct {
	*mailStorage.MailStorage
	*UserStorage.UserStorage
}

func NewRepo(db *sqlx.DB) *Repo {
	return &Repo{
		MailStorage: mailStorage.NewMailStorage(),
		UserStorage: UserStorage.NewUserStorage(db),
	}
}
