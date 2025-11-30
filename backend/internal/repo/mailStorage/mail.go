package mailStorage

import (
	"fmt"
	"mail_server/models"
	"sync"
)

type MailStorage struct {
	mails       map[string][]models.Mail
	blockedMail map[string][]models.Mail
	rwMutex     *sync.RWMutex
}

func NewMailStorage() *MailStorage {
	return &MailStorage{
		mails:       make(map[string][]models.Mail),
		blockedMail: make(map[string][]models.Mail),
		rwMutex:     &sync.RWMutex{},
	}
}

func (m *MailStorage) StoreMail(mail models.Mail) {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()
	m.mails[mail.To] = append(m.mails[mail.To], mail)
}

func (m *MailStorage) GetMailByRecipient(email string) ([]models.Mail, bool) {
	m.rwMutex.RLock()
	m.rwMutex.RUnlock()

	email = fmt.Sprintf("<%s>", email)
	mail, found := m.mails[email]
	return mail, found
}

func (m *MailStorage) GetAllMails() []models.Mail {
	m.rwMutex.RLock()
	m.rwMutex.RUnlock()

	var allMails []models.Mail
	for _, mail := range m.mails {
		allMails = append(allMails, mail...)
	}
	return allMails
}

func (m *MailStorage) GetBlockedMails() map[string][]models.Mail {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()

	return m.blockedMail
}

func (m *MailStorage) AddBlockedMail(cause string, mail models.Mail) {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()

	m.blockedMail[cause] = append(m.blockedMail[cause], mail)
}
