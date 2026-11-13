package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ErrValidation marks errors caused by invalid user input.
var ErrValidation = errors.New("validation error")

// Names become part of the login and e-mail address, so only safe characters are allowed.
var namePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,49}$`)

type User struct {
	ID        int       `json:"id" db:"id"`
	FirstName string    `json:"first_name" db:"first_name"`
	LastName  string    `json:"last_name" db:"last_name"`
	Email     string    `json:"email" db:"email"`
	Login     string    `json:"username" db:"login"`
	Password  string    `json:"password,omitempty" db:"password"`
	IsAdmin   bool      `json:"is_admin" db:"is_admin"`
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

func (u *User) Validate() error {
	u.FirstName = strings.TrimSpace(u.FirstName)
	u.LastName = strings.TrimSpace(u.LastName)

	if u.FirstName == "" {
		return fmt.Errorf("%w: first name cannot be empty", ErrValidation)
	}
	if u.LastName == "" {
		return fmt.Errorf("%w: last name cannot be empty", ErrValidation)
	}
	if !namePattern.MatchString(u.FirstName) || !namePattern.MatchString(u.LastName) {
		return fmt.Errorf("%w: names may contain only latin letters, digits and '-'", ErrValidation)
	}
	if strings.TrimSpace(u.Password) == "" {
		return fmt.Errorf("%w: password cannot be empty", ErrValidation)
	}
	if len(u.Password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters long", ErrValidation)
	}
	if len(u.Password) > 72 { // bcrypt limit
		return fmt.Errorf("%w: password must be at most 72 bytes long", ErrValidation)
	}

	return nil
}
