package models

import (
	"fmt"
	"strings"
	"time"
)

type User struct {
	ID        int       `json:"id" db:"id"`
	FirstName string    `json:"first_name" db:"first_name"`
	LastName  string    `json:"last_name" db:"last_name"`
	Email     string    `json:"email" db:"email"`
	Login     string    `json:"username" db:"login"`
	Password  string    `json:"password" db:"password"`
	IsAdmin   bool      `json:"is_admin" db:"is_admin"`
	Status    string    `json:"status" db:"status"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

func (u *User) Validate() error {
	if strings.TrimSpace(u.FirstName) == "" {
		return fmt.Errorf("first name cannot be empty")
	}

	if strings.TrimSpace(u.LastName) == "" {
		return fmt.Errorf("last name cannot be empty")
	}

	if strings.TrimSpace(u.Password) == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if len(u.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	return nil
}
