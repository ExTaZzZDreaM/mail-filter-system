package userstorage

import (
	"fmt"
	"mail_server/models"
	"sync"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

type UserStorage struct {
	db      *sqlx.DB
	rwMutex *sync.RWMutex
}

func NewUserStorage(db *sqlx.DB) *UserStorage {
	return &UserStorage{
		db:      db,
		rwMutex: &sync.RWMutex{},
	}
}

func (u *UserStorage) GetUserByMail(email string) (models.User, bool) {
	var user models.User
	query := `SELECT id, first_name, last_name, email, login, password, is_admin, status, created_at FROM staff WHERE email = $1`

	err := u.db.QueryRow(query, email).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Login,
		&user.Password,
		&user.IsAdmin,
		&user.Status,
		&user.CreatedAt,
	)
	if err != nil {
		return models.User{}, false
	}

	return user, true
}

func (u *UserStorage) GetUser(login string) (models.User, bool) {
	var user models.User
	query := `SELECT id, first_name, last_name, email, login, password, is_admin, status, created_at FROM staff WHERE login = $1`

	err := u.db.QueryRow(query, login).Scan(
		&user.ID,
		&user.FirstName,
		&user.LastName,
		&user.Email,
		&user.Login,
		&user.Password,
		&user.IsAdmin,
		&user.Status,
		&user.CreatedAt,
	)
	if err != nil {
		return models.User{}, false
	}

	return user, true
}

func (u *UserStorage) AddUser(s models.User) error {
	query := `
		INSERT INTO staff (first_name, last_name, email, login, password, is_admin, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7);
	`

	err := u.db.QueryRow(query, s.FirstName, s.LastName, s.Email, s.Login, s.Password, false, "Inactive")
	if err != nil {
		return fmt.Errorf("failed to insert staff: %w", err)
	}
	return nil
}

func (u *UserStorage) GetInactiveUsers() ([]models.User, error) {
	var users []models.User
	query := `SELECT id, first_name, last_name, email, login, password, is_admin, status, created_at FROM staff WHERE status = 'Inactive'`

	rows, err := u.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.FirstName,
			&user.LastName,
			&user.Email,
			&user.Login,
			&user.Password,
			&user.IsAdmin,
			&user.Status,
			&user.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, err
}

func (u *UserStorage) SetUserActive(login string) error {
	query := `UPDATE staff SET status = 'Active' WHERE login = $1`

	_, err := u.db.Exec(query, login)
	if err != nil {
		return err
	}

	return nil
}
