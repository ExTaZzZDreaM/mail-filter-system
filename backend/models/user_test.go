package models

import (
	"errors"
	"testing"
)

func TestUserValidate(t *testing.T) {
	cases := []struct {
		name string
		u    User
		ok   bool
	}{
		{"valid", User{FirstName: "John", LastName: "Doe", Password: "password123"}, true},
		{"trims spaces", User{FirstName: " John ", LastName: "Doe", Password: "password123"}, true},
		{"empty first name", User{LastName: "Doe", Password: "password123"}, false},
		{"short password", User{FirstName: "John", LastName: "Doe", Password: "short"}, false},
		{"unsafe chars", User{FirstName: "Jo hn", LastName: "Doe@x", Password: "password123"}, false},
	}
	for _, c := range cases {
		err := c.u.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", c.name, err)
		}
	}
}
