/*
User model for the database
Because God doesnt have classes like OOP languages
we use structs instead to map query results directly into objects
*/

package models

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	Email             string     `json:"email" db:"email"`
	Username          string     `json:"username" db:"username"`
	PasswordHash      string     `json:"-" db:"password_hash"`
	MasterKeyHash     string     `json:"-" db:"master_key_hash"`
	Salt              string     `json:"-" db:"salt"`
	TwoFactorEnabled  bool       `json:"two_factor_enabled" db:"two_factor_enabled"`
	TwoFactorSecret   *string    `json:"-" db:"two_factor_secret"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
	LastLogin         *time.Time `json:"last_login" db:"last_login"`
	IsActive          bool       `json:"is_active" db:"is_active"`
	EmailVerified     bool       `json:"email_verified" db:"email_verified"`
	VerificationToken *string    `json:"-" db:"verification_token"`
	ResetToken        *string    `json:"-" db:"reset_token"`
	ResetTokenExpires *time.Time `json:"-" db:"reset_token_expires"`
}

// new struct for user creation
// so waht does this do im guessing its a struct datatype for when a user is
// logging in and insrting their details into the frontend, lets see
type UserRegistration struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username" validate:"required,min=3,max=25"`
	Password  string `json:"password" validate:"required,min=8"`
	MasterKey string `json:"master_key" validate:"required,min=8"`
}

// new struct for user login
type UserLogin struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// new strcut for forgot password
type ForgotPassword struct {
	Email     string `json:"email" validate:"required,email"`
	MasterKey string `json:"master_key" validate:"required,min=8"`
	// im guessng if you also forget your master key we can send you an OTP to reset it
	OTP string `json:"otp" validate:"required,min=6,max=6"`
}

type AuthResponse struct {
	User         User   `json:"user"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// type RefreshTokenRequest struct{
// 	RefreshToken string `json:"refresh_token" validate:"required"`
// }

// type TwoFactorAuth struct{
// 	Email string `json:"email" validate:"required,email"`
