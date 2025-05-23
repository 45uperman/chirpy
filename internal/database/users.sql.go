// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0
// source: users.sql

package database

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)

RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type CreateUserParams struct {
	ID             uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Email          string
	HashedPassword string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.ID,
		arg.CreatedAt,
		arg.UpdatedAt,
		arg.Email,
		arg.HashedPassword,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const deleteAllUsers = `-- name: DeleteAllUsers :exec
DELETE FROM users
`

func (q *Queries) DeleteAllUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteAllUsers)
	return err
}

const getUser = `-- name: GetUser :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users
where id = $1
`

func (q *Queries) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red FROM users
WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const giveUserChirpyRed = `-- name: GiveUserChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1
`

func (q *Queries) GiveUserChirpyRed(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, giveUserChirpyRed, id)
	return err
}

const updateEmailAndPassword = `-- name: UpdateEmailAndPassword :one
UPDATE users
SET email = $2, hashed_password = $3
WHERE id = $1

RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red
`

type UpdateEmailAndPasswordParams struct {
	ID             uuid.UUID
	Email          string
	HashedPassword string
}

func (q *Queries) UpdateEmailAndPassword(ctx context.Context, arg UpdateEmailAndPasswordParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateEmailAndPassword, arg.ID, arg.Email, arg.HashedPassword)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}
