// Package auth is the single-admin password, session, and lockout logic.
package auth

import (
	"errors"
	"os"
	"time"

	"pwpush/internal/config"
	"pwpush/internal/crypto"
	"pwpush/internal/storage"
)

const (
	idleTimeout     = 30 * time.Minute
	absoluteTimeout = 12 * time.Hour
	lockFailures    = 5
	lockDuration    = 15 * time.Minute
)

// Gate limits Argon2 to one operation at a time.
type Gate struct {
	sem chan struct{}
}

func NewGate() *Gate {
	return &Gate{sem: make(chan struct{}, 1)}
}

// Try runs fn while holding the only Argon2 slot.
// It returns false immediately when the slot is busy.
func (g *Gate) Try(fn func()) bool {
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
		fn()
		return true
	default:
		return false
	}
}

// EnsureAdmin hashes the password file only when no admin row exists.
func EnsureAdmin(db *storage.DB, cfg config.Config) error {
	admin, err := db.LoadAdmin()
	if err != nil {
		return err
	}
	if admin.Present {
		if admin.MemoryKiB < 19*1024 || admin.Iterations < 2 || admin.Parallelism < 1 {
			return errors.New("stored Argon2 parameters are below the floor")
		}
		return nil
	}
	return setPasswordFromFile(db, cfg)
}

// ResetAdmin replaces the hash, deletes every session, and clears lockout.
// It runs only when the operator invokes the subcommand.
func ResetAdmin(db *storage.DB, cfg config.Config) error {
	if err := setPasswordFromFile(db, cfg); err != nil {
		return err
	}
	if err := db.DeleteAllSessions(); err != nil {
		return err
	}
	return db.ClearLock()
}

func setPasswordFromFile(db *storage.DB, cfg config.Config) error {
	pw, err := config.ReadPasswordFile(cfg.AdminPasswordFile, os.ReadFile)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pw)
	salt, err := crypto.Random(16)
	if err != nil {
		return err
	}
	hash := crypto.Argon2id(pw, salt, cfg.Argon2Time, cfg.Argon2MemoryKiB, cfg.Argon2Threads)
	defer crypto.Wipe(hash)
	stored := append([]byte(nil), hash...)
	return db.SetAdmin(stored, salt, cfg.Argon2MemoryKiB, cfg.Argon2Time, cfg.Argon2Threads)
}

// LoginResult is a new session or a classified failure.
type LoginResult struct {
	Token  []byte
	CSRF   []byte
	OK     bool
	Busy   bool
	Locked bool
}

// Login checks the password. The caller applies the IP rate limit first.
func Login(db *storage.DB, gate *Gate, password []byte, now time.Time) (LoginResult, error) {
	lock, err := db.LoadLock()
	if err != nil {
		return LoginResult{}, err
	}
	if !lock.Until.IsZero() && now.Before(lock.Until) {
		return LoginResult{Locked: true}, nil
	}
	admin, err := db.LoadAdmin()
	if err != nil {
		return LoginResult{}, err
	}
	if !admin.Present {
		return LoginResult{}, errors.New("admin is not initialised")
	}
	var match bool
	ran := gate.Try(func() {
		sum := crypto.Argon2id(password, admin.Salt, admin.Iterations, admin.MemoryKiB, admin.Parallelism)
		match = crypto.Equal(sum, admin.Hash)
		crypto.Wipe(sum)
	})
	if !ran {
		return LoginResult{Busy: true}, nil
	}
	if !match {
		failures := lock.Failures + 1
		until := time.Time{}
		if !lock.Until.IsZero() && !now.Before(lock.Until) {
			failures = 1
		}
		if failures >= lockFailures {
			until = now.Add(lockDuration)
		}
		if err := db.SaveLock(failures, until); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, nil
	}
	if err := db.ClearLock(); err != nil {
		return LoginResult{}, err
	}
	token, err := crypto.Random(32)
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := crypto.Random(32)
	if err != nil {
		return LoginResult{}, err
	}
	if err := db.CreateSession(crypto.HashToken(token), csrf, now, now.Add(absoluteTimeout)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token, CSRF: csrf, OK: true}, nil
}

// ErrBusy means another Argon2 operation holds the only slot.
var ErrBusy = errors.New("argon2 busy")

// ChangePassword replaces the hash and ends every session.
// Hashing takes the same single Argon2 slot as login.
func ChangePassword(db *storage.DB, gate *Gate, cfg config.Config, password []byte) error {
	if err := config.ValidatePassword(password); err != nil {
		return err
	}
	salt, err := crypto.Random(16)
	if err != nil {
		return err
	}
	var hash []byte
	ran := gate.Try(func() {
		hash = crypto.Argon2id(password, salt, cfg.Argon2Time, cfg.Argon2MemoryKiB, cfg.Argon2Threads)
	})
	if !ran {
		return ErrBusy
	}
	defer crypto.Wipe(hash)
	if err := db.SetAdmin(append([]byte(nil), hash...), salt, cfg.Argon2MemoryKiB, cfg.Argon2Time, cfg.Argon2Threads); err != nil {
		return err
	}
	if err := db.DeleteAllSessions(); err != nil {
		return err
	}
	return db.ClearLock()
}

// Authenticate loads a live session. Expired sessions are deleted.
func Authenticate(db *storage.DB, rawToken []byte, now time.Time) (storage.Session, []byte, bool, error) {
	sum := crypto.HashToken(rawToken)
	sess, err := db.FindSession(sum)
	if err != nil || !sess.Present {
		return storage.Session{}, nil, false, err
	}
	if now.After(sess.Absolute) || now.Sub(sess.LastSeen) > idleTimeout {
		_, _ = db.SQL.Exec(`DELETE FROM sessions WHERE token_hash=?`, sum)
		return storage.Session{}, nil, false, nil
	}
	if err := db.TouchSession(sum, now); err != nil {
		return storage.Session{}, nil, false, err
	}
	return sess, sum, true, nil
}
