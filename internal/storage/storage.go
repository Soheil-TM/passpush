// Package storage opens the single SQLite database.
package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	reservationTTL = 5 * time.Minute
	openCap        = 10
)

var (
	ErrReservation = errors.New("reservation rejected")
	ErrCap         = errors.New("too many open reservations")
)

// DB is one SQLite file. MaxOpenConns is 1.
type DB struct {
	SQL  *sql.DB
	path string
}

// Open creates DATA_DIR at 0700 and the database file at 0600.
func Open(dir string) (*DB, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "pwpush.db")
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)&_txlock=immediate"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	db := &DB{SQL: sqlDB, path: path}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if _, err := sqlDB.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if _, err := sqlDB.Exec(`PRAGMA secure_delete=ON`); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if _, err := sqlDB.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := migrate(sqlDB); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := db.harden(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  hash BLOB NOT NULL,
  salt BLOB NOT NULL,
  memory_kib INTEGER NOT NULL,
  iterations INTEGER NOT NULL,
  parallelism INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash BLOB PRIMARY KEY,
  csrf BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  absolute_expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lockout (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  failures INTEGER NOT NULL,
  locked_until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reservations (
  id TEXT PRIMARY KEY,
  session_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  version INTEGER NOT NULL,
  auth_hash BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS secrets_expires ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS reservations_expires ON reservations(expires_at);
`)
	if err != nil {
		return err
	}
	return ensureRemaining(db)
}

func ensureRemaining(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(secrets)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == "remaining" {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE secrets ADD COLUMN remaining INTEGER NOT NULL DEFAULT 1`)
	return err
}

func (db *DB) harden() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := db.path + suffix
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.Chmod(p, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (db *DB) Close() error { return db.SQL.Close() }

// Checkpoint truncates the WAL. It does not claim to erase deleted bytes.
func (db *DB) Checkpoint() error {
	_, err := db.SQL.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// Cleanup removes expired secret and reservation rows.
func (db *DB) Cleanup(now time.Time) error {
	unix := now.Unix()
	if _, err := db.SQL.Exec(`DELETE FROM secrets WHERE expires_at <= ?`, unix); err != nil {
		return err
	}
	_, err := db.SQL.Exec(`DELETE FROM reservations WHERE expires_at <= ?`, unix)
	return err
}

type Admin struct {
	Hash, Salt            []byte
	MemoryKiB, Iterations uint32
	Parallelism           uint8
	Present               bool
}

func (db *DB) LoadAdmin() (Admin, error) {
	var a Admin
	var threads int
	err := db.SQL.QueryRow(`SELECT hash, salt, memory_kib, iterations, parallelism FROM admin WHERE id=1`).
		Scan(&a.Hash, &a.Salt, &a.MemoryKiB, &a.Iterations, &threads)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, nil
	}
	if err != nil {
		return Admin{}, err
	}
	a.Parallelism = uint8(threads)
	a.Present = true
	return a, nil
}

func (db *DB) SetAdmin(hash, salt []byte, memoryKiB, iterations uint32, threads uint8) error {
	_, err := db.SQL.Exec(`
INSERT INTO admin(id, hash, salt, memory_kib, iterations, parallelism)
VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  hash=excluded.hash,
  salt=excluded.salt,
  memory_kib=excluded.memory_kib,
  iterations=excluded.iterations,
  parallelism=excluded.parallelism
`, hash, salt, memoryKiB, iterations, threads)
	return err
}

type Lock struct {
	Failures int
	Until    time.Time
}

func (db *DB) LoadLock() (Lock, error) {
	var failures int
	var until int64
	err := db.SQL.QueryRow(`SELECT failures, locked_until FROM lockout WHERE id=1`).Scan(&failures, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return Lock{}, nil
	}
	if err != nil {
		return Lock{}, err
	}
	l := Lock{Failures: failures}
	if until > 0 {
		l.Until = time.Unix(until, 0)
	}
	return l, nil
}

func (db *DB) SaveLock(failures int, until time.Time) error {
	var unix int64
	if !until.IsZero() {
		unix = until.Unix()
	}
	_, err := db.SQL.Exec(`
INSERT INTO lockout(id, failures, locked_until) VALUES (1, ?, ?)
ON CONFLICT(id) DO UPDATE SET failures=excluded.failures, locked_until=excluded.locked_until
`, failures, unix)
	return err
}

func (db *DB) ClearLock() error {
	return db.SaveLock(0, time.Time{})
}

type Session struct {
	CSRF     []byte
	Created  time.Time
	LastSeen time.Time
	Absolute time.Time
	Present  bool
}

func (db *DB) CreateSession(tokenHash, csrf []byte, created time.Time, absolute time.Time) error {
	_, err := db.SQL.Exec(`INSERT INTO sessions(token_hash, csrf, created_at, last_seen, absolute_expires) VALUES (?,?,?,?,?)`,
		tokenHash, csrf, created.Unix(), created.Unix(), absolute.Unix())
	return err
}

func (db *DB) FindSession(tokenHash []byte) (Session, error) {
	var s Session
	var created, last, abs int64
	err := db.SQL.QueryRow(`SELECT csrf, created_at, last_seen, absolute_expires FROM sessions WHERE token_hash=?`, tokenHash).
		Scan(&s.CSRF, &created, &last, &abs)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, nil
	}
	if err != nil {
		return Session{}, err
	}
	s.Created = time.Unix(created, 0)
	s.LastSeen = time.Unix(last, 0)
	s.Absolute = time.Unix(abs, 0)
	s.Present = true
	return s, nil
}

func (db *DB) TouchSession(tokenHash []byte, seen time.Time) error {
	_, err := db.SQL.Exec(`UPDATE sessions SET last_seen=? WHERE token_hash=?`, seen.Unix(), tokenHash)
	return err
}

func (db *DB) DeleteAllSessions() error {
	_, err := db.SQL.Exec(`DELETE FROM sessions`)
	return err
}

func (db *DB) SessionCount() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	return n, err
}

// Reserve inserts a session-owned reservation if the open cap allows it.
func (db *DB) Reserve(sessionHash []byte, id string, now time.Time) error {
	tx, err := db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM reservations WHERE session_hash=? AND expires_at>?`, sessionHash, now.Unix()).Scan(&n); err != nil {
		return err
	}
	if n >= openCap {
		return ErrCap
	}
	exp := now.Add(reservationTTL).Unix()
	if _, err := tx.Exec(`INSERT INTO reservations(id, session_hash, expires_at) VALUES (?,?,?)`, id, sessionHash, exp); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateSecret consumes a live reservation owned by the session and inserts the secret.
// A failed insert rolls the reservation back.
func (db *DB) CreateSecret(sessionHash []byte, id string, nonce, ciphertext, authHash []byte, version, remaining int, expires time.Time, now time.Time) error {
	tx, err := db.SQL.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var got string
	err = tx.QueryRow(`DELETE FROM reservations WHERE id=? AND session_hash=? AND expires_at>? RETURNING id`, id, sessionHash, now.Unix()).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrReservation
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO secrets(id, nonce, ciphertext, version, auth_hash, expires_at, created_at, remaining) VALUES (?,?,?,?,?,?,?,?)`,
		id, nonce, ciphertext, version, authHash, expires.Unix(), now.Unix(), remaining)
	if err != nil {
		return err
	}
	return tx.Commit()
}

type Secret struct {
	Nonce      []byte
	Ciphertext []byte
	Version    int
	Remaining  int
	Present    bool
}

// Reveal deletes a matching live secret and returns its opaque fields.
// A wrong auth hash matches zero rows and leaves the secret in place.
func (db *DB) Reveal(id string, authHash []byte, now time.Time) (Secret, error) {
	tx, err := db.SQL.Begin()
	if err != nil {
		return Secret{}, err
	}
	defer tx.Rollback()
	var s Secret
	err = tx.QueryRow(`
UPDATE secrets SET remaining = remaining - 1
WHERE id=? AND auth_hash=? AND expires_at>? AND remaining > 1
RETURNING nonce, ciphertext, version, remaining`,
		id, authHash, now.Unix()).Scan(&s.Nonce, &s.Ciphertext, &s.Version, &s.Remaining)
	if err == nil {
		if err := tx.Commit(); err != nil {
			return Secret{}, err
		}
		s.Present = true
		return s, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Secret{}, err
	}
	err = tx.QueryRow(`
DELETE FROM secrets
WHERE id=? AND auth_hash=? AND expires_at>? AND remaining <= 1
RETURNING nonce, ciphertext, version`,
		id, authHash, now.Unix()).Scan(&s.Nonce, &s.Ciphertext, &s.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, nil
	}
	if err != nil {
		return Secret{}, err
	}
	if err := tx.Commit(); err != nil {
		return Secret{}, err
	}
	s.Present = true
	return s, nil
}

func (db *DB) SecretCount() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&n)
	return n, err
}

func (db *DB) ReservationCount() (int, error) {
	var n int
	err := db.SQL.QueryRow(`SELECT COUNT(*) FROM reservations`).Scan(&n)
	return n, err
}

// InsertSecretForTest plants a row without a reservation. Tests only.
func (db *DB) InsertSecretForTest(id string, nonce, ciphertext, authHash []byte, expires time.Time) error {
	_, err := db.SQL.Exec(`INSERT INTO secrets(id, nonce, ciphertext, version, auth_hash, expires_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		id, nonce, ciphertext, 1, authHash, expires.Unix(), time.Now().Unix())
	return err
}

// InsertReservationForTest plants a reservation. Tests only.
func (db *DB) InsertReservationForTest(id string, sessionHash []byte, expires time.Time) error {
	_, err := db.SQL.Exec(`INSERT INTO reservations(id, session_hash, expires_at) VALUES (?,?,?)`, id, sessionHash, expires.Unix())
	return err
}

// Path returns the database file path.
func (db *DB) Path() string { return db.path }

// PragmaInt reads an integer PRAGMA.
func (db *DB) PragmaInt(name string) (int, error) {
	var n int
	err := db.SQL.QueryRow(fmt.Sprintf("PRAGMA %s", name)).Scan(&n)
	return n, err
}

// PragmaText reads a text PRAGMA.
func (db *DB) PragmaText(name string) (string, error) {
	var s string
	err := db.SQL.QueryRow(fmt.Sprintf("PRAGMA %s", name)).Scan(&s)
	return s, err
}
