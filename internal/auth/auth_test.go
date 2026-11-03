package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"pwpush/internal/config"
	"pwpush/internal/crypto"
	"pwpush/internal/storage"
)

func testCfg(t *testing.T, password string) (config.Config, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	pw := filepath.Join(dir, "password")
	if err := os.WriteFile(pw, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PUBLIC_ORIGIN":       "https://secrets.example",
		"DATA_DIR":            dir,
		"ADMIN_PASSWORD_FILE": pw,
		"TLS_MODE":            "proxy",
		"TRUSTED_PROXY_IPS":   "127.0.0.1",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return cfg, db
}

func TestShortPasswordRefusesInit(t *testing.T) {
	cfg, db := testCfg(t, "short")
	if err := EnsureAdmin(db, cfg); err == nil {
		t.Fatal("short password initialised an admin")
	}
}

func TestPasswordFileIsIdempotent(t *testing.T) {
	cfg, db := testCfg(t, "long-enough-pw")
	if err := EnsureAdmin(db, cfg); err != nil {
		t.Fatal(err)
	}
	first, err := db.LoadAdmin()
	if err != nil || !first.Present {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.AdminPasswordFile, []byte("a-different-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureAdmin(db, cfg); err != nil {
		t.Fatal(err)
	}
	second, err := db.LoadAdmin()
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.Equal(first.Hash, second.Hash) || !crypto.Equal(first.Salt, second.Salt) {
		t.Fatal("startup changed the admin hash")
	}
}

func TestLoginLockoutAndSessionHash(t *testing.T) {
	cfg, db := testCfg(t, "long-enough-pw")
	if err := EnsureAdmin(db, cfg); err != nil {
		t.Fatal(err)
	}
	gate := NewGate()
	now := time.Now()
	for i := 0; i < 5; i++ {
		res, err := Login(db, gate, []byte("wrong-password"), now)
		if err != nil {
			t.Fatal(err)
		}
		if res.OK {
			t.Fatal("wrong password succeeded")
		}
	}
	res, err := Login(db, gate, []byte("long-enough-pw"), now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Locked {
		t.Fatal("expected lockout")
	}
	if err := ResetAdmin(db, cfg); err != nil {
		t.Fatal(err)
	}
	lock, err := db.LoadLock()
	if err != nil {
		t.Fatal(err)
	}
	if lock.Failures != 0 || !lock.Until.IsZero() {
		t.Fatal("reset-admin left lockout in place")
	}
	res, err = Login(db, gate, []byte("long-enough-pw"), now)
	if err != nil || !res.OK {
		t.Fatalf("login after reset: %+v %v", res, err)
	}
	n, err := db.SessionCount()
	if err != nil || n != 1 {
		t.Fatalf("sessions %d %v", n, err)
	}
	sess, err := db.FindSession(crypto.HashToken(res.Token))
	if err != nil || !sess.Present {
		t.Fatal("session hash not stored")
	}
	if err := db.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(db.Path())
	if err != nil {
		t.Fatal(err)
	}
	if wal, err := os.ReadFile(db.Path() + "-wal"); err == nil {
		file = append(file, wal...)
	}
	if bytesContains(file, res.Token) {
		t.Fatal("raw session token is in the database file")
	}
	if err := ChangePassword(db, NewGate(), cfg, []byte("another-long-pw")); err != nil {
		t.Fatal(err)
	}
	n, _ = db.SessionCount()
	if n != 0 {
		t.Fatal("password change left sessions")
	}
	lock, _ = db.LoadLock()
	if lock.Failures != 0 {
		t.Fatal("password change left lockout")
	}
}

func TestGateBusy(t *testing.T) {
	g := NewGate()
	if !g.Try(func() {
		if g.Try(func() {}) {
			t.Fatal("second argon2 slot was granted")
		}
	}) {
		t.Fatal("first slot denied")
	}
}

func bytesContains(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
