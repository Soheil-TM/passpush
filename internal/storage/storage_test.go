package storage

import (
	"os"
	"testing"
	"time"
)

func TestOpenPermissionsAndPragmas(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", info.Mode().Perm())
	}
	fi, err := os.Stat(db.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %o", fi.Mode().Perm())
	}
	mode, err := db.PragmaText("journal_mode")
	if err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode %s", mode)
	}
	sd, err := db.PragmaInt("secure_delete")
	if err != nil {
		t.Fatal(err)
	}
	if sd != 1 {
		t.Fatalf("secure_delete %d", sd)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
}

func TestRevealWrongHashDoesNotDelete(t *testing.T) {
	db := openTest(t)
	id := "abcdefghijklmnopqrstuv"
	nonce := []byte("0123456789ab")
	ct := bytesRepeat(32)
	hash := bytesRepeat(32)
	if err := db.InsertSecretForTest(id, nonce, ct, hash, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := db.Reveal(id, hash, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Present {
		t.Fatal("expired secret returned")
	}
	if _, err := db.SQL.Exec(`DELETE FROM secrets WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	if err := db.InsertSecretForTest(id, nonce, ct, hash, exp); err != nil {
		t.Fatal(err)
	}
	wrong := bytesRepeat(32)
	wrong[0] = 9
	got, err = db.Reveal(id, wrong, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Present {
		t.Fatal("wrong hash returned a secret")
	}
	n, err := db.SecretCount()
	if err != nil || n != 1 {
		t.Fatalf("count %d err %v", n, err)
	}
	got, err = db.Reveal(id, hash, time.Now())
	if err != nil || !got.Present {
		t.Fatalf("present %v err %v", got.Present, err)
	}
	if string(got.Nonce) != string(nonce) || string(got.Ciphertext) != string(ct) || got.Version != 1 {
		t.Fatal("returned bytes differ")
	}
	n, _ = db.SecretCount()
	if n != 0 {
		t.Fatalf("secret remained after reveal: %d", n)
	}
}

func TestReservationConsumeRollsBack(t *testing.T) {
	db := openTest(t)
	sess := bytesRepeat(32)
	now := time.Now()
	id := "abcdefghijklmnopqrstuv"
	if err := db.Reserve(sess, id, now); err != nil {
		t.Fatal(err)
	}
	other := bytesRepeat(32)
	other[0] = 1
	err := db.CreateSecret(other, id, []byte("0123456789ab"), bytesRepeat(16), bytesRepeat(32), 1, 1, now.Add(time.Hour), now)
	if err == nil {
		t.Fatal("other session was accepted")
	}
	n, _ := db.ReservationCount()
	if n != 1 {
		t.Fatalf("reservation lost: %d", n)
	}
	for i := 0; i < 9; i++ {
		if err := db.Reserve(sess, id[:21]+string(rune('a'+i)), now); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Reserve(sess, "zzzzzzzzzzzzzzzzzzzzzz", now); err != ErrCap {
		t.Fatalf("cap err %v", err)
	}
}

func TestCleanup(t *testing.T) {
	db := openTest(t)
	now := time.Now()
	if err := db.InsertSecretForTest("abcdefghijklmnopqrstuv", []byte("0123456789ab"), bytesRepeat(16), bytesRepeat(32), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertReservationForTest("bcdefghijklmnopqrstuvw", bytesRepeat(32), now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertSecretForTest("cdefghijklmnopqrstuvwx", []byte("0123456789ab"), bytesRepeat(16), bytesRepeat(32), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.Cleanup(now); err != nil {
		t.Fatal(err)
	}
	ns, _ := db.SecretCount()
	nr, _ := db.ReservationCount()
	if ns != 1 || nr != 0 {
		t.Fatalf("secrets %d reservations %d", ns, nr)
	}
}

func TestRevealKeepsSecretUntilLastView(t *testing.T) {
	db := openTest(t)
	id := "abcdefghijklmnopqrstuv"
	nonce := []byte("0123456789ab")
	ct := bytesRepeat(16)
	hash := bytesRepeat(32)
	if err := db.InsertSecretForTest(id, nonce, ct, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SQL.Exec(`UPDATE secrets SET remaining=2 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	first, err := db.Reveal(id, hash, time.Now())
	if err != nil || !first.Present || first.Remaining != 1 {
		t.Fatalf("first %#v %v", first, err)
	}
	n, _ := db.SecretCount()
	if n != 1 {
		t.Fatal("first view deleted the row")
	}
	wrong := bytesRepeat(32)
	wrong[0] = 1
	miss, err := db.Reveal(id, wrong, time.Now())
	if err != nil || miss.Present {
		t.Fatal("wrong token changed a multi-view secret")
	}
	second, err := db.Reveal(id, hash, time.Now())
	if err != nil || !second.Present || second.Remaining != 0 {
		t.Fatalf("second %#v %v", second, err)
	}
	n, _ = db.SecretCount()
	if n != 0 {
		t.Fatal("last view left the row")
	}
}

func openTest(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 7
	}
	return b
}
