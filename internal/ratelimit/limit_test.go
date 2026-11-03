package ratelimit

import (
	"testing"
	"time"
)

func TestAllowPairRequiresBoth(t *testing.T) {
	l := New(func() time.Time { return time.Unix(0, 0) })
	rule := Rule{Capacity: 1, RefillPerSec: 0}
	if !l.AllowIPAndID("ip", "id-a", rule) {
		t.Fatal("first allow")
	}
	if l.AllowIPAndID("ip", "id-b", rule) {
		t.Fatal("ip bucket should be empty")
	}
	l2 := New(func() time.Time { return time.Unix(0, 0) })
	if !l2.AllowIPAndID("ip-a", "same", rule) {
		t.Fatal("first id allow")
	}
	if l2.AllowIPAndID("ip-b", "same", rule) {
		t.Fatal("id bucket should be empty")
	}
}

func TestPairDoesNotConsumeOnPartial(t *testing.T) {
	l := New(func() time.Time { return time.Unix(0, 0) })
	rule := Rule{Capacity: 1, RefillPerSec: 0}
	if !l.AllowIP("create-ip:a", rule) {
		t.Fatal("seed")
	}
	if l.AllowIPAndSession("create-ip:a", "sess", rule) {
		t.Fatal("ip already empty")
	}
	if !l.AllowIP("create-ses-check", Rule{Capacity: 1, RefillPerSec: 0}) {
		t.Fatal("unrelated key")
	}
	fresh := New(func() time.Time { return time.Unix(0, 0) })
	if !fresh.AllowIPAndSession("ip", "sess", rule) {
		t.Fatal("session key should still be full on a fresh limiter after a failed pair")
	}
}

func TestIDLRUBoundsMemory(t *testing.T) {
	l := New(time.Now)
	rule := Rule{Capacity: 1, RefillPerSec: 0}
	for i := 0; i < 1100; i++ {
		if !l.AllowIPAndID("ip-unique-"+itoa(i), "id-"+itoa(i), Rule{Capacity: 2, RefillPerSec: 0}) {
			t.Fatalf("unexpected deny at %d", i)
		}
		_ = rule
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.id.items) > 1024 {
		t.Fatalf("id buckets = %d", len(l.id.items))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
