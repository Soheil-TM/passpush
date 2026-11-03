package clientip

import (
	"net/http"
	"testing"
)

func request(remote string, lines ...string) *http.Request {
	r, err := http.NewRequest(http.MethodPost, "/api/reveal", nil)
	if err != nil {
		panic(err)
	}
	r.RemoteAddr = remote
	for _, line := range lines {
		r.Header.Add("X-Forwarded-For", line)
	}
	return r
}

func TestIgnoresHeaderFromUntrustedPeer(t *testing.T) {
	got := FromRequest(request("203.0.113.8:443", "198.51.100.9"), map[string]struct{}{"127.0.0.1": {}})
	if got != "203.0.113.8" {
		t.Fatalf("got %s", got)
	}
}

func TestDirectModeIgnoresHeader(t *testing.T) {
	got := FromRequest(request("203.0.113.8:443", "198.51.100.9"), map[string]struct{}{})
	if got != "203.0.113.8" {
		t.Fatalf("got %s", got)
	}
}

func TestLastItemOfLastLine(t *testing.T) {
	trusted := map[string]struct{}{"127.0.0.1": {}}
	r := request("127.0.0.1:8443", "1.1.1.1, 2.2.2.2", "3.3.3.3, 198.51.100.20")
	got := FromRequest(r, trusted)
	if got != "198.51.100.20" {
		t.Fatalf("got %s, want the rightmost item of the last line", got)
	}
}

func TestSpoofedLeftmostIsIgnored(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.5": {}}
	got := FromRequest(request("10.0.0.5:443", "8.8.8.8, 198.51.100.7"), trusted)
	if got != "198.51.100.7" {
		t.Fatalf("got %s", got)
	}
}

func TestInvalidLastItemUsesProxyIP(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.5": {}}
	got := FromRequest(request("10.0.0.5:443", "8.8.8.8, 9.9.9.9", "not-an-ip"), trusted)
	if got != "10.0.0.5" {
		t.Fatalf("got %s, want the proxy address", got)
	}
}

func TestEmptyForwardedUsesProxyIP(t *testing.T) {
	trusted := map[string]struct{}{"10.0.0.5": {}}
	got := FromRequest(request("10.0.0.5:443"), trusted)
	if got != "10.0.0.5" {
		t.Fatalf("got %s", got)
	}
}
