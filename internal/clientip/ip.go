// Package clientip resolves the client address used for rate limits.
// Forwarded headers are honored only from a trusted peer, and only the
// rightmost entry of the last header line is a candidate.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// FromRequest returns the client IP string.
// When the TCP peer is not trusted, X-Forwarded-For is ignored.
// When the peer is trusted and the last item of the last header line is
// empty or not an IP, the proxy's own TCP address is returned.
// The function never walks left to a client-supplied entry.
func FromRequest(r *http.Request, trusted map[string]struct{}) string {
	peer := peerIP(r.RemoteAddr)
	if _, ok := trusted[peer]; !ok {
		return peer
	}
	lines := r.Header.Values("X-Forwarded-For")
	if len(lines) == 0 {
		return peer
	}
	lastLine := lines[len(lines)-1]
	parts := strings.Split(lastLine, ",")
	item := strings.TrimSpace(parts[len(parts)-1])
	ip := net.ParseIP(item)
	if ip == nil {
		return peer
	}
	return ip.String()
}

func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	return ip.String()
}
