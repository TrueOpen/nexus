// Package middleware provides HTTP middleware for ingress:
// access logging (latency / source IP / path / status code / bytes), api-key auth, IP allowlist.
//
// The core auth/allowlist decisions (ValidKey / IPAllowed) are transport-agnostic pure functions
// so the same logic can be reused in a unary interceptor once a gRPC server is wired in.
package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Middleware is a standard http.Handler decorator.
type Middleware func(http.Handler) http.Handler

// Chain wraps h with mws in order; mws[0] is outermost (runs first).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// HeaderAPIKey is the request header carrying the api-key.
const HeaderAPIKey = "X-API-Key"

// ---------- access log ----------

// statusRecorder captures the status code and response byte count.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// RequestLog records method, path, status code, source IP, latency and bytes for every request.
func RequestLog(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if rec.status == 0 {
				rec.status = http.StatusOK
			}
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"ip", ClientIP(r),
				"dur_ms", time.Since(start).Milliseconds(),
				"bytes", rec.bytes,
			)
		})
	}
}

// ---------- api-key auth ----------

// APIKey validates the api-key request header. Empty keys means disabled (pass through).
// Requests matching exempt skip validation (e.g. /healthz).
func APIKey(keys map[string]struct{}, exempt func(*http.Request) bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(keys) == 0 || (exempt != nil && exempt(r)) {
				next.ServeHTTP(w, r)
				return
			}
			if !ValidKey(keys, r.Header.Get(HeaderAPIKey)) {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidKey is a pure function: whether key is in the valid set (shared by HTTP / gRPC).
func ValidKey(keys map[string]struct{}, key string) bool {
	if key == "" {
		return false
	}
	_, ok := keys[key]
	return ok
}

// ---------- IP allowlist ----------

// IPWhitelist only admits requests whose peer IP matches allowed. Empty allowed = disabled.
// Decided on the TCP peer address (RemoteAddr); the forgeable XFF header is not trusted.
func IPWhitelist(allowed []*net.IPNet, exempt func(*http.Request) bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) == 0 || (exempt != nil && exempt(r)) {
				next.ServeHTTP(w, r)
				return
			}
			if !IPAllowed(allowed, peerIP(r)) {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPAllowed is a pure function: whether ip falls within any allowed network (shared by HTTP / gRPC).
func IPAllowed(allowed []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRs parses IP / CIDR strings into networks; a bare IP is treated as /32 or /128.
func ParseCIDRs(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, e := range entries {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				if ip.To4() != nil {
					e += "/32"
				} else {
					e += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// ---------- helpers ----------

// ClientIP best-effort source IP (logging only): XFF -> X-Real-IP -> RemoteAddr.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	return hostOnly(r.RemoteAddr)
}

// peerIP returns the TCP peer IP (used for the allowlist; cannot be forged via headers).
func peerIP(r *http.Request) net.IP {
	return net.ParseIP(hostOnly(r.RemoteAddr))
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"error":"` + msg + `"}`))
}
