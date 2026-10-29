package ingress

import (
	"net/http"

	"github.com/TrueOpen/nexus/internal/opsmetrics"
)

// route is a plain HTTP route served on the ingress port next to /healthz.
type route struct {
	pattern string
	handler http.Handler
}

// WithRoute serves handler at pattern (an http.ServeMux pattern) on the ingress port: a plain
// HTTP route like /healthz, outside the API key and IP allowlist interceptors of the Connect
// API. It is for public read-only routes such as the readiness verdict and the public statistics.
func WithRoute(pattern string, handler http.Handler) Option {
	return func(s *Server) {
		if handler != nil {
			s.routes = append(s.routes, route{pattern: pattern, handler: handler})
		}
	}
}

// WithMetrics times the OpenTask precheck and the first output frame of each accepted task into
// metrics.
func WithMetrics(metrics *opsmetrics.Registry) Option {
	return func(s *Server) { s.metrics = metrics }
}

func withServiceMetrics(metrics *opsmetrics.Registry) serviceOption {
	return func(s *service) { s.metrics = metrics }
}
