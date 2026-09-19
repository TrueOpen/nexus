// tlsproxy is the reverse proxy that adds TLS to the node's three ports: the node's own gRPC / RPC / REST do not support TLS,
// and in production that is handled by a CA-issued certificate plus a reverse proxy (Deployment Security Baseline); this tool is for integration environments, with a self-signed certificate.
//
//	tlsproxy -cert cert.pem -key key.pem -bind 0.0.0.0 //	  -map 9443=h2c://127.0.0.1:9090 -map 26667=127.0.0.1:26657 -map 1443=127.0.0.1:1317
//
// Each mapping listens on <bind>:<port> (TLS, ALPN h2 + http/1.1) and forwards requests unchanged to the plaintext backend port;
// a gRPC backend is reached over h2c (HTTP/2 prior knowledge), everything else over HTTP/1.1. -bind defaults to 127.0.0.1;
// write 0.0.0.0 to serve externally.
//
// Self-signed certificate (the SAN must contain the IP the client connects to):
//
//	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 //	  -subj "/CN=trueopen-node" -addext "subjectAltName=IP:<ip>" -keyout key.pem -out cert.pem
//
// Client trust: SSL_CERT_FILE=cert.pem for Go programs, NODE_EXTRA_CA_CERTS=cert.pem for Node.js.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type mapping struct {
	port    string
	backend string
	h2c     bool // the backend is h2c (gRPC); otherwise HTTP/1.1
}

type mappings []mapping

func (m *mappings) String() string { return fmt.Sprint(*m) }
func (m *mappings) Set(v string) error {
	parts := strings.SplitN(v, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("map must be <port>=<host:port>, got %q", v)
	}
	backend, h2 := parts[1], false
	if strings.HasPrefix(backend, "h2c://") {
		backend, h2 = strings.TrimPrefix(backend, "h2c://"), true
	}
	*m = append(*m, mapping{port: parts[0], backend: backend, h2c: h2})
	return nil
}

func main() {
	var (
		certFile = flag.String("cert", "", "TLS certificate PEM")
		keyFile  = flag.String("key", "", "TLS key PEM")
		bind     = flag.String("bind", "127.0.0.1", "listen address for every mapping (0.0.0.0 to serve externally)")
		maps     mappings
	)
	flag.Var(&maps, "map", "listen port = backend host:port (repeatable)")
	flag.Parse()
	if *certFile == "" || *keyFile == "" || len(maps) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}
	var wg sync.WaitGroup
	for _, m := range maps {
		wg.Add(1)
		go func(m mapping) {
			defer wg.Done()
			listen := net.JoinHostPort(*bind, m.port)
			if err := serve(listen, m, cert); err != nil {
				log.Fatalf("%s -> %s: %v", listen, m.backend, err)
			}
		}(m)
	}
	wg.Wait()
}

func serve(listen string, m mapping, cert tls.Certificate) error {
	target := &url.URL{Scheme: "http", Host: m.backend}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// The backend protocol follows the mapping: the gRPC port uses h2c (HTTP/2 prior knowledge), RPC / REST use HTTP/1.1.
	if m.h2c {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
	} else {
		proxy.Transport = http.DefaultTransport
	}
	server := &http.Server{
		Addr:      listen,
		Handler:   h2c.NewHandler(proxy, &http2.Server{}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("tlsproxy %s -> %s", listen, m.backend)
	return server.ListenAndServeTLS("", "")
}
