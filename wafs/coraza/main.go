// coraza-proxy — minimal Coraza-in-front-of-reverse-proxy for the WAF Lab.
//
// Reads CRS v4 from the coraza-coreruleset embedded FS, wraps a stdlib
// httputil.ReverseProxy with corazahttp.WrapHandler, and serves on LISTEN_ADDR.
// Paranoia level (and any other CRS tunables) are injected via the
// CORAZA_EXTRA_DIRECTIVES env var so the compose file can toggle defaults
// without rebuilding the image.
//
// Implements the reverse-proxy half of the paper's WAF test bench for
// Coraza (one of the four WAFs compared in §Methodology).
package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	coreruleset "github.com/corazawaf/coraza-coreruleset"
	coraza "github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	backend := getenv("BACKEND", "http://whoami:80")
	listen := getenv("LISTEN_ADDR", ":80")
	extra := os.Getenv("CORAZA_EXTRA_DIRECTIVES")

	// SecRuleEngine defaults to DetectionOnly in @coraza.conf-recommended — at
	// that setting Coraza observes attacks but never 403s, which produced a
	// spurious 100% "bypass rate" in earlier runs. Force blocking mode for
	// parity with ModSecurity; override via CORAZA_BLOCKING_MODE=off if a
	// future profile wants monitor-only behaviour.
	blockingMode := getenv("CORAZA_BLOCKING_MODE", "on")
	engineDirective := "SecRuleEngine On"
	if blockingMode == "off" {
		engineDirective = "SecRuleEngine DetectionOnly"
	}

	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectivesFromFile("@coraza.conf-recommended").
		WithDirectivesFromFile("@crs-setup.conf.example").
		WithDirectivesFromFile("@owasp_crs/*.conf").
		WithDirectives(engineDirective)

	if extra != "" {
		cfg = cfg.WithDirectives(extra)
	}

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		log.Fatalf("coraza init: %v", err)
	}

	u, err := url.Parse(backend)
	if err != nil {
		log.Fatalf("invalid BACKEND %q: %v", backend, err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	origDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = u.Host
	}

	// /healthz is served directly without routing through Coraza or the backend
	// target. Health must not depend on the application it protects — see
	// docs/DEV.md "Known gotchas".
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-waflab-waf", "coraza")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("/", corazahttp.WrapHandler(waf, proxy))

	log.Printf("coraza-proxy listening on %s, backend=%s, blocking_mode=%s, extra_directives=%dB",
		listen, backend, blockingMode, len(extra))
	if err := http.ListenAndServe(listen, mux); err != nil {
		log.Fatalf("http.ListenAndServe: %v", err)
	}
}
