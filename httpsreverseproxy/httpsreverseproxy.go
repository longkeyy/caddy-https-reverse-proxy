package httpsreverseproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(HTTPSReverseProxy{})
}

// HTTPSReverseProxy implements a transparent reverse proxy for HTTPS websites
type HTTPSReverseProxy struct {
	Target string `json:"target,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (HTTPSReverseProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.https_reverse_proxy",
		New: func() caddy.Module { return new(HTTPSReverseProxy) },
	}
}

// Provision sets up the module
func (h *HTTPSReverseProxy) Provision(ctx caddy.Context) error {
	return nil
}

// Validate checks the module configuration
func (h *HTTPSReverseProxy) Validate() error {
	_, err := url.Parse(h.Target)
	return err
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (h HTTPSReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	target, err := url.Parse(h.Target)
	if err != nil {
		return err
	}

	// Create a custom director function
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		// Remove X-Forwarded-For header
		req.Header.Del("X-Forwarded-For")

		// Remove other headers that might reveal proxy existence
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Real-IP")

		// Remove hop-by-hop headers
		for _, h := range hopHeaders {
			req.Header.Del(h)
		}
	}

	// Create a custom ModifyResponse function
	modifyResponse := func(resp *http.Response) error {
		// Remove hop-by-hop headers
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
		return nil
	}

	proxy := &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Note: This is insecure and should be used carefully
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	proxy.ServeHTTP(w, r)
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *HTTPSReverseProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&h.Target) {
			return d.ArgErr()
		}
	}
	return nil
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// Interface guards
var (
	_ caddy.Provisioner           = (*HTTPSReverseProxy)(nil)
	_ caddy.Validator             = (*HTTPSReverseProxy)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPSReverseProxy)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPSReverseProxy)(nil)
)
