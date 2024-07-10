package httpsreverseproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
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

	// Create a new request
	outReq := new(http.Request)
	*outReq = *r // This only does a shallow copy, so we need to deep copy some fields

	outReq.URL = target
	outReq.URL.Path = r.URL.Path
	outReq.URL.RawQuery = r.URL.RawQuery
	outReq.Host = target.Host
	outReq.RequestURI = "" // This must be reset when serving a request with the client

	// Deep-copy headers
	outReq.Header = make(http.Header)
	for k, v := range r.Header {
		if k != "X-Forwarded-For" && k != "X-Real-Ip" {
			outReq.Header[k] = v
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		outReq.Header.Del(h)
	}

	// Create a custom transport
	transport := &http.Transport{
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
	}

	// Send the request
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Copy headers from response
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Send response
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

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
