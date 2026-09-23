package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yashiels/fnb/internal/exitcode"
	"github.com/yashiels/fnb/internal/guard"
)

var ErrSentUnknownOutcome = errors.New("request was sent but its outcome is unknown")

type RequestGuard interface {
	Check(*http.Request) error
	CheckRedirect(*http.Request, []*http.Request) error
}

type Clock interface {
	Now() time.Time
	Sleep(context.Context, time.Duration) error
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

func (RealClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type HTTPTransport struct {
	Base  http.RoundTripper
	guard RequestGuard
	jar   *guardedJar
	clock Clock
	pace  sync.Mutex
	last  time.Time
}

func NewHTTP(requestGuard RequestGuard, clock Clock) *http.Client {
	if clock == nil {
		clock = RealClock{}
	}
	jar, _ := cookiejar.New(nil)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableKeepAlives = true
	disableHTTP2(base)
	wrapped := &HTTPTransport{
		Base:  base,
		guard: requestGuard,
		jar:   newGuardedJar(jar, clock),
		clock: clock,
	}
	return &http.Client{
		Transport: wrapped,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if err := requestGuard.CheckRedirect(request, via); err != nil {
				return err
			}
			if request.Response != nil && request.Response.Request != nil {
				wrapped.jar.SetCookies(request.Response.Request.URL, request.Response.Cookies())
			}
			return nil
		},
	}
}

func disableHTTP2(transport *http.Transport) {
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport.Protocols = protocols
}

func (transport *HTTPTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := transport.guard.Check(request); err != nil {
		return nil, err
	}
	if err := transport.wait(request.Context()); err != nil {
		return nil, err
	}
	outbound := request.Clone(request.Context())
	outbound.Header = request.Header.Clone()
	for _, cookie := range transport.jar.Cookies(request.URL) {
		outbound.AddCookie(cookie)
	}
	response, err := transport.Base.RoundTrip(outbound)
	if err != nil {
		return nil, err
	}
	if !isRedirectResponse(response) {
		transport.jar.SetCookies(request.URL, response.Cookies())
	}
	return response, nil
}

func (transport *HTTPTransport) CookieSnapshot() []*http.Cookie {
	return transport.jar.snapshot()
}

func (transport *HTTPTransport) ImportCookies(cookies []*http.Cookie) error {
	target := &url.URL{Scheme: guard.Scheme, Host: guard.Host, Path: "/"}
	return transport.jar.importCookies(target, cookies)
}

func (transport *HTTPTransport) DroppedCookies() map[string]int {
	return transport.jar.droppedCookies()
}

func (transport *HTTPTransport) wait(ctx context.Context) error {
	transport.pace.Lock()
	defer transport.pace.Unlock()
	now := transport.clock.Now()
	if !transport.last.IsZero() {
		remaining := time.Second - now.Sub(transport.last)
		if remaining > 0 {
			if err := transport.clock.Sleep(ctx, remaining); err != nil {
				return err
			}
			now = transport.clock.Now()
		}
	}
	transport.last = now
	return nil
}

func isRedirectResponse(response *http.Response) bool {
	switch response.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return response.Header.Get("Location") != ""
	default:
		return false
	}
}

type guardedJar struct {
	jar      http.CookieJar
	mu       sync.Mutex
	dropped  map[string]int
	accepted map[string]*http.Cookie
	clock    Clock
}

func newGuardedJar(jar http.CookieJar, clock Clock) *guardedJar {
	return &guardedJar{jar: jar, dropped: make(map[string]int), accepted: make(map[string]*http.Cookie), clock: clock}
}

func (jar *guardedJar) SetCookies(target *url.URL, cookies []*http.Cookie) {
	accepted := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if jar.accepts(target, cookie) {
			accepted = append(accepted, cookie)
			jar.remember(target, cookie)
			continue
		}
		name := ""
		if cookie != nil {
			name = cookie.Name
		}
		jar.mu.Lock()
		jar.dropped[name]++
		jar.mu.Unlock()
	}
	if len(accepted) > 0 {
		jar.jar.SetCookies(target, accepted)
	}
}

func (jar *guardedJar) Cookies(target *url.URL) []*http.Cookie {
	if target == nil || target.Scheme != guard.Scheme || target.Host != guard.Host {
		return nil
	}
	return jar.jar.Cookies(target)
}

func (jar *guardedJar) importCookies(target *url.URL, cookies []*http.Cookie) error {
	for _, cookie := range cookies {
		if !jar.accepts(target, cookie) {
			name := ""
			if cookie != nil {
				name = cookie.Name
			}
			return fmt.Errorf("cookie %q failed validation", name)
		}
	}
	jar.SetCookies(target, cookies)
	return nil
}

func (jar *guardedJar) droppedCookies() map[string]int {
	jar.mu.Lock()
	defer jar.mu.Unlock()
	result := make(map[string]int, len(jar.dropped))
	for name, count := range jar.dropped {
		result[name] = count
	}
	return result
}

func (jar *guardedJar) snapshot() []*http.Cookie {
	jar.mu.Lock()
	defer jar.mu.Unlock()
	result := make([]*http.Cookie, 0, len(jar.accepted))
	now := jar.clock.Now()
	for key, cookie := range jar.accepted {
		if !cookie.Expires.IsZero() && !now.Before(cookie.Expires) {
			delete(jar.accepted, key)
			continue
		}
		copy := *cookie
		result = append(result, &copy)
	}
	return result
}

func (jar *guardedJar) remember(target *url.URL, cookie *http.Cookie) {
	jar.mu.Lock()
	defer jar.mu.Unlock()
	now := jar.clock.Now()
	canonical := canonicalCookie(target, cookie, now)
	key := canonical.Name + "\x00" + cookieScope(canonical) + "\x00" + canonical.Path
	if cookie.MaxAge < 0 || (!canonical.Expires.IsZero() && !now.Before(canonical.Expires)) {
		delete(jar.accepted, key)
		return
	}
	jar.accepted[key] = canonical
}

func canonicalCookie(target *url.URL, cookie *http.Cookie, now time.Time) *http.Cookie {
	canonical := *cookie
	canonical.Domain = strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
	if canonical.Path == "" || !strings.HasPrefix(canonical.Path, "/") {
		canonical.Path = defaultCookiePath(target.Path)
	}
	if cookie.MaxAge > 0 {
		canonical.Expires = now.Add(time.Duration(cookie.MaxAge) * time.Second)
	}
	canonical.MaxAge = 0
	canonical.Raw = ""
	canonical.RawExpires = ""
	canonical.Unparsed = nil
	return &canonical
}

func cookieScope(cookie *http.Cookie) string {
	if cookie.Domain == "" {
		return "host:" + guard.Host
	}
	return "domain:" + cookie.Domain
}

func defaultCookiePath(requestPath string) string {
	if !strings.HasPrefix(requestPath, "/") {
		return "/"
	}
	last := strings.LastIndex(requestPath, "/")
	if last == 0 {
		return "/"
	}
	return requestPath[:last]
}

func (jar *guardedJar) accepts(target *url.URL, cookie *http.Cookie) bool {
	if target == nil || target.Scheme != guard.Scheme || target.Host != guard.Host || cookie == nil || !cookie.Secure {
		return false
	}
	if err := cookie.Valid(); err != nil {
		return false
	}
	domain := strings.ToLower(cookie.Domain)
	if domain != "" && domain != "online.fnb.co.za" && domain != ".online.fnb.co.za" {
		return false
	}
	return cookie.Name != "" && len(cookie.Name)+len(cookie.Value) <= 4096
}

func DoOnce(client *http.Client, request *http.Request) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("HTTP client is required")
	}
	var wrote atomic.Bool
	traced := request.WithContext(withWriteTrace(request.Context(), func() { wrote.Store(true) }))
	response, err := client.Do(traced)
	if err == nil || response != nil {
		return response, err
	}
	var coded *exitcode.Error
	if errors.As(err, &coded) {
		return nil, err
	}
	if wrote.Load() {
		return nil, ErrSentUnknownOutcome
	}
	return nil, err
}
