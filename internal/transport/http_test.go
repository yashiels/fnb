package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yashiels/fnb/internal/exitcode"
	"github.com/yashiels/fnb/internal/guard"
	"github.com/yashiels/fnb/internal/session"
)

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.sleeps = append(clock.sleeps, duration)
	clock.now = clock.now.Add(duration)
	return nil
}

func mappedClient(t *testing.T, server *httptest.Server, requestGuard *guard.Guard, clock Clock) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := NewHTTP(requestGuard, clock)
	base, ok := client.Transport.(*HTTPTransport).Base.(*http.Transport)
	if !ok {
		t.Fatal("HTTP transport base is not *http.Transport")
	}
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
	}
	return client
}

func staticURL(path string) string {
	return "https://" + guard.Host + "/banking/static/" + path
}

func TestGuardRejectionMakesZeroRequests(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { hits++ }))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	request, err := http.NewRequest(http.MethodGet, "https://example.test/banking/static/app.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); err == nil {
		t.Fatal("expected rejection")
	}
	if hits != 0 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestDisallowedRedirectStopsAndDoesNotStoreCookie(t *testing.T) {
	var cookies []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookies = append(cookies, request.Header.Get("Cookie"))
		if strings.HasSuffix(request.URL.Path, "/start") {
			http.SetCookie(writer, &http.Cookie{Name: "redirected", Value: "secret", Secure: true})
			http.Redirect(writer, request, "https://example.test/disallowed", http.StatusFound)
		}
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	if _, err := client.Get(staticURL("start")); err == nil {
		t.Fatal("expected redirect rejection")
	}
	response, err := client.Get(staticURL("next"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(cookies) != 2 || cookies[1] != "" {
		t.Fatalf("cookies = %#v", cookies)
	}
}

func TestPacingIsAtLeastOneSecond(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {}))
	defer server.Close()
	clock := &fakeClock{now: time.Unix(1, 0)}
	client := mappedClient(t, server, guard.Default(), clock)
	for _, path := range []string{"one", "two", "three"} {
		response, err := client.Get(staticURL(path))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if len(clock.sleeps) != 2 || clock.sleeps[0] != time.Second || clock.sleeps[1] != time.Second {
		t.Fatalf("sleeps = %v", clock.sleeps)
	}
}

func TestHTTP2IsDisabled(t *testing.T) {
	protocol := ""
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		protocol = request.Proto
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	response, err := client.Get(staticURL("protocol"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if protocol != "HTTP/1.1" {
		t.Fatalf("protocol = %q", protocol)
	}
}

func TestDroppedConnectionAfterBodyIsSentUnknown(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		hits++
		_, _ = io.ReadAll(request.Body)
		connection, _, err := writer.(http.Hijacker).Hijack()
		if err == nil {
			connection.Close()
		}
	}))
	defer server.Close()
	requestGuard := guard.New([]guard.Entry{{
		Name:   "credential",
		Method: http.MethodPost,
		Path:   "/login",
		Params: guard.Params{Required: []string{"username"}},
	}})
	client := mappedClient(t, server, requestGuard, &fakeClock{now: time.Unix(1, 0)})
	request, err := http.NewRequest(http.MethodPost, "https://"+guard.Host+"/login", strings.NewReader("username=synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = DoOnce(client, request)
	if !errors.Is(err, ErrSentUnknownOutcome) {
		t.Fatalf("error = %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestRedirectLimitIsTen(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, staticURL("redirect"), nil)
	if err != nil {
		t.Fatal(err)
	}
	via := make([]*http.Request, 10)
	if err := guard.Default().CheckRedirect(request, via); err == nil {
		t.Fatal("expected redirect limit rejection")
	}
}

func TestRedirectLimitDoesNotStoreRejectedResponseCookie(t *testing.T) {
	var received string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/inspect") {
			received = request.Header.Get("Cookie")
			return
		}
		segment := strings.TrimPrefix(request.URL.Path, "/banking/static/")
		if segment == "9" {
			http.SetCookie(writer, &http.Cookie{Name: "rejected", Value: "secret", Secure: true})
		}
		next := "https://" + guard.Host + "/banking/static/" + fmt.Sprint(mustAtoi(t, segment)+1)
		http.Redirect(writer, request, next, http.StatusFound)
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	response, err := client.Get(staticURL("0"))
	if err == nil || response == nil {
		t.Fatalf("response = %#v, error = %v", response, err)
	}
	response.Body.Close()
	response, err = client.Get(staticURL("inspect"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if received != "" {
		t.Fatalf("Cookie = %q", received)
	}
	if snapshot := client.Transport.(*HTTPTransport).CookieSnapshot(); len(snapshot) != 0 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestGuardedJarDropsUnsafeCookies(t *testing.T) {
	var received string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/cookies") {
			headers := []string{
				"foreign=value; Domain=example.test; Secure",
				"insecure=value",
				"parent=value; Domain=fnb.co.za; Secure",
				"oversize=" + strings.Repeat("x", 4096) + "; Secure",
				"accepted=value; Domain=.online.fnb.co.za; Secure",
			}
			for _, header := range headers {
				writer.Header().Add("Set-Cookie", header)
			}
			return
		}
		received = request.Header.Get("Cookie")
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	for _, path := range []string{"cookies", "inspect"} {
		response, err := client.Get(staticURL(path))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if received != "accepted=value" {
		t.Fatalf("Cookie = %q", received)
	}
	snapshot := client.Transport.(*HTTPTransport).CookieSnapshot()
	if len(snapshot) != 1 || snapshot[0].Name != "accepted" || snapshot[0].Value != "value" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	dropped := client.Transport.(*HTTPTransport).DroppedCookies()
	for _, name := range []string{"foreign", "insecure", "parent", "oversize"} {
		if dropped[name] != 1 {
			t.Fatalf("dropped = %#v", dropped)
		}
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := session.NewStore(root, time.Hour, &fakeClock{now: time.Unix(1, 0)})
	if err := store.SaveCookieSnapshot(client.Transport.(*HTTPTransport), time.Unix(1, 0), false); err != nil {
		t.Fatal(err)
	}
	saved, present, err := store.LoadSession()
	if err != nil || !present || len(saved.Cookies) != 1 || saved.Cookies[0].Name != "accepted" {
		t.Fatalf("saved = %#v, present = %v, err = %v", saved, present, err)
	}
}

func TestImportCookiesRejectsUnsafeCookiesAtomically(t *testing.T) {
	tests := map[string]*http.Cookie{
		"non secure": {Name: "unsafe", Value: "secret"},
		"foreign":    {Name: "unsafe", Value: "secret", Domain: "example.test", Secure: true},
	}
	for name, unsafe := range tests {
		t.Run(name, func(t *testing.T) {
			var received string
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				received = request.Header.Get("Cookie")
			}))
			defer server.Close()
			client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
			transport := client.Transport.(*HTTPTransport)
			cookies := []*http.Cookie{
				{Name: "valid", Value: "synthetic", Secure: true},
				unsafe,
			}
			if err := transport.ImportCookies(cookies); err == nil {
				t.Fatal("expected rejection")
			}
			response, err := client.Get(staticURL("inspect"))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if received != "" {
				t.Fatalf("Cookie = %q", received)
			}
			if snapshot := transport.CookieSnapshot(); len(snapshot) != 0 {
				t.Fatalf("snapshot = %#v", snapshot)
			}
		})
	}
}

func TestSessionStoreLoadsThroughValidatedCookieImport(t *testing.T) {
	var received string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		received = request.Header.Get("Cookie")
	}))
	defer server.Close()
	clock := &fakeClock{now: time.Unix(1, 0)}
	client := mappedClient(t, server, guard.Default(), clock)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := session.NewStore(root, time.Hour, clock)
	if err := store.SaveSession(session.Session{
		Cookies:   []session.Cookie{{Name: "stored", Value: "synthetic", Secure: true}},
		CreatedAt: clock.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	loaded, present, err := store.LoadCookieSnapshot(client.Transport.(*HTTPTransport))
	if err != nil || !present || len(loaded.Cookies) != 1 {
		t.Fatalf("session = %#v, present = %v, error = %v", loaded, present, err)
	}
	response, err := client.Get(staticURL("stored"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if received != "stored=synthetic" {
		t.Fatalf("Cookie = %q", received)
	}
}

func TestCookieSnapshotPrunesExpiredCookiesWithInjectedClock(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1, 0)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.SetCookie(writer, &http.Cookie{Name: "expiring", Value: "synthetic", Expires: time.Unix(3601, 0), Secure: true})
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), clock)
	response, err := client.Get(staticURL("expiry"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	transport := client.Transport.(*HTTPTransport)
	if snapshot := transport.CookieSnapshot(); len(snapshot) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	clock.mu.Lock()
	clock.now = time.Unix(7201, 0)
	clock.mu.Unlock()
	if snapshot := transport.CookieSnapshot(); len(snapshot) != 0 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}

func TestManualCookieHeaderIsRejectedBeforeIO(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { hits++ }))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	request, err := http.NewRequest(http.MethodGet, staticURL("manual"), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", "manual=secret")
	if _, err := client.Do(request); err == nil {
		t.Fatal("expected rejection")
	}
	if hits != 0 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestDoOncePreservesRedirectPolicyErrorAndResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.test/disallowed", http.StatusFound)
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	request, err := http.NewRequest(http.MethodGet, staticURL("redirect-policy"), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := DoOnce(client, request)
	if response == nil || response.StatusCode != http.StatusFound {
		t.Fatalf("response = %#v", response)
	}
	response.Body.Close()
	if exitcode.Code(err) != exitcode.ExitGeneral || exitcode.Slug(err) != "blocked_request" || errors.Is(err, ErrSentUnknownOutcome) {
		t.Fatalf("error = %v", err)
	}
}

func TestDoOncePreservesCodedErrorWithoutResponse(t *testing.T) {
	policyError := exitcode.New(exitcode.ExitGeneral, "blocked_request", "blocked")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		trace := httptrace.ContextClientTrace(request.Context())
		trace.WroteRequest(httptrace.WroteRequestInfo{})
		return nil, policyError
	})}
	request, err := http.NewRequest(http.MethodPost, staticURL("coded"), strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := DoOnce(client, request)
	if response != nil || exitcode.Slug(err) != "blocked_request" || errors.Is(err, ErrSentUnknownOutcome) {
		t.Fatalf("response = %#v, error = %v", response, err)
	}
}

func TestDoOncePreservesUnsentTransportError(t *testing.T) {
	transportError := errors.New("transport failed before send")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, transportError
	})}
	request, err := http.NewRequest(http.MethodPost, staticURL("unsent"), strings.NewReader("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := DoOnce(client, request)
	if response != nil || !errors.Is(err, transportError) || errors.Is(err, ErrSentUnknownOutcome) {
		t.Fatalf("response = %#v, error = %v", response, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCookieSnapshotConvertsMaxAgeToAbsoluteExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.SetCookie(writer, &http.Cookie{Name: "short", Value: "synthetic", MaxAge: 60, Secure: true})
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), clock)
	response, err := client.Get(staticURL("maxage"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	transport := client.Transport.(*HTTPTransport)
	snapshot := transport.CookieSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	if snapshot[0].MaxAge != 0 || !snapshot[0].Expires.Equal(time.Unix(1060, 0)) {
		t.Fatalf("cookie = %#v", snapshot[0])
	}
	for range 3 {
		if again := transport.CookieSnapshot(); len(again) != 1 || !again[0].Expires.Equal(time.Unix(1060, 0)) {
			t.Fatalf("repeated snapshot refreshed expiry: %#v", again)
		}
	}
	clock.mu.Lock()
	clock.now = time.Unix(1060, 0)
	clock.mu.Unlock()
	if expired := transport.CookieSnapshot(); len(expired) != 0 {
		t.Fatalf("snapshot = %#v", expired)
	}
}

func TestCookieSnapshotRecordsCanonicalScope(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.SetCookie(writer, &http.Cookie{Name: "hostonly", Value: "synthetic", Secure: true})
		http.SetCookie(writer, &http.Cookie{Name: "scoped", Value: "synthetic", Domain: ".ONLINE.fnb.co.za", Path: "/banking", Secure: true})
	}))
	defer server.Close()
	client := mappedClient(t, server, guard.Default(), &fakeClock{now: time.Unix(1, 0)})
	response, err := client.Get(staticURL("scope"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	byName := map[string]*http.Cookie{}
	for _, cookie := range client.Transport.(*HTTPTransport).CookieSnapshot() {
		byName[cookie.Name] = cookie
	}
	hostOnly, scoped := byName["hostonly"], byName["scoped"]
	if hostOnly == nil || scoped == nil {
		t.Fatalf("snapshot = %#v", byName)
	}
	if hostOnly.Domain != "" || hostOnly.Path != "/banking/static" {
		t.Fatalf("host-only cookie = %#v", hostOnly)
	}
	if scoped.Domain != "online.fnb.co.za" || scoped.Path != "/banking" {
		t.Fatalf("scoped cookie = %#v", scoped)
	}
}
