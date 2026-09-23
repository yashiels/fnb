package guard

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/yashiels/fnb/internal/exitcode"
)

func syntheticGuard() *Guard {
	return New([]Entry{{
		Name:   "read_summary",
		Method: http.MethodPost,
		Path:   "/synthetic/read",
		Params: Params{
			Required: []string{"account"},
			Allowed:  []string{"page"},
			Routing:  map[string][]string{"action": {"view"}},
		},
	}})
}

func validRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://"+Host+"/synthetic/read?action=view", strings.NewReader("account=synthetic&page=1"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func TestEveryEntryValidShapePasses(t *testing.T) {
	request := validRequest(t)
	if err := syntheticGuard().Check(request); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil || string(body) != "account=synthetic&page=1" {
		t.Fatalf("restored body = %q, err = %v", body, err)
	}
}

func TestGuardMutationsAreRejected(t *testing.T) {
	tests := map[string]func(*http.Request){
		"extra key":            func(request *http.Request) { request.URL.RawQuery += "&extra=redacted" },
		"missing required":     func(request *http.Request) { request.Body = io.NopCloser(strings.NewReader("page=1")) },
		"routing value":        func(request *http.Request) { request.URL.RawQuery = "action=change" },
		"method":               func(request *http.Request) { request.Method = http.MethodPut },
		"path":                 func(request *http.Request) { request.URL.Path = "/synthetic/other" },
		"host":                 func(request *http.Request) { request.URL.Host = "example.test" },
		"scheme":               func(request *http.Request) { request.URL.Scheme = "http" },
		"userinfo":             func(request *http.Request) { request.URL.User = url.User("synthetic") },
		"port":                 func(request *http.Request) { request.URL.Host = Host + ":443" },
		"traversal":            func(request *http.Request) { request.URL.Path = "/synthetic/../read" },
		"encoded traversal":    func(request *http.Request) { request.URL.RawPath = "/synthetic/%2e%2e/read" },
		"double slash":         func(request *http.Request) { request.URL.Path = "/synthetic//read" },
		"conflicting routing":  func(request *http.Request) { request.URL.RawQuery = "action=view&action=change" },
		"cookie header":        func(request *http.Request) { request.Header.Set("Cookie", "secret=value") },
		"authorization header": func(request *http.Request) { request.Header.Set("Authorization", "secret") },
		"request host":         func(request *http.Request) { request.Host = "example.test" },
		"opaque URL":           func(request *http.Request) { request.URL.Opaque = "//example.test/synthetic/read" },
		"mismatched raw path":  func(request *http.Request) { request.URL.RawPath = "/synthetic/other" },
		"fragment":             func(request *http.Request) { request.URL.Fragment = "synthetic" },
		"query semicolon":      func(request *http.Request) { request.URL.RawQuery = "action=view&unknown=x;y" },
		"query bad escape":     func(request *http.Request) { request.URL.RawQuery = "action=view&unknown=%zz" },
		"form semicolon": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("account=synthetic&page=x;y"))
		},
		"form bad escape": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("account=synthetic&page=%zz"))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest(t)
			mutate(request)
			err := syntheticGuard().Check(request)
			if err == nil || exitcode.Slug(err) != "blocked_request" {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "redacted") || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "change") {
				t.Fatalf("error leaked a value: %q", err)
			}
		})
	}
}

func TestForbiddenHeaderPresenceIsRejected(t *testing.T) {
	tests := map[string]http.Header{
		"lowercase cookie":         {"cookie": {"secret=value"}},
		"mixed case authorization": {"aUtHoRiZaTiOn": {"secret"}},
		"empty then populated":     {"cOoKiE": {"", "secret=value"}},
		"empty only":               {"authorization": {""}},
	}
	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest(t)
			request.Header = header
			err := syntheticGuard().Check(request)
			if err == nil || exitcode.Slug(err) != "blocked_request" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestEntriesAreDeepCopied(t *testing.T) {
	entries := []Entry{{
		Name:   "read_summary",
		Method: http.MethodPost,
		Path:   "/synthetic/read",
		Params: Params{
			Required: []string{"account"},
			Allowed:  []string{"page"},
			Routing:  map[string][]string{"action": {"view"}},
		},
	}}
	requestGuard := New(entries)
	entries[0].Params.Required[0] = "changed"
	entries[0].Params.Allowed[0] = "changed"
	entries[0].Params.Routing["action"][0] = "change"
	entries[0].Params.Routing["added"] = []string{"change"}
	exposed := requestGuard.Entries()
	exposed[0].Params.Required[0] = "changed"
	exposed[0].Params.Allowed[0] = "changed"
	exposed[0].Params.Routing["action"][0] = "change"
	exposed[0].Params.Routing["added"] = []string{"change"}
	if err := requestGuard.Check(validRequest(t)); err != nil {
		t.Fatal(err)
	}
	actual := requestGuard.Entries()[0].Params
	if len(actual.Required) != 1 || actual.Required[0] != "account" || len(actual.Allowed) != 1 || actual.Allowed[0] != "page" || len(actual.Routing) != 1 || len(actual.Routing["action"]) != 1 || actual.Routing["action"][0] != "view" {
		t.Fatalf("params = %#v", actual)
	}
}

func TestDefaultContainsOnlyStaticAssets(t *testing.T) {
	entries := Default().Entries()
	if len(entries) != 1 || entries[0].Name != "static_asset" {
		t.Fatalf("entries = %#v", entries)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+Host+"/banking/static/app.js?ver=synthetic", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Default().Check(request); err != nil {
		t.Fatal(err)
	}
}

func TestWriteActionNames(t *testing.T) {
	entries := syntheticGuard().Entries()
	if err := WriteActionNames(entries, []string{"pay", "transfer"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteActionNames(entries, []string{"view"}); err == nil {
		t.Fatal("expected denied routing value")
	}
}
