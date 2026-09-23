package guard

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/yashiels/fnb/internal/exitcode"
)

const (
	Scheme = "https"
	Host   = "www.online.fnb.co.za"
)

type Params struct {
	Required []string
	Allowed  []string
	Routing  map[string][]string
}

type Entry struct {
	Name   string
	Method string
	Path   string
	Params Params
}

type Guard struct {
	entries []Entry
}

func New(entries []Entry) *Guard {
	return &Guard{entries: cloneEntries(entries)}
}

func Default() *Guard {
	return New([]Entry{{
		Name:   "static_asset",
		Method: http.MethodGet,
		Path:   "/banking/static/**",
		Params: Params{Allowed: []string{"ver"}},
	}})
}

func (guard *Guard) Entries() []Entry {
	return cloneEntries(guard.entries)
}

func (guard *Guard) Check(request *http.Request) error {
	if request == nil || request.URL == nil {
		return blocked("request", "missing URL", nil)
	}
	if request.URL.Scheme != Scheme || request.URL.Host != Host || request.URL.User != nil || request.URL.Opaque != "" {
		return blocked(request.URL.EscapedPath(), "origin", nil)
	}
	if request.Host != "" && request.Host != Host {
		return blocked(request.URL.EscapedPath(), "host", nil)
	}
	if request.URL.Fragment != "" || rawPathDiffers(request.URL) {
		return blocked(request.URL.EscapedPath(), "target", nil)
	}
	if unsafePath(request.URL) {
		return blocked(request.URL.EscapedPath(), "path", nil)
	}
	if hasForbiddenHeader(request.Header) {
		return blocked(request.URL.EscapedPath(), "headers", []string{"Authorization", "Cookie"})
	}
	parameters, err := requestParams(request)
	if err != nil {
		return blocked(request.URL.EscapedPath(), err.Error(), nil)
	}
	for _, entry := range guard.entries {
		if !entryMatchesPath(entry, request.URL.Path) || request.Method != entry.Method {
			continue
		}
		if err := checkParams(entry, parameters); err != nil {
			return err
		}
		return nil
	}
	return blocked(request.URL.EscapedPath(), "method or path", parameterKeys(parameters))
}

func (guard *Guard) CheckRedirect(request *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return blocked(request.URL.EscapedPath(), "redirect limit", nil)
	}
	return guard.Check(request)
}

func WriteActionNames(entries []Entry, denied []string) error {
	deny := make(map[string]struct{}, len(denied))
	for _, name := range denied {
		deny[name] = struct{}{}
	}
	for _, entry := range entries {
		for key, values := range entry.Params.Routing {
			for _, value := range values {
				if _, found := deny[value]; found {
					return fmt.Errorf("entry %q routing key %q matches denied action name", entry.Name, key)
				}
			}
		}
	}
	return nil
}

func requestParams(request *http.Request) (url.Values, error) {
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("query keys")
	}
	values := cloneValues(query)
	if request.Body == nil || request.Body == http.NoBody {
		return values, nil
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("body keys")
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	if len(body) == 0 {
		return values, nil
	}
	if request.Method == http.MethodGet {
		return nil, fmt.Errorf("body keys")
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("content type")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("body keys")
	}
	for key, items := range form {
		values[key] = append(values[key], items...)
	}
	return values, nil
}

func checkParams(entry Entry, values url.Values) error {
	allowed := make(map[string]struct{}, len(entry.Params.Allowed)+len(entry.Params.Required)+len(entry.Params.Routing))
	for _, key := range entry.Params.Allowed {
		allowed[key] = struct{}{}
	}
	for _, key := range entry.Params.Required {
		allowed[key] = struct{}{}
		if len(values[key]) == 0 {
			return blocked(entry.Name, "missing keys", []string{key})
		}
	}
	for key := range entry.Params.Routing {
		allowed[key] = struct{}{}
	}
	for key := range values {
		if _, found := allowed[key]; !found {
			return blocked(entry.Name, "unknown keys", []string{key})
		}
	}
	for key, accepted := range entry.Params.Routing {
		items := values[key]
		if len(items) == 0 {
			return blocked(entry.Name, "missing routing keys", []string{key})
		}
		first := items[0]
		for _, item := range items[1:] {
			if item != first {
				return blocked(entry.Name, "conflicting routing keys", []string{key})
			}
		}
		if !contains(accepted, first) {
			return blocked(entry.Name, "routing keys", []string{key})
		}
	}
	return nil
}

func entryMatchesPath(entry Entry, path string) bool {
	if strings.HasSuffix(entry.Path, "/**") {
		prefix := strings.TrimSuffix(entry.Path, "**")
		return strings.HasPrefix(path, prefix) && len(path) > len(prefix)
	}
	return path == entry.Path
}

func unsafePath(target *url.URL) bool {
	escaped := strings.ToLower(target.EscapedPath())
	if target.RawPath != "" {
		escaped = strings.ToLower(target.RawPath)
	}
	if strings.Contains(target.Path, "//") || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return true
	}
	if strings.Contains(target.Path, "%") || strings.Contains(target.Path, `\`) {
		return true
	}
	for _, segment := range strings.Split(target.Path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return strings.Contains(escaped, "%2e")
}

func rawPathDiffers(target *url.URL) bool {
	if target.RawPath == "" {
		return false
	}
	decoded, err := url.PathUnescape(target.RawPath)
	return err != nil || decoded != target.Path
}

func hasForbiddenHeader(header http.Header) bool {
	for key := range header {
		if strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Authorization") {
			return true
		}
	}
	return false
}

func blocked(entry, reason string, keys []string) error {
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	message := fmt.Sprintf("blocked request for %s: %s", entry, reason)
	if len(keys) > 0 {
		message += " (keys: " + strings.Join(keys, ", ") + ")"
	}
	return exitcode.New(exitcode.ExitGeneral, "blocked_request", message)
}

func parameterKeys(values url.Values) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func cloneValues(values url.Values) url.Values {
	copy := make(url.Values, len(values))
	for key, items := range values {
		copy[key] = append([]string(nil), items...)
	}
	return copy
}

func cloneEntries(entries []Entry) []Entry {
	cloned := make([]Entry, len(entries))
	for index, entry := range entries {
		cloned[index] = entry
		cloned[index].Params.Required = append([]string(nil), entry.Params.Required...)
		cloned[index].Params.Allowed = append([]string(nil), entry.Params.Allowed...)
		cloned[index].Params.Routing = make(map[string][]string, len(entry.Params.Routing))
		for key, values := range entry.Params.Routing {
			cloned[index].Params.Routing[key] = append([]string(nil), values...)
		}
	}
	return cloned
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
