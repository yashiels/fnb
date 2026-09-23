package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yashiels/fnb/internal/secure"
)

const SessionFileName = "session.json"

type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	Expires  time.Time `json:"expires,omitempty"`
	Secure   bool      `json:"secure"`
	HTTPOnly bool      `json:"httpOnly,omitempty"`
}

type Session struct {
	Cookies         []Cookie  `json:"cookies"`
	CreatedAt       time.Time `json:"createdAt"`
	ApprovalPending bool      `json:"approvalPending"`
}

type SessionStorage interface {
	SaveSession(Session) error
	LoadSession() (Session, bool, error)
	DeleteSession() error
}

type CookieSnapshot interface {
	CookieSnapshot() []*http.Cookie
}

type CookieImporter interface {
	ImportCookies([]*http.Cookie) error
}

type Store struct {
	root     *os.Root
	lifetime time.Duration
	clock    Clock
}

func NewStore(root *os.Root, lifetime time.Duration, clock Clock) *Store {
	return &Store{root: root, lifetime: lifetime, clock: normalizeClock(clock)}
}

func (store *Store) SaveSession(session Session) error {
	filtered := make([]Cookie, 0, len(session.Cookies))
	for _, cookie := range session.Cookies {
		if validStoredCookie(cookie, store.clock.Now()) {
			filtered = append(filtered, cookie)
		}
	}
	session.Cookies = filtered
	if session.CreatedAt.IsZero() {
		session.CreatedAt = store.clock.Now()
	}
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("encode session: %w", err)
	}
	if err := secure.WriteFile(store.root, SessionFileName, data, secure.Overwrite); err != nil {
		return fmt.Errorf("write session: %w", err)
	}
	return nil
}

func (store *Store) SaveCookieSnapshot(source CookieSnapshot, createdAt time.Time, approvalPending bool) error {
	if source == nil {
		return errors.New("cookie snapshot is required")
	}
	return store.SaveSession(Session{
		Cookies:         CookiesFromHTTP(source.CookieSnapshot()),
		CreatedAt:       createdAt,
		ApprovalPending: approvalPending,
	})
}

func (store *Store) LoadCookieSnapshot(destination CookieImporter) (Session, bool, error) {
	if destination == nil {
		return Session{}, false, errors.New("cookie importer is required")
	}
	session, present, err := store.LoadSession()
	if err != nil || !present {
		return session, present, err
	}
	if err := destination.ImportCookies(CookiesToHTTP(session.Cookies)); err != nil {
		return Session{}, false, fmt.Errorf("import session cookies: %w", err)
	}
	return session, true, nil
}

func (store *Store) LoadSession() (Session, bool, error) {
	file, err := store.root.Open(SessionFileName)
	if errors.Is(err, os.ErrNotExist) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, fmt.Errorf("open session: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024))
	closeErr := file.Close()
	if readErr != nil {
		return Session{}, false, fmt.Errorf("read session: %w", readErr)
	}
	if closeErr != nil {
		return Session{}, false, fmt.Errorf("close session: %w", closeErr)
	}
	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, false, fmt.Errorf("decode session: %w", err)
	}
	if session.CreatedAt.IsZero() || (store.lifetime > 0 && !store.clock.Now().Before(session.CreatedAt.Add(store.lifetime))) {
		if err := store.DeleteSession(); err != nil {
			return Session{}, false, err
		}
		return Session{}, false, nil
	}
	filtered := make([]Cookie, 0, len(session.Cookies))
	for _, cookie := range session.Cookies {
		if validStoredCookie(cookie, store.clock.Now()) {
			filtered = append(filtered, cookie)
		}
	}
	session.Cookies = filtered
	return session, true, nil
}

func (store *Store) DeleteSession() error {
	err := store.root.Remove(SessionFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return syncRoot(store.root)
}

func CookiesFromHTTP(cookies []*http.Cookie) []Cookie {
	result := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		result = append(result, Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
		})
	}
	return result
}

func CookiesToHTTP(cookies []Cookie) []*http.Cookie {
	result := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		result = append(result, &http.Cookie{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Path:     cookie.Path,
			Domain:   cookie.Domain,
			Expires:  cookie.Expires,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
		})
	}
	return result
}

func validStoredCookie(cookie Cookie, now time.Time) bool {
	domain := strings.ToLower(cookie.Domain)
	if domain != "" && domain != "online.fnb.co.za" && domain != ".online.fnb.co.za" {
		return false
	}
	if !cookie.Secure || cookie.Name == "" || len(cookie.Name)+len(cookie.Value) > 4096 {
		return false
	}
	return cookie.Expires.IsZero() || now.Before(cookie.Expires)
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
