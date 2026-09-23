package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/yashiels/fnb/internal/exitcode"
	"github.com/yashiels/fnb/internal/secure"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
	return nil
}

type fakeAttempts struct {
	attempt Attempt
	found   bool
}

func (attempts *fakeAttempts) LoadAttempt() (Attempt, bool, error) {
	return attempts.attempt, attempts.found, nil
}

func (attempts *fakeAttempts) SaveAttempt(attempt Attempt) error {
	attempts.attempt = attempt
	attempts.found = true
	return nil
}

func (attempts *fakeAttempts) DeleteAttempt() error {
	attempts.found = false
	return nil
}

type fakeSubmitter struct {
	outcome Outcome
	calls   int
	log     *[]string
}

type attemptWriteOperations struct {
	log      *[]string
	failStep string
	writes   [][]byte
}

type attemptWriteFile struct {
	operations *attemptWriteOperations
}

func (operations *attemptWriteOperations) CheckDirectory() error {
	return nil
}

func (operations *attemptWriteOperations) OpenTemp(string) (secure.FileHandle, error) {
	if err := operations.record("open(temp)"); err != nil {
		return nil, err
	}
	return &attemptWriteFile{operations: operations}, nil
}

func (operations *attemptWriteOperations) Lstat(string) (os.FileInfo, error) {
	return nil, os.ErrNotExist
}

func (operations *attemptWriteOperations) Link(string, string) error {
	return errors.New("unexpected link")
}

func (operations *attemptWriteOperations) Rename(string, string) error {
	return operations.record("rename")
}

func (operations *attemptWriteOperations) Remove(string) error {
	return nil
}

func (operations *attemptWriteOperations) SyncDirectory() error {
	return operations.record("fsync(dir)")
}

func (operations *attemptWriteOperations) record(step string) error {
	if operations.log != nil {
		*operations.log = append(*operations.log, step)
	}
	if operations.failStep == step {
		return errors.New("injected " + step + " failure")
	}
	return nil
}

func (file *attemptWriteFile) Chmod(mode os.FileMode) error {
	if mode != 0o600 {
		return errors.New("unexpected mode")
	}
	return nil
}

func (file *attemptWriteFile) Write(data []byte) (int, error) {
	if err := file.operations.record("write"); err != nil {
		return 0, err
	}
	file.operations.writes = append(file.operations.writes, append([]byte(nil), data...))
	return len(data), nil
}

func (file *attemptWriteFile) Sync() error {
	return file.operations.record("fsync(file)")
}

func (file *attemptWriteFile) Close() error {
	return nil
}

func (submitter *fakeSubmitter) Submit() Outcome {
	submitter.calls++
	if submitter.log != nil {
		*submitter.log = append(*submitter.log, "submit")
	}
	return submitter.outcome
}

type fakeSessions struct {
	session Session
	present bool
	deleted int
}

func (sessions *fakeSessions) SaveSession(session Session) error {
	sessions.session = session
	sessions.present = true
	return nil
}

func (sessions *fakeSessions) LoadSession() (Session, bool, error) {
	return sessions.session, sessions.present, nil
}

func (sessions *fakeSessions) DeleteSession() error {
	sessions.present = false
	sessions.deleted++
	return nil
}

func TestLoginPersistsInFlightDurablyBeforeSubmit(t *testing.T) {
	log := []string{}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	operations := &attemptWriteOperations{log: &log}
	attempts := NewAttemptsWithWriteOperations(root, operations)
	submitter := &fakeSubmitter{outcome: Outcome{Kind: Success}, log: &log}
	manager := LoginManager{Attempts: attempts, Submitter: submitter, Clock: &testClock{now: time.Unix(1000, 0)}}
	if _, err := manager.Login(); err != nil {
		t.Fatal(err)
	}
	want := []string{"open(temp)", "write", "fsync(file)", "rename", "fsync(dir)", "submit"}
	submitIndex := -1
	for index, step := range log {
		if step == "submit" {
			submitIndex = index
			break
		}
	}
	if submitIndex < 0 || !reflect.DeepEqual(log[:submitIndex+1], want) {
		t.Fatalf("order through submit = %v, want %v", log, want)
	}
	if len(operations.writes) == 0 {
		t.Fatal("attempt store did not write")
	}
	var saved Attempt
	if err := json.Unmarshal(operations.writes[0], &saved); err != nil {
		t.Fatal(err)
	}
	if saved.State != AttemptInFlight {
		t.Fatalf("first saved state = %q", saved.State)
	}
}

func TestLoginAttemptWriteFailureMakesZeroSubmitterCalls(t *testing.T) {
	for _, step := range []string{"open(temp)", "write", "fsync(file)", "rename", "fsync(dir)"} {
		t.Run(step, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			submitter := &fakeSubmitter{outcome: Outcome{Kind: Success}}
			manager := LoginManager{
				Attempts:  NewAttemptsWithWriteOperations(root, &attemptWriteOperations{failStep: step}),
				Submitter: submitter,
				Clock:     &testClock{now: time.Unix(1000, 0)},
			}
			if _, err := manager.Login(); err == nil {
				t.Fatal("expected failure")
			}
			if submitter.calls != 0 {
				t.Fatalf("submitter calls = %d", submitter.calls)
			}
		})
	}
}

func TestBadCredentialsBlocksFurtherLogin(t *testing.T) {
	attempts := &fakeAttempts{}
	submitter := &fakeSubmitter{outcome: Outcome{Kind: BadCredentials}}
	manager := LoginManager{Attempts: attempts, Submitter: submitter, Clock: &testClock{now: time.Unix(1000, 0)}}
	if _, err := manager.Login(); exitcode.Code(err) != exitcode.ExitAuthentication {
		t.Fatalf("error = %v", err)
	}
	if attempts.attempt.State != AttemptBlocked {
		t.Fatalf("state = %q", attempts.attempt.State)
	}
	if _, err := manager.Login(); exitcode.Slug(err) != "login_blocked" {
		t.Fatalf("error = %v", err)
	}
	if submitter.calls != 1 {
		t.Fatalf("submitter calls = %d", submitter.calls)
	}
}

func TestSentUnknownBlocksFurtherLogin(t *testing.T) {
	attempts := &fakeAttempts{}
	submitter := &fakeSubmitter{outcome: Outcome{Kind: SentUnknown}}
	manager := LoginManager{Attempts: attempts, Submitter: submitter, Clock: &testClock{now: time.Unix(1000, 0)}}
	if _, err := manager.Login(); exitcode.Code(err) != exitcode.ExitNetwork {
		t.Fatalf("error = %v", err)
	}
	if _, err := manager.Login(); exitcode.Slug(err) != "login_blocked" {
		t.Fatalf("error = %v", err)
	}
	if submitter.calls != 1 {
		t.Fatalf("submitter calls = %d", submitter.calls)
	}
}

func TestLoginOutcomeTransitions(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		kind    OutcomeKind
		exit    int
		state   AttemptState
		reason  string
		pending bool
	}{
		{"success", Success, exitcode.ExitOK, AttemptOK, "", false},
		{"approval pending", ApprovalPending, exitcode.ExitApprovalPending, AttemptInFlight, "approval_pending", true},
		{"unclassified", Unclassified, exitcode.ExitAuthentication, AttemptBlocked, "unclassified", false},
		{"maintenance", Maintenance, exitcode.ExitNetwork, AttemptBlocked, "maintenance", false},
		{"throttled", Throttled, exitcode.ExitRateLimit, AttemptBlocked, "throttled", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			attempts := &fakeAttempts{}
			sessions := &fakeSessions{}
			submitter := &fakeSubmitter{outcome: Outcome{Kind: testCase.kind, Session: &Session{}}}
			manager := LoginManager{Attempts: attempts, Sessions: sessions, Submitter: submitter, Clock: &testClock{now: time.Unix(1000, 0)}}
			_, err := manager.Login()
			actualExit := exitcode.ExitOK
			if err != nil {
				actualExit = exitcode.Code(err)
			}
			if actualExit != testCase.exit || attempts.attempt.State != testCase.state || attempts.attempt.Reason != testCase.reason {
				t.Fatalf("exit = %d, attempt = %#v, err = %v", actualExit, attempts.attempt, err)
			}
			if sessions.present != (testCase.kind == Success || testCase.kind == ApprovalPending) {
				t.Fatalf("session present = %v", sessions.present)
			}
			if sessions.present && sessions.session.ApprovalPending != testCase.pending {
				t.Fatalf("session = %#v", sessions.session)
			}
		})
	}
}

func TestLoginRateGuard(t *testing.T) {
	now := time.Unix(1000, 0)
	attempts := &fakeAttempts{attempt: Attempt{State: AttemptOK, At: now, LastCredentialLoginAt: &now}, found: true}
	submitter := &fakeSubmitter{outcome: Outcome{Kind: Success}}
	manager := LoginManager{Attempts: attempts, Submitter: submitter, Clock: &testClock{now: now.Add(14 * time.Minute)}}
	if _, err := manager.Login(); exitcode.Slug(err) != "rate_limited" {
		t.Fatalf("error = %v", err)
	}
	if submitter.calls != 0 {
		t.Fatalf("submitter calls = %d", submitter.calls)
	}
}

func TestLockContention(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first, err := AcquireLock(context.Background(), root, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	clock := &testClock{now: time.Unix(1000, 0)}
	second, err := AcquireLock(context.Background(), root, clock, 300*time.Millisecond)
	if second != nil {
		second.Close()
	}
	if exitcode.Slug(err) != "lock_contention" {
		t.Fatalf("error = %v", err)
	}
}

func TestSessionLifetimeExpiryDeletesSession(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	created := time.Unix(1000, 0)
	clock := &testClock{now: created}
	store := NewStore(root, time.Hour, clock)
	saved := Session{CreatedAt: created, Cookies: []Cookie{{Name: "session", Value: "synthetic", Secure: true}}}
	if err := store.SaveSession(saved); err != nil {
		t.Fatal(err)
	}
	clock.now = created.Add(time.Hour)
	if _, found, err := store.LoadSession(); err != nil || found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	if _, err := os.Stat(directory + "/" + SessionFileName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat error = %v", err)
	}
}

func TestSessionStoreFiltersCookies(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	clock := &testClock{now: time.Unix(1000, 0)}
	store := NewStore(root, time.Hour, clock)
	saved := Session{Cookies: []Cookie{
		{Name: "accepted", Value: "synthetic", Domain: ".online.fnb.co.za", Secure: true},
		{Name: "foreign", Value: "synthetic", Domain: "example.test", Secure: true},
		{Name: "insecure", Value: "synthetic"},
	}}
	if err := store.SaveSession(saved); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadSession()
	if err != nil || !found {
		t.Fatalf("found = %v, err = %v", found, err)
	}
	if len(loaded.Cookies) != 1 || loaded.Cookies[0].Name != "accepted" {
		t.Fatalf("cookies = %#v", loaded.Cookies)
	}
}

func TestApprovalTransitions(t *testing.T) {
	for _, testCase := range []struct {
		resolution ApprovalResolution
		exit       int
		state      AttemptState
		deleted    int
		pending    bool
	}{
		{Approved, exitcode.ExitOK, AttemptOK, 0, false},
		{Declined, exitcode.ExitAuthentication, AttemptBlocked, 1, false},
		{Expired, exitcode.ExitApprovalExpired, AttemptBlocked, 1, false},
	} {
		t.Run(string(testCase.resolution), func(t *testing.T) {
			attempts := &fakeAttempts{attempt: Attempt{State: AttemptInFlight}, found: true}
			sessions := &fakeSessions{session: Session{ApprovalPending: true}, present: true}
			manager := LoginManager{Attempts: attempts, Sessions: sessions, Clock: &testClock{now: time.Unix(1000, 0)}}
			err := manager.ResolveApproval(testCase.resolution)
			actualExit := exitcode.ExitOK
			if err != nil {
				actualExit = exitcode.Code(err)
			}
			if actualExit != testCase.exit {
				t.Fatalf("error = %v", err)
			}
			if attempts.attempt.State != testCase.state || sessions.deleted != testCase.deleted {
				t.Fatalf("attempt = %#v, session = %#v, deleted = %d", attempts.attempt, sessions.session, sessions.deleted)
			}
			if testCase.resolution == Approved && sessions.session.ApprovalPending != testCase.pending {
				t.Fatalf("session = %#v", sessions.session)
			}
		})
	}
}

func TestClearLockoutRefusesNonInteractiveUse(t *testing.T) {
	called := false
	err := ClearLockout(&fakeAttempts{}, func() (bool, error) {
		called = true
		return true, nil
	}, false)
	if exitcode.Slug(err) != "interactive_required" || called {
		t.Fatalf("error = %v, called = %v", err, called)
	}
}
