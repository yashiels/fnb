package session

import (
	"fmt"
	"time"

	"github.com/yashiels/fnb/internal/exitcode"
)

const CredentialInterval = 15 * time.Minute

type OutcomeKind string

const (
	Success         OutcomeKind = "success"
	ApprovalPending OutcomeKind = "approval_pending"
	BadCredentials  OutcomeKind = "bad_credentials"
	Unclassified    OutcomeKind = "unclassified"
	Maintenance     OutcomeKind = "maintenance"
	SentUnknown     OutcomeKind = "sent_unknown"
	Throttled       OutcomeKind = "throttled"
)

type Outcome struct {
	Kind      OutcomeKind
	Method    string
	ExpiresIn time.Duration
	Session   *Session
}

type Submitter interface {
	Submit() Outcome
}

type LoginManager struct {
	Attempts  AttemptStorage
	Sessions  SessionStorage
	Submitter Submitter
	Clock     Clock
}

func (manager LoginManager) Preflight() error {
	now := normalizeClock(manager.Clock).Now()
	attempt, found, err := manager.Attempts.LoadAttempt()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if attempt.State == AttemptInFlight || attempt.State == AttemptBlocked {
		reason := attempt.Reason
		if reason == "" {
			reason = string(attempt.State)
		}
		message := fmt.Sprintf("previous login did not complete (%s at %s); verify you can log in on the FNB site, then run 'fnb auth clear-lockout'", reason, attempt.At.Format(time.RFC3339))
		return exitcode.New(exitcode.ExitAuthentication, "login_blocked", message)
	}
	if attempt.LastCredentialLoginAt != nil {
		next := attempt.LastCredentialLoginAt.Add(CredentialInterval)
		if now.Before(next) {
			return exitcode.New(exitcode.ExitRateLimit, "rate_limited", "credential login is rate limited until "+next.Format(time.RFC3339))
		}
	}
	return nil
}

func (manager LoginManager) Login() (Outcome, error) {
	if err := manager.Preflight(); err != nil {
		return Outcome{}, err
	}
	clock := normalizeClock(manager.Clock)
	now := clock.Now()
	inFlight := Attempt{State: AttemptInFlight, At: now, LastCredentialLoginAt: &now}
	if err := manager.Attempts.SaveAttempt(inFlight); err != nil {
		return Outcome{}, err
	}
	outcome := manager.Submitter.Submit()
	if outcome.Session != nil && manager.Sessions != nil && (outcome.Kind == Success || outcome.Kind == ApprovalPending) {
		outcome.Session.ApprovalPending = outcome.Kind == ApprovalPending
		if err := manager.Sessions.SaveSession(*outcome.Session); err != nil {
			return outcome, err
		}
	}
	switch outcome.Kind {
	case Success:
		if err := manager.Attempts.SaveAttempt(Attempt{State: AttemptOK, At: clock.Now(), LastCredentialLoginAt: &now}); err != nil {
			return outcome, err
		}
		return outcome, nil
	case ApprovalPending:
		inFlight.Reason = string(ApprovalPending)
		if err := manager.Attempts.SaveAttempt(inFlight); err != nil {
			return outcome, err
		}
		return outcome, exitcode.New(exitcode.ExitApprovalPending, "approval_pending", "login approval is pending")
	default:
		reason, code, slug := outcomeFailure(outcome.Kind)
		if err := manager.Attempts.SaveAttempt(Attempt{State: AttemptBlocked, Reason: reason, At: clock.Now(), LastCredentialLoginAt: &now}); err != nil {
			return outcome, err
		}
		return outcome, exitcode.New(code, slug, "login blocked after "+reason)
	}
}

type ApprovalResolution string

const (
	Approved ApprovalResolution = "approved"
	Declined ApprovalResolution = "declined"
	Expired  ApprovalResolution = "expired"
)

func (manager LoginManager) ResolveApproval(resolution ApprovalResolution) error {
	attempt, found, err := manager.Attempts.LoadAttempt()
	if err != nil {
		return err
	}
	if !found || attempt.State != AttemptInFlight {
		return exitcode.New(exitcode.ExitAuthentication, "approval_missing", "no approval is pending")
	}
	now := normalizeClock(manager.Clock).Now()
	switch resolution {
	case Approved:
		attempt.State = AttemptOK
		attempt.Reason = ""
		attempt.At = now
		if manager.Sessions != nil {
			saved, present, err := manager.Sessions.LoadSession()
			if err != nil {
				return err
			}
			if present {
				saved.ApprovalPending = false
				if err := manager.Sessions.SaveSession(saved); err != nil {
					return err
				}
			}
		}
		return manager.Attempts.SaveAttempt(attempt)
	case Declined, Expired:
		if manager.Sessions != nil {
			if err := manager.Sessions.DeleteSession(); err != nil {
				return err
			}
		}
		attempt.State = AttemptBlocked
		attempt.Reason = string(resolution)
		attempt.At = now
		if err := manager.Attempts.SaveAttempt(attempt); err != nil {
			return err
		}
		if resolution == Expired {
			return exitcode.New(exitcode.ExitApprovalExpired, "approval_expired", "login approval expired")
		}
		return exitcode.New(exitcode.ExitAuthentication, "approval_declined", "login approval was declined")
	default:
		return exitcode.Usagef("unknown approval resolution %q", resolution)
	}
}

func ClearLockout(attempts AttemptStorage, confirm func() (bool, error), interactive bool) error {
	if !interactive {
		return exitcode.New(exitcode.ExitUsage, "interactive_required", "auth clear-lockout requires an interactive terminal")
	}
	confirmed, err := confirm()
	if err != nil {
		return err
	}
	if !confirmed {
		return exitcode.New(exitcode.ExitUsage, "confirmation_required", "lockout was not cleared")
	}
	attempt, found, err := attempts.LoadAttempt()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	attempt.State = AttemptOK
	attempt.Reason = ""
	return attempts.SaveAttempt(attempt)
}

func outcomeFailure(kind OutcomeKind) (string, int, string) {
	switch kind {
	case BadCredentials:
		return string(kind), exitcode.ExitAuthentication, "bad_credentials"
	case Maintenance:
		return string(kind), exitcode.ExitNetwork, "maintenance"
	case SentUnknown:
		return string(kind), exitcode.ExitNetwork, "sent_unknown"
	case Throttled:
		return string(kind), exitcode.ExitRateLimit, "throttled"
	default:
		return string(Unclassified), exitcode.ExitAuthentication, "unclassified_login"
	}
}
