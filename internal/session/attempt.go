package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/yashiels/fnb/internal/secure"
)

const AttemptFileName = "login-attempt.json"

type AttemptState string

const (
	AttemptInFlight AttemptState = "in_flight"
	AttemptBlocked  AttemptState = "blocked"
	AttemptOK       AttemptState = "ok"
)

type Attempt struct {
	State                 AttemptState `json:"state"`
	Reason                string       `json:"reason,omitempty"`
	At                    time.Time    `json:"at"`
	LastCredentialLoginAt *time.Time   `json:"lastCredentialLoginAt,omitempty"`
}

type AttemptStorage interface {
	LoadAttempt() (Attempt, bool, error)
	SaveAttempt(Attempt) error
	DeleteAttempt() error
}

type Attempts struct {
	root            *os.Root
	writeOperations secure.WriteOperations
}

func NewAttempts(root *os.Root) *Attempts {
	return &Attempts{root: root}
}

func NewAttemptsWithWriteOperations(root *os.Root, writeOperations secure.WriteOperations) *Attempts {
	return &Attempts{root: root, writeOperations: writeOperations}
}

func (attempts *Attempts) LoadAttempt() (Attempt, bool, error) {
	file, err := attempts.root.Open(AttemptFileName)
	if errors.Is(err, os.ErrNotExist) {
		return Attempt{}, false, nil
	}
	if err != nil {
		return Attempt{}, false, fmt.Errorf("open attempt state: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024))
	if err != nil {
		return Attempt{}, false, fmt.Errorf("read attempt state: %w", err)
	}
	var attempt Attempt
	if err := json.Unmarshal(data, &attempt); err != nil {
		return Attempt{}, false, fmt.Errorf("decode attempt state: %w", err)
	}
	if attempt.State != AttemptInFlight && attempt.State != AttemptBlocked && attempt.State != AttemptOK {
		return Attempt{}, false, fmt.Errorf("invalid attempt state %q", attempt.State)
	}
	return attempt, true, nil
}

func (attempts *Attempts) SaveAttempt(attempt Attempt) error {
	data, err := json.Marshal(attempt)
	if err != nil {
		return fmt.Errorf("encode attempt state: %w", err)
	}
	if attempts.writeOperations == nil {
		err = secure.WriteFile(attempts.root, AttemptFileName, data, secure.Overwrite)
	} else {
		err = secure.WriteFileWithOperations(attempts.writeOperations, AttemptFileName, data, secure.Overwrite)
	}
	if err != nil {
		return fmt.Errorf("write attempt state: %w", err)
	}
	return nil
}

func (attempts *Attempts) DeleteAttempt() error {
	err := attempts.root.Remove(AttemptFileName)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete attempt state: %w", err)
	}
	return syncRoot(attempts.root)
}
