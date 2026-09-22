package fixturescan

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{7}\b`),
	regexp.MustCompile(`\d{10,16}`),
	regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
	regexp.MustCompile(`(\+27|0)[6-8]\d{8}`),
	regexp.MustCompile(`\b4\d{5}\*{6}\d{4}\b|\b[45]\d{15}\b`),
}

func TestFixturesContainNoSensitiveData(t *testing.T) {
	err := filepath.WalkDir("testdata", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if matchesSensitiveData(content) {
			t.Errorf("sensitive data pattern found in %s", path)
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestSensitiveDataMatcher(t *testing.T) {
	positive := []string{
		"identity 9001015009087",
		"reference 1234567890",
		"person@example.co.za",
		"+27821234567",
		"412345******6789",
		"5123456789012345",
	}
	for _, value := range positive {
		if !matchesSensitiveData([]byte(value)) {
			t.Errorf("expected match for %q", value)
		}
	}
	negative := []string{
		"identity synthetic-user",
		"reference 123456789",
		"person at example dot com",
		"+27521234",
		"312345******6789",
		"612345******6789",
	}
	for _, value := range negative {
		if matchesSensitiveData([]byte(value)) {
			t.Errorf("unexpected match for %q", value)
		}
	}
}

func matchesSensitiveData(content []byte) bool {
	for _, pattern := range sensitivePatterns {
		if pattern.Match(content) {
			return true
		}
	}
	return false
}
