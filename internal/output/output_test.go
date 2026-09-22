package output

import (
	"bytes"
	"testing"
)

func TestWriteJSONUsesTwoSpaceIndent(t *testing.T) {
	var output bytes.Buffer
	if err := WriteJSON(&output, map[string]any{"value": 1}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\n  \"value\": 1\n}\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestWritePlainUsesStableTabSeparatedLines(t *testing.T) {
	var output bytes.Buffer
	rows := [][]string{{"first", "1"}, {"second", "2"}}
	if err := WritePlain(&output, rows); err != nil {
		t.Fatal(err)
	}
	if output.String() != "first\t1\nsecond\t2\n" {
		t.Fatalf("output = %q", output.String())
	}
}
