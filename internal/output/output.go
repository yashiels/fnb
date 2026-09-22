package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

type Mode int

const (
	Auto Mode = iota
	JSON
	Plain
	Table
)

func Resolve(jsonFlag, plainFlag bool, output io.Writer) Mode {
	if jsonFlag {
		return JSON
	}
	if plainFlag {
		return Plain
	}
	if file, ok := output.(*os.File); ok && IsTTY(file) {
		return Table
	}
	return JSON
}

func IsTTY(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func WriteJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func WritePlain(writer io.Writer, rows [][]string) error {
	for _, row := range rows {
		if _, err := fmt.Fprintln(writer, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return nil
}

func WriteTable(writer io.Writer, rows [][]string) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if err := WritePlain(table, rows); err != nil {
		return err
	}
	return table.Flush()
}
