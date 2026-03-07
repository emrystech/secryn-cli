package output

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

func JSON(w io.Writer, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func Table(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	if len(headers) > 0 {
		for idx, header := range headers {
			if idx > 0 {
				if _, err := fmt.Fprint(tw, "\t"); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(tw, header); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(tw, "\n"); err != nil {
			return err
		}
	}
	for _, row := range rows {
		for idx, cell := range row {
			if idx > 0 {
				if _, err := fmt.Fprint(tw, "\t"); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprint(tw, cell); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprint(tw, "\n"); err != nil {
			return err
		}
	}
	return tw.Flush()
}
