package output

import "testing"

func TestFormatEnvSortsKeys(t *testing.T) {
	t.Parallel()

	input := map[string]string{
		"B": "two",
		"A": "one",
	}

	got := FormatEnv(input)
	want := "A=one\nB=two\n"
	if got != want {
		t.Fatalf("FormatEnv() mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestFormatEnvEscapesSpecialValues(t *testing.T) {
	t.Parallel()

	input := map[string]string{
		"EMPTY": "",
		"MULTI": "line1\nline2",
		"PATH":  `C:\\tmp\\file`,
		"SPACE": "hello world",
	}

	got := FormatEnv(input)
	want := "EMPTY=\"\"\nMULTI=\"line1\\nline2\"\nPATH=\"C:\\\\\\\\tmp\\\\\\\\file\"\nSPACE=\"hello world\"\n"
	if got != want {
		t.Fatalf("FormatEnv() mismatch\nwant:\n%s\ngot:\n%s", want, got)
	}
}
