package main

import (
	"os"

	"github.com/secryn/secryn-cli/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
