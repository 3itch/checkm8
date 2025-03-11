package main

import (
	"github.com/alecthomas/kong"
)

const (
	programName = "goswid"
	programDesc = ""
)

func main() {
	ctx := kong.Parse(&cli,
		kong.Name(programName),
		kong.Description(programDesc),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
			Summary: true,
		}))
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
