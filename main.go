package main

import (
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/nathanejohnson/dhcpoptions/commands"
	"os"
)

func main() {
	c := cli.NewCLI("dhcpoptions", "0.1.0")
	c.Args = os.Args[1:]
	c.Commands = map[string]cli.CommandFactory{
		"121": func() (cli.Command, error) {
			return commands.NewOption121Cmd(), nil
		},
	}
	errno, err := c.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(errno)
}
