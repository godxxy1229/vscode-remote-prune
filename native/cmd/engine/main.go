package main

import (
	"os"
	"os/user"
	"path/filepath"
	"remoteprune/core"
	"strconv"
)

func main() {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || len(os.Args) != 2 {
		core.Failure(core.Refused("nonroot_single_command_required"))
		os.Exit(1)
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		core.Failure(err)
		os.Exit(1)
	}
	exe, err := os.Executable()
	if err != nil {
		core.Failure(err)
		os.Exit(1)
	}
	engine := core.NewEngine(u.HomeDir, uint32(os.Getuid()), filepath.Dir(exe))
	if err = engine.Open(); err != nil {
		core.Failure(err)
		os.Exit(1)
	}
	result, err := engine.Run(os.Args[1], os.Stdin)
	engine.Close()
	if err != nil {
		core.Failure(err)
		os.Exit(1)
	}
	core.Print(map[string]any{"ok": true, "result": result})
}
