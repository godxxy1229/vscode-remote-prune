package main

import "remoteprune/core"

func main() {
	v, e := core.Inspector()
	if e != nil {
		core.Print(map[string]any{"protocol": 2, "complete": false, "reason": "inspection_unavailable"})
		return
	}
	core.Print(v)
}
