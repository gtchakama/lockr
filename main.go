// Package main is the entrypoint for the Lockr CLI.
package main

import "github.com/gtchakama/lockr/cmd"

// main delegates execution to the Cobra root command defined in the cmd package.
func main() {
	cmd.Execute()
}
