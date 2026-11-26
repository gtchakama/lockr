// Package skill embeds the agent skill file that `lockr skill install` writes
// into an agent's skills directory. Boundary: static content only.
package skill

import _ "embed"

// Content is the SKILL.md text.
//
//go:embed SKILL.md
var Content string
