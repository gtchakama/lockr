package parser

import "strings"

// ParseKey parses a string like "work/stripe_key" into group="work" and key="stripe_key".
// If no group is provided, it defaults to "default".
func ParseKey(input string) (group, key string) {
	parts := strings.SplitN(input, "/", 2)
	if len(parts) == 1 {
		return "default", parts[0]
	}
	return parts[0], parts[1]
}
