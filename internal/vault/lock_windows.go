//go:build windows

// Windows has no flock; writes remain atomic renames, so the worst case of
// two concurrent writers is a lost update, never a corrupt file.
package vault

// Lock is a no-op on Windows.
func Lock(string) (func(), error) { return func() {}, nil }
