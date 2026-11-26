// Package model defines the vault's domain types: validated names, secret
// references and items. Raw strings from the command line are parsed into
// these types once, at the boundary; nothing past the parser handles an
// unchecked name or reference.
package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	envPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

// Name is a validated project or item name.
type Name string

// ParseName accepts 1–64 characters of letters, digits, '_' and '-',
// starting with a letter or digit.
func ParseName(s string) (Name, error) {
	if !namePattern.MatchString(s) {
		return "", fmt.Errorf("invalid name %q: use 1-64 letters, digits, '_' or '-'", s)
	}
	return Name(s), nil
}

// EnvName is a validated environment variable name used by `lockr run`.
type EnvName string

// ParseEnvName accepts a POSIX-style environment variable name.
func ParseEnvName(s string) (EnvName, error) {
	if !envPattern.MatchString(s) {
		return "", fmt.Errorf("invalid env var name %q", s)
	}
	return EnvName(s), nil
}

// Field selects which part of an item a reference resolves to.
type Field string

// Fields a reference may select. Password is the default and also names the
// value of a plain secret.
const (
	FieldPassword Field = "password"
	FieldUsername Field = "username"
	FieldURL      Field = "url"
	FieldTOTP     Field = "totp"
)

// ParseField accepts one of the known field names.
func ParseField(s string) (Field, error) {
	switch f := Field(s); f {
	case FieldPassword, FieldUsername, FieldURL, FieldTOTP:
		return f, nil
	}
	return "", fmt.Errorf("unknown field %q: use password, username, url or totp", s)
}

// Ref points at one field of one item: <project>/<item>[.<field>].
type Ref struct {
	Project Name
	Item    Name
	Field   Field
}

// ParseRef parses a reference; the field defaults to password.
func ParseRef(s string) (Ref, error) {
	project, rest, ok := strings.Cut(s, "/")
	if !ok {
		return Ref{}, fmt.Errorf("invalid reference %q: expected <project>/<item>[.<field>]", s)
	}
	item, field, hasField := strings.Cut(rest, ".")
	p, err := ParseName(project)
	if err != nil {
		return Ref{}, err
	}
	i, err := ParseName(item)
	if err != nil {
		return Ref{}, err
	}
	f := FieldPassword
	if hasField {
		if f, err = ParseField(field); err != nil {
			return Ref{}, err
		}
	}
	return Ref{Project: p, Item: i, Field: f}, nil
}

// ItemRef parses a reference that must not carry a field (used by add/rm/mv).
func ItemRef(s string) (Ref, error) {
	r, err := ParseRef(s)
	if err != nil {
		return Ref{}, err
	}
	if strings.Contains(s, ".") {
		return Ref{}, fmt.Errorf("expected <project>/<item> without a field, got %q", s)
	}
	return r, nil
}

// String renders the reference in canonical form.
func (r Ref) String() string {
	if r.Field == FieldPassword || r.Field == "" {
		return string(r.Project) + "/" + string(r.Item)
	}
	return string(r.Project) + "/" + string(r.Item) + "." + string(r.Field)
}

// Kind distinguishes a website login from a plain secret (API key, token).
type Kind string

// Item kinds.
const (
	KindLogin  Kind = "login"
	KindSecret Kind = "secret"
)

// ParseKind accepts "login" or "secret".
func ParseKind(s string) (Kind, error) {
	switch k := Kind(s); k {
	case KindLogin, KindSecret:
		return k, nil
	}
	return "", fmt.Errorf("unknown kind %q: use login or secret", s)
}

// Item is one stored credential. Secret holds the password (login) or the
// value (secret); TOTPSeed is a base32 seed and never leaves the vault, only
// codes derived from it do.
type Item struct {
	Kind      Kind      `json:"kind"`
	URL       string    `json:"url,omitempty"`
	Username  string    `json:"username,omitempty"`
	Env       EnvName   `json:"env,omitempty"`
	Secret    []byte    `json:"secret"`
	TOTPSeed  string    `json:"totp,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SchemaVersion is the current body schema.
const SchemaVersion = 1

// Body is the decrypted vault content.
type Body struct {
	SchemaVersion int                     `json:"schema_version"`
	Projects      map[Name]map[Name]*Item `json:"projects"`
}

// NewBody returns an empty body at the current schema version.
func NewBody() *Body {
	return &Body{SchemaVersion: SchemaVersion, Projects: map[Name]map[Name]*Item{}}
}

// ErrNotFound reports a missing project, item or field.
var ErrNotFound = errors.New("not found")

// Item looks up an item; the error names exactly what is missing.
func (b *Body) Item(r Ref) (*Item, error) {
	items, ok := b.Projects[r.Project]
	if !ok {
		return nil, fmt.Errorf("project %q %w", r.Project, ErrNotFound)
	}
	it, ok := items[r.Item]
	if !ok {
		return nil, fmt.Errorf("item %q in project %q %w", r.Item, r.Project, ErrNotFound)
	}
	return it, nil
}
