package model

import (
	"errors"
	"strings"
	"testing"
)

func TestParseName(t *testing.T) {
	max64 := "a" + strings.Repeat("b1_-", 15) + "xyz" // 1 + 60 + 3 = 64
	over64 := max64 + "a"

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "single letter", in: "a"},
		{name: "single uppercase", in: "Z"},
		{name: "single digit", in: "0"},
		{name: "letters digits dash underscore", in: "Prod_API-v2"},
		{name: "max length 64", in: max64},
		{name: "empty", in: "", wantErr: true},
		{name: "leading dash", in: "-foo", wantErr: true},
		{name: "leading underscore", in: "_foo", wantErr: true},
		{name: "over max length 65", in: over64, wantErr: true},
		{name: "dot inside", in: "a.b", wantErr: true},
		{name: "slash inside", in: "a/b", wantErr: true},
		{name: "space inside", in: "a b", wantErr: true},
		{name: "leading space", in: " foo", wantErr: true},
		{name: "trailing space", in: "foo ", wantErr: true},
		{name: "trailing newline", in: "foo\n", wantErr: true},
		{name: "carriage return", in: "foo\r", wantErr: true},
		{name: "tab", in: "foo\tbar", wantErr: true},
		{name: "null byte", in: "foo\x00bar", wantErr: true},
		{name: "unicode accented", in: "café", wantErr: true},
		{name: "unicode CJK", in: "日本語", wantErr: true},
		{name: "unicode digit", in: "٢", wantErr: true},
		{name: "unicode nbsp", in: "a\u00a0b", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseName(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseName(%q) unexpected error: %v", tc.in, err)
			}
			if string(got) != tc.in {
				t.Fatalf("ParseName(%q) = %q, want %q", tc.in, got, tc.in)
			}
		})
	}
}

func TestParseEnvName(t *testing.T) {
	max128 := "_" + strings.Repeat("A1", 63) + "Z" // 1 + 126 + 1 = 128
	over128 := max128 + "0"

	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{name: "single letter", in: "A"},
		{name: "single underscore", in: "_"},
		{name: "lowercase", in: "my_var_1"},
		{name: "standard posix", in: "OPENAI_API_KEY"},
		{name: "leading underscore", in: "_INTERNAL_2"},
		{name: "max length 128", in: max128},
		{name: "empty", in: "", wantErr: true},
		{name: "leading digit", in: "1VAR", wantErr: true},
		{name: "over max length 129", in: over128, wantErr: true},
		{name: "dash", in: "API-KEY", wantErr: true},
		{name: "dot", in: "API.KEY", wantErr: true},
		{name: "equals", in: "API=1", wantErr: true},
		{name: "space", in: "API KEY", wantErr: true},
		{name: "trailing newline", in: "API_KEY\n", wantErr: true},
		{name: "unicode", in: "API_KÉY", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseEnvName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseEnvName(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseEnvName(%q) unexpected error: %v", tc.in, err)
			}
			if string(got) != tc.in {
				t.Fatalf("ParseEnvName(%q) = %q, want %q", tc.in, got, tc.in)
			}
		})
	}
}

func TestParseField(t *testing.T) {
	tests := []struct {
		in      string
		want    Field
		wantErr bool
	}{
		{in: "password", want: FieldPassword},
		{in: "username", want: FieldUsername},
		{in: "url", want: FieldURL},
		{in: "totp", want: FieldTOTP},
		{in: "", wantErr: true},
		{in: "PASSWORD", wantErr: true},
		{in: "secret", wantErr: true},
		{in: "pass", wantErr: true},
		{in: "password ", wantErr: true},
		{in: "url\n", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseField(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseField(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseField(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseField(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseKind(t *testing.T) {
	tests := []struct {
		in      string
		want    Kind
		wantErr bool
	}{
		{in: "login", want: KindLogin},
		{in: "secret", want: KindSecret},
		{in: "", wantErr: true},
		{in: "LOGIN", wantErr: true},
		{in: "SECRET", wantErr: true},
		{in: "token", wantErr: true},
		{in: "login ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseKind(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseKind(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseKind(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseKind(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseRef(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Ref
		wantErr bool
	}{
		{
			name: "default password field",
			in:   "stripe/live-key",
			want: Ref{Project: "stripe", Item: "live-key", Field: FieldPassword},
		},
		{
			name: "explicit password field",
			in:   "stripe/live-key.password",
			want: Ref{Project: "stripe", Item: "live-key", Field: FieldPassword},
		},
		{
			name: "username field",
			in:   "github/work_acct.username",
			want: Ref{Project: "github", Item: "work_acct", Field: FieldUsername},
		},
		{
			name: "url field",
			in:   "aws/console.url",
			want: Ref{Project: "aws", Item: "console", Field: FieldURL},
		},
		{
			name: "totp field",
			in:   "aws/console.totp",
			want: Ref{Project: "aws", Item: "console", Field: FieldTOTP},
		},
		{name: "empty", in: "", wantErr: true},
		{name: "no slash", in: "stripe", wantErr: true},
		{name: "only slash", in: "/", wantErr: true},
		{name: "empty project", in: "/item", wantErr: true},
		{name: "empty item", in: "proj/", wantErr: true},
		{name: "empty item with field", in: "proj/.password", wantErr: true},
		{name: "trailing dot empty field", in: "proj/item.", wantErr: true},
		{name: "multiple dots", in: "a/b.c.d", wantErr: true},
		{name: "valid field with extra dot", in: "a/b.password.extra", wantErr: true},
		{name: "multiple slashes", in: "a/b/c", wantErr: true},
		{name: "multiple slashes with field", in: "a/b/c.password", wantErr: true},
		{name: "dot in project", in: "a.b/c", wantErr: true},
		{name: "invalid project name", in: "-proj/item", wantErr: true},
		{name: "invalid item name", in: "proj/_item", wantErr: true},
		{name: "unknown field", in: "proj/item.secret", wantErr: true},
		{name: "trailing newline", in: "proj/item\n", wantErr: true},
		{name: "trailing newline on field", in: "proj/item.url\n", wantErr: true},
		{name: "unicode project", in: "prøj/item", wantErr: true},
		{name: "unicode item", in: "proj/itëm", wantErr: true},
		{name: "unicode field", in: "proj/item.pässword", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRef(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseRef(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseRef(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestItemRef(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    Ref
		wantErr bool
	}{
		{
			name: "valid item ref",
			in:   "stripe/live",
			want: Ref{Project: "stripe", Item: "live", Field: FieldPassword},
		},
		{name: "explicit password rejected", in: "stripe/live.password", wantErr: true},
		{name: "username field rejected", in: "stripe/live.username", wantErr: true},
		{name: "url field rejected", in: "stripe/live.url", wantErr: true},
		{name: "totp field rejected", in: "stripe/live.totp", wantErr: true},
		{name: "trailing dot rejected", in: "stripe/live.", wantErr: true},
		{name: "multiple dots rejected", in: "a/b.c.d", wantErr: true},
		{name: "missing slash", in: "stripe", wantErr: true},
		{name: "dot in project", in: "a.b/c", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ItemRef(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ItemRef(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ItemRef(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ItemRef(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRefString(t *testing.T) {
	tests := []struct {
		ref  Ref
		want string
	}{
		{ref: Ref{Project: "p", Item: "i", Field: FieldPassword}, want: "p/i"},
		{ref: Ref{Project: "p", Item: "i", Field: ""}, want: "p/i"},
		{ref: Ref{Project: "p", Item: "i", Field: FieldUsername}, want: "p/i.username"},
		{ref: Ref{Project: "p", Item: "i", Field: FieldURL}, want: "p/i.url"},
		{ref: Ref{Project: "p", Item: "i", Field: FieldTOTP}, want: "p/i.totp"},
	}

	for _, tc := range tests {
		got := tc.ref.String()
		if got != tc.want {
			t.Errorf("Ref(%+v).String() = %q, want %q", tc.ref, got, tc.want)
		}
		parsed, err := ParseRef(got)
		if err != nil {
			t.Errorf("ParseRef(%q) failed: %v", got, err)
		}
		wantField := tc.ref.Field
		if wantField == "" {
			wantField = FieldPassword
		}
		if parsed.Project != tc.ref.Project || parsed.Item != tc.ref.Item || parsed.Field != wantField {
			t.Errorf("round trip ParseRef(%q) = %+v, want %+v", got, parsed, tc.ref)
		}
	}
}

func TestBodyItem(t *testing.T) {
	item := &Item{Kind: KindSecret, Secret: []byte("top-secret")}
	b := NewBody()
	if b.SchemaVersion != SchemaVersion {
		t.Fatalf("NewBody().SchemaVersion = %d, want %d", b.SchemaVersion, SchemaVersion)
	}
	b.Projects["app"] = map[Name]*Item{
		"token": item,
		"empty": nil,
	}

	got, err := b.Item(Ref{Project: "app", Item: "token", Field: FieldPassword})
	if err != nil {
		t.Fatalf("Body.Item existing: unexpected error %v", err)
	}
	if got != item {
		t.Fatalf("Body.Item returned wrong pointer")
	}

	missingTests := []struct {
		name string
		body *Body
		ref  Ref
	}{
		{name: "missing project", body: b, ref: Ref{Project: "nope", Item: "token"}},
		{name: "missing item", body: b, ref: Ref{Project: "app", Item: "nope"}},
		{name: "nil item value", body: b, ref: Ref{Project: "app", Item: "empty"}},
		{name: "nil projects map", body: &Body{}, ref: Ref{Project: "app", Item: "token"}},
	}

	for _, tc := range missingTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.body.Item(tc.ref)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("Body.Item(%+v) err = %v, want ErrNotFound", tc.ref, err)
			}
			if got != nil {
				t.Fatalf("Body.Item(%+v) = %+v, want nil", tc.ref, got)
			}
		})
	}
}
