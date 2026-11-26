package totp

import (
	"bytes"
	"encoding/base32"
	"testing"
	"time"
)

func TestCodeRFC6238SHA1Vectors(t *testing.T) {
	// RFC 6238 Appendix B test secret (20-byte ASCII "12345678901234567890").
	seed := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	tests := []struct {
		unix int64
		want string
	}{
		{unix: 59, want: "287082"},
		{unix: 1111111109, want: "081804"},
		{unix: 1111111111, want: "050471"},
		{unix: 1234567890, want: "005924"},
		{unix: 2000000000, want: "279037"},
		{unix: 20000000000, want: "353130"},
	}

	for _, tc := range tests {
		got, err := Code(seed, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("Code(T=%d) unexpected error: %v", tc.unix, err)
		}
		if got != tc.want {
			t.Fatalf("Code(T=%d) = %q, want %q", tc.unix, got, tc.want)
		}
	}
}

func TestCodeEdgeCases(t *testing.T) {
	seed := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	// Epoch T=0 and step boundary T=29 vs T=30.
	c0, err := Code(seed, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Code(T=0) unexpected error: %v", err)
	}
	c29, err := Code(seed, time.Unix(29, 0).UTC())
	if err != nil {
		t.Fatalf("Code(T=29) unexpected error: %v", err)
	}
	c30, err := Code(seed, time.Unix(30, 0).UTC())
	if err != nil {
		t.Fatalf("Code(T=30) unexpected error: %v", err)
	}
	if len(c0) != 6 || c0 != c29 {
		t.Fatalf("codes within same 30s window differed: T=0:%q T=29:%q", c0, c29)
	}
	if c30 != "287082" {
		t.Fatalf("Code(T=30) = %q, want 287082 (same step as T=59)", c30)
	}

	// Timezone independence.
	ist := time.FixedZone("IST", 5*3600+30*60)
	cTZ, err := Code(seed, time.Unix(1234567890, 0).In(ist))
	if err != nil {
		t.Fatalf("Code(IST) unexpected error: %v", err)
	}
	if cTZ != "005924" {
		t.Fatalf("Code(IST) = %q, want 005924", cTZ)
	}

	// Negative Unix timestamps (including zero time.Time{}) must fail instead of wrapping.
	for _, ts := range []time.Time{time.Unix(-1, 0), {}} {
		if _, err := Code(seed, ts); err == nil {
			t.Fatalf("Code(%v) succeeded, want error", ts)
		}
	}

	// Invalid seed returns error.
	if _, err := Code("not-valid!", time.Unix(59, 0)); err == nil {
		t.Fatalf("Code with invalid seed succeeded, want error")
	}
}

func TestDecodeSeed(t *testing.T) {
	want := []byte("12345")
	canonical := base32.StdEncoding.EncodeToString(want) // "GEZDGNBV"

	validTests := []struct {
		name string
		seed string
		want []byte
	}{
		{name: "canonical uppercase", seed: canonical, want: want},
		{name: "lowercase", seed: "gezdgnbv", want: want},
		{name: "grouped spaces", seed: "GEZD GNBV", want: want},
		{name: "mixed case spaces and padding", seed: " gezd gnbv === ", want: want},
		{name: "padded with trailing newline", seed: "GEZDG===\n", want: []byte("123")},
		{name: "tabs and crlf", seed: "\tGEZD\tGNBV\r\n", want: want},
		{name: "unpadded short seed", seed: "GEZDG", want: []byte("123")},
	}

	for _, tc := range validTests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSeed(tc.seed)
			if err != nil {
				t.Fatalf("DecodeSeed(%q) unexpected error: %v", tc.seed, err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("DecodeSeed(%q) = %x, want %x", tc.seed, got, tc.want)
			}
		})
	}

	invalidTests := []struct {
		name string
		seed string
	}{
		{name: "empty", seed: ""},
		{name: "spaces only", seed: "   \t\n"},
		{name: "padding only", seed: "===="},
		{name: "invalid digits 0189", seed: "01890189"},
		{name: "punctuation", seed: "JBSW!Y3DP"},
		{name: "hyphenated", seed: "JBSW-Y3DP"},
		{name: "internal padding", seed: "GEZD=GNBV"},
		{name: "invalid base32 length", seed: "A"},
	}

	for _, tc := range invalidTests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := DecodeSeed(tc.seed); err == nil {
				t.Fatalf("DecodeSeed(%q) = %x, want error", tc.seed, got)
			}
		})
	}
}
