// Package totp computes RFC 6238 time-based one-time passwords (SHA-1,
// 6 digits, 30-second steps), the scheme used by almost every website.
package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA1 is not broken for this use.
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	step   = 30
	digits = 6
)

// DecodeSeed normalises and decodes a base32 seed as shown by websites
// (spaces, lower case and missing padding are accepted).
func DecodeSeed(seed string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(seed, " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("invalid TOTP seed: expected base32")
	}
	return key, nil
}

// Code returns the 6-digit code for the given seed at time t.
func Code(seed string, t time.Time) (string, error) {
	key, err := DecodeSeed(seed)
	if err != nil {
		return "", err
	}
	return codeAt(key, uint64(t.Unix())/step), nil
}

func codeAt(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, bin%1_000_000)
}
