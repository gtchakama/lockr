package crypto

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"testing/quick"
)

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

func TestKDFParamsValidate(t *testing.T) {
	tests := []struct {
		name    string
		params  KDFParams
		wantErr bool
	}{
		{name: "default KDF", params: DefaultKDF},
		{name: "minimum floor", params: KDFParams{Memory: 8 * 1024, Time: 1, Threads: 1}},
		{name: "maximum ceiling", params: KDFParams{Memory: maxKDFMemory, Time: maxKDFTime, Threads: maxKDFThreads}},
		{name: "memory below floor", params: KDFParams{Memory: 8*1024 - 1, Time: 1, Threads: 1}, wantErr: true},
		{name: "memory zero", params: KDFParams{Memory: 0, Time: 1, Threads: 1}, wantErr: true},
		{name: "time zero", params: KDFParams{Memory: 8 * 1024, Time: 0, Threads: 1}, wantErr: true},
		{name: "threads zero", params: KDFParams{Memory: 8 * 1024, Time: 1, Threads: 0}, wantErr: true},
		{name: "memory above ceiling", params: KDFParams{Memory: maxKDFMemory + 1, Time: 1, Threads: 1}, wantErr: true},
		{name: "memory uint32 max DoS", params: KDFParams{Memory: ^uint32(0), Time: 1, Threads: 1}, wantErr: true},
		{name: "time above ceiling", params: KDFParams{Memory: 8 * 1024, Time: maxKDFTime + 1, Threads: 1}, wantErr: true},
		{name: "time uint32 max DoS", params: KDFParams{Memory: 8 * 1024, Time: ^uint32(0), Threads: 1}, wantErr: true},
		{name: "threads above ceiling", params: KDFParams{Memory: 8 * 1024, Time: 1, Threads: maxKDFThreads + 1}, wantErr: true},
		{name: "threads uint8 max", params: KDFParams{Memory: 8 * 1024, Time: 1, Threads: 255}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate(%+v) = nil, want error", tc.params)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate(%+v) unexpected error: %v", tc.params, err)
			}
		})
	}
}

func TestDeriveKEK(t *testing.T) {
	fast := KDFParams{Memory: 8 * 1024, Time: 1, Threads: 1}
	salt := bytes.Repeat([]byte{0x42}, SaltSize)

	k1 := DeriveKEK([]byte("password"), salt, fast)
	k2 := DeriveKEK([]byte("password"), salt, fast)
	if len(k1) != KeySize {
		t.Fatalf("len(DeriveKEK) = %d, want %d", len(k1), KeySize)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("DeriveKEK not deterministic")
	}

	diffPW := DeriveKEK([]byte("other-password"), salt, fast)
	if bytes.Equal(k1, diffPW) {
		t.Fatalf("different passwords produced identical KEK")
	}

	diffSalt := DeriveKEK([]byte("password"), bytes.Repeat([]byte{0x24}, SaltSize), fast)
	if bytes.Equal(k1, diffSalt) {
		t.Fatalf("different salts produced identical KEK")
	}

	diffParams := DeriveKEK([]byte("password"), salt, KDFParams{Memory: 8 * 1024, Time: 2, Threads: 1})
	if bytes.Equal(k1, diffParams) {
		t.Fatalf("different KDF params produced identical KEK")
	}
}

func TestRandom(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 64} {
		b, err := Random(n)
		if err != nil {
			t.Fatalf("Random(%d) unexpected error: %v", n, err)
		}
		if len(b) != n {
			t.Fatalf("len(Random(%d)) = %d", n, len(b))
		}
	}

	a, err := Random(32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Random(32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("two 32-byte Random calls returned identical bytes")
	}

	if _, err := Random(-1); err == nil {
		t.Fatalf("Random(-1) = nil error, want error")
	}

	orig := randReader
	t.Cleanup(func() { randReader = orig })
	boom := errors.New("entropy exhausted")
	randReader = errReader{err: boom}
	if _, err := Random(16); !errors.Is(err, boom) {
		t.Fatalf("Random with failing reader err = %v, want %v", err, boom)
	}
}

func TestSealOpen(t *testing.T) {
	key, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := Random(KeySize)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pt   []byte
		aad  []byte
	}{
		{name: "empty plaintext and nil aad", pt: []byte{}, aad: nil},
		{name: "nil plaintext with aad", pt: nil, aad: []byte("header")},
		{name: "short secret", pt: []byte("s3cr3t!"), aad: []byte("aad-bytes")},
		{name: "larger payload", pt: bytes.Repeat([]byte("lockr-v2-"), 500), aad: bytes.Repeat([]byte{0xaa}, 122)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nonce, ct, err := Seal(key, tc.pt, tc.aad)
			if err != nil {
				t.Fatalf("Seal error: %v", err)
			}
			if len(nonce) != NonceSize {
				t.Fatalf("len(nonce) = %d, want %d", len(nonce), NonceSize)
			}
			if len(ct) != len(tc.pt)+Overhead {
				t.Fatalf("len(ct) = %d, want %d", len(ct), len(tc.pt)+Overhead)
			}

			got, err := Open(key, nonce, ct, tc.aad)
			if err != nil {
				t.Fatalf("Open error: %v", err)
			}
			if !bytes.Equal(got, tc.pt) {
				t.Fatalf("Open plaintext mismatch: got %x, want %x", got, tc.pt)
			}

			// Nonce uniqueness across consecutive calls.
			nonce2, _, err := Seal(key, tc.pt, tc.aad)
			if err != nil {
				t.Fatalf("second Seal error: %v", err)
			}
			if bytes.Equal(nonce, nonce2) {
				t.Fatalf("Seal reused nonce")
			}

			// Wrong key.
			if _, err := Open(wrongKey, nonce, ct, tc.aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("Open with wrong key err = %v, want ErrAuth", err)
			}

			// Tampered ciphertext (first and last byte).
			for _, idx := range []int{0, len(ct) / 2, len(ct) - 1} {
				badCT := append([]byte(nil), ct...)
				badCT[idx] ^= 0x01
				if _, err := Open(key, nonce, badCT, tc.aad); !errors.Is(err, ErrAuth) {
					t.Fatalf("Open with tampered ct[%d] err = %v, want ErrAuth", idx, err)
				}
			}

			// Truncated ciphertext.
			if _, err := Open(key, nonce, ct[:Overhead-1], tc.aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("Open with truncated ct err = %v, want ErrAuth", err)
			}

			// Tampered nonce.
			badNonce := append([]byte(nil), nonce...)
			badNonce[0] ^= 0x80
			if _, err := Open(key, badNonce, ct, tc.aad); !errors.Is(err, ErrAuth) {
				t.Fatalf("Open with tampered nonce err = %v, want ErrAuth", err)
			}

			// Tampered AAD.
			badAAD := append(append([]byte(nil), tc.aad...), 0x01)
			if _, err := Open(key, nonce, ct, badAAD); !errors.Is(err, ErrAuth) {
				t.Fatalf("Open with tampered aad err = %v, want ErrAuth", err)
			}
		})
	}
}

func TestSealOpenErrors(t *testing.T) {
	validKey := make([]byte, KeySize)
	validNonce := make([]byte, NonceSize)

	for _, badKey := range [][]byte{nil, {}, make([]byte, KeySize-1), make([]byte, KeySize+1)} {
		if _, _, err := Seal(badKey, []byte("hi"), nil); err == nil {
			t.Fatalf("Seal with key len %d succeeded, want error", len(badKey))
		}
		if _, err := Open(badKey, validNonce, make([]byte, Overhead), nil); err == nil {
			t.Fatalf("Open with key len %d succeeded, want error", len(badKey))
		}
	}

	for _, badNonce := range [][]byte{nil, {}, make([]byte, 12), make([]byte, NonceSize-1), make([]byte, NonceSize+1)} {
		if _, err := Open(validKey, badNonce, make([]byte, Overhead), nil); err == nil {
			t.Fatalf("Open with nonce len %d succeeded, want error", len(badNonce))
		}
	}

	orig := randReader
	t.Cleanup(func() { randReader = orig })
	boom := errors.New("rng failure")
	randReader = errReader{err: boom}
	if _, _, err := Seal(validKey, []byte("hi"), nil); !errors.Is(err, boom) {
		t.Fatalf("Seal with failing rng err = %v, want %v", err, boom)
	}
}

func TestZero(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 255}
	Zero(buf)
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("Zero left buf[%d] = %d", i, b)
		}
	}
	Zero(nil)
	Zero([]byte{})
}

func TestSealOpenProperty(t *testing.T) {
	cfg := &quick.Config{
		MaxCount: 200,
		Rand:     rand.New(rand.NewSource(42)),
	}
	prop := func(key [KeySize]byte, pt []byte, aad []byte, flipPos uint16) bool {
		nonce, ct, err := Seal(key[:], pt, aad)
		if err != nil {
			return false
		}
		if len(nonce) != NonceSize || len(ct) != len(pt)+Overhead {
			return false
		}
		got, err := Open(key[:], nonce, ct, aad)
		if err != nil || !bytes.Equal(got, pt) {
			return false
		}

		// Tampering with any ciphertext byte must fail with ErrAuth.
		badCT := append([]byte(nil), ct...)
		badCT[int(flipPos)%len(badCT)] ^= 0x01
		if _, err := Open(key[:], nonce, badCT, aad); !errors.Is(err, ErrAuth) {
			return false
		}

		// Tampering with AAD must fail with ErrAuth.
		badAAD := append(append([]byte(nil), aad...), 0xff)
		if _, err := Open(key[:], nonce, ct, badAAD); !errors.Is(err, ErrAuth) {
			return false
		}

		// Tampering with key must fail with ErrAuth.
		badKey := key
		badKey[int(flipPos)%KeySize] ^= 0x01
		if _, err := Open(badKey[:], nonce, ct, aad); !errors.Is(err, ErrAuth) {
			return false
		}
		return true
	}

	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}
